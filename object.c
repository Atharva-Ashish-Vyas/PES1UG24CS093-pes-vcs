/*
 * object.c — Content-addressable object store
 *
 * Object format (stored on disk):
 *   "<type> <size>\0<data>"
 *
 * where:
 *   <type>  is "blob", "tree", or "commit"
 *   <size>  is the decimal length of <data>
 *   \0      is a literal NUL byte separating header from content
 *   <data>  is the raw content bytes
 *
 * The SHA-256 is computed over the FULL object (header + NUL + data).
 * The object is stored at:
 *   .pes/objects/<first-2-hex-chars>/<remaining-62-hex-chars>
 */

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <dirent.h>


/* ── SHA-256 implementation ─────────────────────────────────── */

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z) (((x)&(y))^(~(x)&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define S0(x) (ROTR(x,2)^ROTR(x,13)^ROTR(x,22))
#define S1(x) (ROTR(x,6)^ROTR(x,11)^ROTR(x,25))
#define R0(x) (ROTR(x,7)^ROTR(x,18)^((x)>>3))
#define R1(x) (ROTR(x,17)^ROTR(x,19)^((x)>>10))

void sha256_init(SHA256_CTX *ctx) {
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
}

static void sha256_transform(SHA256_CTX *ctx, const uint8_t *block) {
    uint32_t w[64], a, b, c, d, e, f, g, h, t1, t2;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)block[i*4]<<24)|((uint32_t)block[i*4+1]<<16)|
               ((uint32_t)block[i*4+2]<<8)|(uint32_t)block[i*4+3];
    for (i = 16; i < 64; i++)
        w[i] = R1(w[i-2]) + w[i-7] + R0(w[i-15]) + w[i-16];
    a=ctx->state[0]; b=ctx->state[1]; c=ctx->state[2]; d=ctx->state[3];
    e=ctx->state[4]; f=ctx->state[5]; g=ctx->state[6]; h=ctx->state[7];
    for (i = 0; i < 64; i++) {
        t1 = h + S1(e) + CH(e,f,g) + K[i] + w[i];
        t2 = S0(a) + MAJ(a,b,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
    ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;
}

void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len) {
    size_t i, idx = ctx->count & 63;
    ctx->count += len;
    for (i = 0; i < len; i++) {
        ctx->buf[idx++] = data[i];
        if (idx == 64) { sha256_transform(ctx, ctx->buf); idx = 0; }
    }
}

void sha256_final(SHA256_CTX *ctx, uint8_t digest[32]) {
    uint64_t bits = ctx->count * 8;
    uint8_t pad = 0x80;
    sha256_update(ctx, &pad, 1);
    pad = 0;
    while ((ctx->count & 63) != 56)
        sha256_update(ctx, &pad, 1);
    uint8_t len_enc[8];
    for (int i = 7; i >= 0; i--) { len_enc[i] = bits & 0xff; bits >>= 8; }
    sha256_update(ctx, len_enc, 8);
    for (int i = 0; i < 8; i++) {
        digest[i*4]   = (ctx->state[i]>>24)&0xff;
        digest[i*4+1] = (ctx->state[i]>>16)&0xff;
        digest[i*4+2] = (ctx->state[i]>>8)&0xff;
        digest[i*4+3] =  ctx->state[i]&0xff;
    }
}

void sha256_hex(const uint8_t *data, size_t len, char out[65]) {
    SHA256_CTX ctx;
    uint8_t digest[32];
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, digest);
    for (int i = 0; i < 32; i++)
        sprintf(out + i*2, "%02x", digest[i]);
    out[64] = '\0';
}

/* ── Utility helpers ────────────────────────────────────────── */
 
void die(const char *msg) {
    perror(msg);
    exit(1);
}
 
void *xmalloc(size_t n) {
    void *p = malloc(n);
    if (!p) die("malloc");
    return p;
}
 
void *xrealloc(void *p, size_t n) {
    void *q = realloc(p, n);
    if (!q) die("realloc");
    return q;
}
 
char *xstrdup(const char *s) {
    char *d = strdup(s);
    if (!d) die("strdup");
    return d;
}
 
int make_dirs(const char *path) {
    char tmp[MAX_PATH];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) < 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) < 0 && errno != EEXIST) return -1;
    return 0;
}

/* ── object_write ───────────────────────────────────────────── */
/*
 * TODO: Store `data` (length `len`) as an object of type `type`
 *       in the PES object store.
 *
 * Steps:
 *   1. Build the full object: "<type> <len>\0<data>"
 *      - Header is the ASCII string  type + " " + decimal(len) + NUL
 *      - Followed immediately by the raw data bytes
 *   2. Compute SHA-256 over the complete object bytes → hex string
 *   3. Derive storage path:
 *        .pes/objects/<hash[0..1]>/<hash[2..63]>
 *   4. If the file already exists → deduplication, return 0 (success)
 *   5. Otherwise write atomically:
 *        a. Create the two-char shard directory if needed
 *        b. Write to a temp file in that directory
 *        c. fsync() the temp file
 *        d. rename() it to the final path
 *   6. Copy the hex hash into out_hash (SHA256_HEX_LEN+1 bytes)
 *
 * Returns 0 on success, -1 on error.
 */
int object_write(const char *type, const uint8_t *data, size_t len,
                 char out_hash[SHA256_HEX_LEN+1]) {
 
    /* Step 1: Build full object = header + data */
    char header[128];
    int hlen = snprintf(header, sizeof(header), "%s %zu", type, len);
    /* +1 for the NUL byte after the header */
    size_t total = hlen + 1 + len;
    uint8_t *obj = xmalloc(total);
    memcpy(obj, header, hlen);
    obj[hlen] = '\0';               /* NUL separator */
    memcpy(obj + hlen + 1, data, len);
 
    /* Step 2: SHA-256 of the full object */
    char hash[SHA256_HEX_LEN+1];
    sha256_hex(obj, total, hash);
 
    /* Step 3: Derive storage path */
    char dir_path[MAX_PATH], obj_path[MAX_PATH], tmp_path[MAX_PATH];
    snprintf(dir_path, sizeof(dir_path), "%s/%.2s", PES_OBJECTS, hash);
    snprintf(obj_path, sizeof(obj_path), "%s/%.2s/%s", PES_OBJECTS, hash, hash+2);
 
    /* Step 4: Deduplication — already stored? */
    if (access(obj_path, F_OK) == 0) {
        free(obj);
        strncpy(out_hash, hash, SHA256_HEX_LEN+1);
        return 0;
    }
 
    /* Step 5a: Create shard directory */
    if (make_dirs(dir_path) < 0) { free(obj); return -1; }
 
    /* Step 5b: Write to temp file */
    snprintf(tmp_path, sizeof(tmp_path), "%s/.tmp_XXXXXX", dir_path);
    int fd = mkstemp(tmp_path);
    if (fd < 0) { free(obj); return -1; }
 
    size_t written = 0;
    while (written < total) {
        ssize_t n = write(fd, obj + written, total - written);
        if (n < 0) { close(fd); unlink(tmp_path); free(obj); return -1; }
        written += n;
    }
 
    /* Step 5c: fsync */
    if (fsync(fd) < 0) { close(fd); unlink(tmp_path); free(obj); return -1; }
    close(fd);
 
    /* Step 5d: Atomic rename */
    if (rename(tmp_path, obj_path) < 0) { unlink(tmp_path); free(obj); return -1; }
 
    free(obj);
 
    /* Step 6: Return hash */
    strncpy(out_hash, hash, SHA256_HEX_LEN+1);
    return 0;
}

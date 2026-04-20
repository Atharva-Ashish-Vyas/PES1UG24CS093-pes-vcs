// commit.c — Commit creation and history traversal
//
// Commit object format (stored as text, one field per line):
//
//   tree <64-char-hex-hash>
//   parent <64-char-hex-hash>        ← omitted for the first commit
//   author <name> <unix-timestamp>
//   committer <name> <unix-timestamp>
//
//   <commit message>
//
// Note: there is a blank line between the headers and the message.
//
// PROVIDED functions: commit_parse, commit_serialize, commit_walk, head_read, head_update
// TODO functions:     commit_create

#include "commit.h"
#include "index.h"
#include "tree.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

// Forward declarations (implemented in object.c)
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out);
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out);

// ─── PROVIDED ────────────────────────────────────────────────────────────────

int commit_parse(const void *data, size_t len, Commit *commit_out) {
    (void)len;
    const char *p = (const char *)data;
    char hex[HASH_HEX_SIZE + 1];

    if (sscanf(p, "tree %64s\n", hex) != 1) return -1;
    if (hex_to_hash(hex, &commit_out->tree) != 0) return -1;
    p = strchr(p, '\n') + 1;

    if (strncmp(p, "parent ", 7) == 0) {
        if (sscanf(p, "parent %64s\n", hex) != 1) return -1;
        if (hex_to_hash(hex, &commit_out->parent) != 0) return -1;
        commit_out->has_parent = 1;
        p = strchr(p, '\n') + 1;
    } else {
        commit_out->has_parent = 0;
    }

    char author_buf[256];
    uint64_t ts;
    if (sscanf(p, "author %255[^\n]\n", author_buf) != 1) return -1;
    char *last_space = strrchr(author_buf, ' ');
    if (!last_space) return -1;
    ts = (uint64_t)strtoull(last_space + 1, NULL, 10);
    *last_space = '\0';
    snprintf(commit_out->author, sizeof(commit_out->author), "%s", author_buf);
    commit_out->timestamp = ts;
    p = strchr(p, '\n') + 1;  // skip author line
    p = strchr(p, '\n') + 1;  // skip committer line
    p = strchr(p, '\n') + 1;  // skip blank line

    snprintf(commit_out->message, sizeof(commit_out->message), "%s", p);
    return 0;
}

int commit_serialize(const Commit *commit, void **data_out, size_t *len_out) {
    char tree_hex[HASH_HEX_SIZE + 1];
    char parent_hex[HASH_HEX_SIZE + 1];
    hash_to_hex(&commit->tree, tree_hex);

    char buf[8192];
    int n = 0;
    n += snprintf(buf + n, sizeof(buf) - n, "tree %s\n", tree_hex);
    if (commit->has_parent) {
        hash_to_hex(&commit->parent, parent_hex);
        n += snprintf(buf + n, sizeof(buf) - n, "parent %s\n", parent_hex);
    }
    n += snprintf(buf + n, sizeof(buf) - n,
                  "author %s %" PRIu64 "\n"
                  "committer %s %" PRIu64 "\n"
                  "\n"
                  "%s",
                  commit->author, commit->timestamp,
                  commit->author, commit->timestamp,
                  commit->message);

    *data_out = malloc(n + 1);
    if (!*data_out) return -1;
    memcpy(*data_out, buf, n + 1);
    *len_out = (size_t)n;
    return 0;
}

int commit_walk(commit_walk_fn callback, void *ctx) {
    ObjectID id;
    if (head_read(&id) != 0) return -1;

    while (1) {
        ObjectType type;
        void *raw;
        size_t raw_len;
        if (object_read(&id, &type, &raw, &raw_len) != 0) return -1;

        Commit c;
        int rc = commit_parse(raw, raw_len, &c);
        free(raw);
        if (rc != 0) return -1;

        callback(&id, &c, ctx);

        if (!c.has_parent) break;
        id = c.parent;
    }
    return 0;
}

int head_read(ObjectID *id_out) {
    FILE *f = fopen(HEAD_FILE, "r");
    if (!f) return -1;
    char line[512];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }
    fclose(f);
    line[strcspn(line, "\r\n")] = '\0';

    char ref_path[512];
    if (strncmp(line, "ref: ", 5) == 0) {
        snprintf(ref_path, sizeof(ref_path), "%s/%s", PES_DIR, line + 5);
        f = fopen(ref_path, "r");
        if (!f) return -1;
        if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }
        fclose(f);
        line[strcspn(line, "\r\n")] = '\0';
    }
    return hex_to_hash(line, id_out);
}

int head_update(const ObjectID *new_commit) {
    FILE *f = fopen(HEAD_FILE, "r");
    if (!f) return -1;
    char line[512];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }
    fclose(f);
    line[strcspn(line, "\r\n")] = '\0';

    char target_path[520];
    if (strncmp(line, "ref: ", 5) == 0) {
        snprintf(target_path, sizeof(target_path), "%s/%s", PES_DIR, line + 5);
    } else {
        snprintf(target_path, sizeof(target_path), "%s", HEAD_FILE);
    }

    char tmp_path[528];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", target_path);

    f = fopen(tmp_path, "w");
    if (!f) return -1;

    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(new_commit, hex);
    fprintf(f, "%s\n", hex);

    fflush(f);
    fsync(fileno(f));
    fclose(f);

    return rename(tmp_path, target_path);
}

// ─── TODO: Implemented ───────────────────────────────────────────────────────
//
// commit_create — Build and store a new commit object.
//
// The sequence is:
//   1. Build the root tree from the staged index → get root tree ObjectID.
//   2. Attempt to read HEAD to find the parent commit.
//      head_read() returns -1 when no commits exist yet (first commit).
//      In that case set has_parent = 0; otherwise set has_parent = 1.
//   3. Fill in a Commit struct:
//        - tree      ← root tree ObjectID from step 1
//        - parent    ← current HEAD (if it exists)
//        - author    ← pes_author()  (reads PES_AUTHOR env var)
//        - timestamp ← time(NULL)
//        - message   ← the -m argument passed in
//   4. Serialize the Commit struct to a text buffer with commit_serialize().
//   5. Write the buffer to the object store as OBJ_COMMIT with object_write().
//      This gives us the new commit's ObjectID.
//   6. Update HEAD (and the branch ref) with head_update() so that the
//      branch now points to our new commit.
//   7. Optionally store the new commit's ObjectID in *commit_id_out.

int commit_create(const char *message, ObjectID *commit_id_out) {

    // ── Step 1: build root tree from the index ───────────────────────────
    ObjectID tree_id;
    if (tree_from_index(&tree_id) != 0) {
        fprintf(stderr, "error: failed to build tree from index\n");
        return -1;
    }

    // ── Step 2: read current HEAD to find the parent ─────────────────────
    Commit c;
    memset(&c, 0, sizeof(c));

    ObjectID parent_id;
    if (head_read(&parent_id) == 0) {
        // A parent commit exists
        c.has_parent = 1;
        c.parent     = parent_id;
    } else {
        // No parent — this is the very first commit
        c.has_parent = 0;
    }

    // ── Step 3: fill in the rest of the commit struct ────────────────────
    c.tree      = tree_id;
    c.timestamp = (uint64_t)time(NULL);

    // Copy author string (pes_author() returns a pointer to static/env memory)
    snprintf(c.author, sizeof(c.author), "%s", pes_author());

    // Copy message — ensure it ends with a newline (Git convention)
    snprintf(c.message, sizeof(c.message), "%s", message);
    size_t msg_len = strlen(c.message);
    if (msg_len == 0 || c.message[msg_len - 1] != '\n') {
        // Append newline if missing and there is space
        if (msg_len + 1 < sizeof(c.message)) {
            c.message[msg_len]     = '\n';
            c.message[msg_len + 1] = '\0';
        }
    }

    // ── Step 4: serialize the Commit struct to a text buffer ─────────────
    void  *raw     = NULL;
    size_t raw_len = 0;
    if (commit_serialize(&c, &raw, &raw_len) != 0) {
        fprintf(stderr, "error: commit_serialize failed\n");
        return -1;
    }

    // ── Step 5: write the buffer to the object store ─────────────────────
    ObjectID commit_id;
    if (object_write(OBJ_COMMIT, raw, raw_len, &commit_id) != 0) {
        fprintf(stderr, "error: object_write failed for commit\n");
        free(raw);
        return -1;
    }
    free(raw);

    // ── Step 6: update HEAD / branch ref to the new commit ───────────────
    if (head_update(&commit_id) != 0) {
        fprintf(stderr, "error: head_update failed\n");
        return -1;
    }

    // ── Step 7: return the new commit's ObjectID to the caller ───────────
    if (commit_id_out)
        *commit_id_out = commit_id;

    // Print confirmation like real Git does
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(&commit_id, hex);
    printf("[%.7s] %s\n", hex, message);   // show short hash + message

    return 0;
}
/* Phase 4: commit create implemented */
/* Phase 4: parent detection */

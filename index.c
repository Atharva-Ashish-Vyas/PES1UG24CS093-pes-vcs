// index.c — Staging area implementation
//
// Text format of .pes/index (one entry per line, sorted by path):
//
//   <mode-octal> <64-char-hex-hash> <mtime-seconds> <size> <path>
//
// Example:
//   100644 a1b2c3d4e5f6...  1699900000 42 README.md
//   100644 f7e8d9c0b1a2...  1699900100 128 src/main.c
//
// PROVIDED functions: index_find, index_remove, index_status
// TODO functions:     index_load, index_save, index_add

#include "index.h"
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out);
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

IndexEntry* index_find(Index *index, const char *path) {
    for (int i = 0; i < index->count; i++) {
        if (strcmp(index->entries[i].path, path) == 0)
            return &index->entries[i];
    }
    return NULL;
}

int index_remove(Index *index, const char *path) {
    for (int i = 0; i < index->count; i++) {
        if (strcmp(index->entries[i].path, path) == 0) {
            int remaining = index->count - i - 1;
            if (remaining > 0)
                memmove(&index->entries[i], &index->entries[i + 1],
                        remaining * sizeof(IndexEntry));
            index->count--;
            return index_save(index);
        }
    }
    fprintf(stderr, "error: '%s' is not in the index\n", path);
    return -1;
}

int index_status(const Index *index) {
    printf("Staged changes:\n");
    int staged_count = 0;
    for (int i = 0; i < index->count; i++) {
        printf("  staged:     %s\n", index->entries[i].path);
        staged_count++;
    }
    if (staged_count == 0) printf("  (nothing to show)\n");
    printf("\n");

    printf("Unstaged changes:\n");
    int unstaged_count = 0;
    for (int i = 0; i < index->count; i++) {
        struct stat st;
        if (stat(index->entries[i].path, &st) != 0) {
            printf("  deleted:    %s\n", index->entries[i].path);
            unstaged_count++;
        } else {
            if (st.st_mtime != (time_t)index->entries[i].mtime_sec ||
                st.st_size  != (off_t)index->entries[i].size) {
                printf("  modified:   %s\n", index->entries[i].path);
                unstaged_count++;
            }
        }
    }
    if (unstaged_count == 0) printf("  (nothing to show)\n");
    printf("\n");

    printf("Untracked files:\n");
    int untracked_count = 0;
    DIR *dir = opendir(".");
    if (dir) {
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
            if (strcmp(ent->d_name, ".pes") == 0) continue;
            if (strcmp(ent->d_name, "pes") == 0) continue;
            if (strstr(ent->d_name, ".o") != NULL) continue;

            int is_tracked = 0;
            for (int i = 0; i < index->count; i++) {
                if (strcmp(index->entries[i].path, ent->d_name) == 0) {
                    is_tracked = 1;
                    break;
                }
            }

            if (!is_tracked) {
                struct stat st;
                stat(ent->d_name, &st);
                if (S_ISREG(st.st_mode)) {
                    printf("  untracked:  %s\n", ent->d_name);
                    untracked_count++;
                }
            }
        }
        closedir(dir);
    }
    if (untracked_count == 0) printf("  (nothing to show)\n");
    printf("\n");

    return 0;
}

// ─── TODO: Implemented ───────────────────────────────────────────────────────

// index_load — Read .pes/index into memory.
//
// Each line has the format:
//   <mode-octal> <64-hex-hash> <mtime> <size> <path>
//
// Steps:
//   1. Initialize the index to empty (count = 0).
//   2. Try to open INDEX_FILE for reading.
//      - If it doesn't exist (fopen returns NULL), that is NOT an error —
//        it just means nothing has been staged yet. Return 0.
//   3. Read one line at a time with fscanf, parsing all five fields.
//   4. Convert the hex string to a binary ObjectID with hex_to_hash().
//   5. Close the file and return 0.
int index_load(Index *index) {
    // Step 1: start with an empty index
    index->count = 0;

    // Step 2: open the index file; missing file is not an error
    FILE *f = fopen(INDEX_FILE, "r");
    if (!f) return 0;   // file doesn't exist yet → empty index, that's fine

    // Step 3 & 4: parse each line
    char hex[HASH_HEX_SIZE + 1];
    while (index->count < MAX_INDEX_ENTRIES) {
        IndexEntry *e = &index->entries[index->count];

        // fscanf returns the number of items successfully matched.
        // We expect exactly 5 fields per line.
        int matched = fscanf(f,
            "%o %64s %llu %u %511s\n",
            &e->mode,
            hex,
            (unsigned long long *)&e->mtime_sec,
            &e->size,
            e->path);

        if (matched == EOF || matched < 5) break;   // end of file or bad line

        // Step 4: convert the 64-char hex string → binary ObjectID
        if (hex_to_hash(hex, &e->hash) != 0) {
            fprintf(stderr, "error: corrupt hash in index\n");
            fclose(f);
            return -1;
        }

        index->count++;
    }

    fclose(f);
    return 0;
}

// Comparator for qsort: sort IndexEntry by path alphabetically.
static int cmp_index_entry(const void *a, const void *b) {
    return strcmp(((const IndexEntry *)a)->path,
                  ((const IndexEntry *)b)->path);
}

// index_save — Write the index to disk atomically.
//
// "Atomic" means: write to a temp file first, then rename() over the real
// index. rename() is guaranteed by POSIX to be atomic — readers always see
// either the old complete file or the new complete file, never a half-written
// one.
//
// Steps:
//   1. Sort entries by path (required for deterministic output and for
//      tree_from_index's grouping logic to work correctly).
//   2. Open a temp file (".pes/index.tmp") for writing.
//   3. Write each entry as one text line.
//   4. fflush → fsync (flush userspace buffer, then kernel buffer to disk).
//   5. fclose, then rename the temp file over INDEX_FILE.
int index_save(const Index *index) {
    // Step 1: sort a mutable copy (index pointer is const)
    // Use malloc — Index is ~5MB, too large for the stack
    Index *sorted = malloc(sizeof(Index));
    if (!sorted) return -1;
    *sorted = *index;
    qsort(sorted->entries, sorted->count, sizeof(IndexEntry), cmp_index_entry);

    // Step 2: open temp file
    const char *tmp_path = INDEX_FILE ".tmp";
    FILE *f = fopen(tmp_path, "w");
    if (!f) {
        perror("index_save: fopen");
        free(sorted);
        return -1;
    }

    // Step 3: write each entry
    for (int i = 0; i < sorted->count; i++) {
        const IndexEntry *e = &sorted->entries[i];

        // Convert binary ObjectID → 64-char hex string
        char hex[HASH_HEX_SIZE + 1];
        hash_to_hex(&e->hash, hex);

        fprintf(f, "%o %s %llu %u %s\n",
                e->mode,
                hex,
                (unsigned long long)e->mtime_sec,
                e->size,
                e->path);
    }

    // Step 4: flush userspace buffer then sync to disk
    if (fflush(f) != 0) { perror("index_save: fflush"); fclose(f); free(sorted); return -1; }
    if (fsync(fileno(f)) != 0) { perror("index_save: fsync"); fclose(f); free(sorted); return -1; }
    fclose(f);
    free(sorted);

    // Step 5: atomic rename temp → real index
    if (rename(tmp_path, INDEX_FILE) != 0) {
        perror("index_save: rename");
        return -1;
    }

    return 0;
}

// index_add — Stage a file for the next commit.
//
// Steps:
//   1. Open and read the entire file into a buffer.
//   2. Call object_write(OBJ_BLOB, ...) to store the contents and get a hash.
//   3. stat() the file to get its mode and mtime.
//   4. Use index_find() to see if this path is already in the index.
//      - If yes:  update the existing entry in place.
//      - If no:   append a new entry (check count < MAX_INDEX_ENTRIES first).
//   5. Call index_save() to persist the updated index atomically.
int index_add(Index *index, const char *path) {
    // Step 1: read the file
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "error: cannot open '%s'\n", path);
        return -1;
    }

    // Determine file size
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long file_size = ftell(f);
    if (file_size < 0)               { fclose(f); return -1; }
    rewind(f);

    // Allocate and read all bytes
    uint8_t *buf = malloc((size_t)file_size);
    if (!buf && file_size > 0)       { fclose(f); return -1; }
    if (file_size > 0 && fread(buf, 1, (size_t)file_size, f) != (size_t)file_size) {
        fprintf(stderr, "error: reading '%s'\n", path);
        free(buf); fclose(f); return -1;
    }
    fclose(f);

    // Step 2: store as a blob object, get its hash
    ObjectID blob_id;
    if (object_write(OBJ_BLOB, buf, (size_t)file_size, &blob_id) != 0) {
        fprintf(stderr, "error: object_write failed for '%s'\n", path);
        free(buf);
        return -1;
    }
    free(buf);

    // Step 3: get file metadata
    struct stat st;
    if (lstat(path, &st) != 0) {
        perror("index_add: lstat");
        return -1;
    }

    // Determine mode (100755 if executable, 100644 otherwise)
    uint32_t mode = (st.st_mode & S_IXUSR) ? 0100755 : 0100644;

    // Step 4: update existing entry or append a new one
    IndexEntry *existing = index_find(index, path);
    if (existing) {
        // File already staged — just refresh its metadata
        existing->hash        = blob_id;
        existing->mode      = mode;
        existing->mtime_sec = (uint64_t)st.st_mtime;
        existing->size      = (uint32_t)st.st_size;
    } else {
        // New file — append
        if (index->count >= MAX_INDEX_ENTRIES) {
            fprintf(stderr, "error: index is full\n");
            return -1;
        }
        IndexEntry *e = &index->entries[index->count++];
        e->hash        = blob_id;
        e->mode      = mode;
        e->mtime_sec = (uint64_t)st.st_mtime;
        e->size      = (uint32_t)st.st_size;
        strncpy(e->path, path, sizeof(e->path) - 1);
        e->path[sizeof(e->path) - 1] = '\0';
    }

    // Step 5: persist atomically
    return index_save(index);
}
/* Phase 3: index load implemented */
/* Phase 3: atomic save implemented */
/* Phase 3: stack overflow fix */
/* Phase 3: index add implemented */

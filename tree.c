// tree.c — Tree object serialization and construction
//
// PROVIDED functions: get_file_mode, tree_parse, tree_serialize
// TODO functions:     tree_from_index
//
// Binary tree format (per entry, concatenated with no separators):
//   "<mode-as-ascii-octal> <name>\0<32-byte-binary-hash>"
//
// Example single entry (conceptual):
//   "100644 hello.txt\0" followed by 32 raw bytes of SHA-256

#include "tree.h"
#include "index.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out);
// ─── Mode Constants ─────────────────────────────────────────────────────────

#define MODE_FILE      0100644
#define MODE_EXEC      0100755
#define MODE_DIR       0040000

// ─── PROVIDED ───────────────────────────────────────────────────────────────

uint32_t get_file_mode(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return 0;
    if (S_ISDIR(st.st_mode))  return MODE_DIR;
    if (st.st_mode & S_IXUSR) return MODE_EXEC;
    return MODE_FILE;
}

int tree_parse(const void *data, size_t len, Tree *tree_out) {
    tree_out->count = 0;
    const uint8_t *ptr = (const uint8_t *)data;
    const uint8_t *end = ptr + len;

    while (ptr < end && tree_out->count < MAX_TREE_ENTRIES) {
        TreeEntry *entry = &tree_out->entries[tree_out->count];

        const uint8_t *space = memchr(ptr, ' ', end - ptr);
        if (!space) return -1;

        char mode_str[16] = {0};
        size_t mode_len = space - ptr;
        if (mode_len >= sizeof(mode_str)) return -1;
        memcpy(mode_str, ptr, mode_len);
        entry->mode = strtol(mode_str, NULL, 8);

        ptr = space + 1;

        const uint8_t *null_byte = memchr(ptr, '\0', end - ptr);
        if (!null_byte) return -1;

        size_t name_len = null_byte - ptr;
        if (name_len >= sizeof(entry->name)) return -1;
        memcpy(entry->name, ptr, name_len);
        entry->name[name_len] = '\0';

        ptr = null_byte + 1;

        if (ptr + HASH_SIZE > end) return -1;
        memcpy(entry->hash.hash, ptr, HASH_SIZE);
        ptr += HASH_SIZE;

        tree_out->count++;
    }
    return 0;
}

static int compare_tree_entries(const void *a, const void *b) {
    return strcmp(((const TreeEntry *)a)->name, ((const TreeEntry *)b)->name);
}

int tree_serialize(const Tree *tree, void **data_out, size_t *len_out) {
    size_t max_size = tree->count * 296;
    uint8_t *buffer = malloc(max_size);
    if (!buffer) return -1;

    Tree sorted_tree = *tree;
    qsort(sorted_tree.entries, sorted_tree.count, sizeof(TreeEntry), compare_tree_entries);

    size_t offset = 0;
    for (int i = 0; i < sorted_tree.count; i++) {
        const TreeEntry *entry = &sorted_tree.entries[i];
        int written = sprintf((char *)buffer + offset, "%o %s", entry->mode, entry->name);
        offset += written + 1;
        memcpy(buffer + offset, entry->hash.hash, HASH_SIZE);
        offset += HASH_SIZE;
    }

    *data_out = buffer;
    *len_out = offset;
    return 0;
}

// ─── TODO: Implemented ──────────────────────────────────────────────────────
//
// Strategy:
//   We use a recursive helper `write_tree_level` that operates on a SLICE
//   of the index entries array. All entries in the slice share the same
//   directory prefix (tracked by prefix_len = how many leading chars to skip).
//
//   For each entry in the slice we ask: does this path have a '/' after the
//   prefix?
//     NO  → it's a plain file in this directory → add a blob TreeEntry directly.
//     YES → it belongs to a subdirectory. Collect ALL entries that share the
//           same next directory component and recurse into them, getting back
//           a subtree ObjectID → add a DIR TreeEntry for that component.
//
//   After processing every entry in the slice, serialize the Tree and write
//   it to the object store as OBJ_TREE.

// Forward declaration
static int write_tree_level(IndexEntry *entries, int count,
                            size_t prefix_len, ObjectID *id_out);

// ─── Recursive helper ───────────────────────────────────────────────────────
static int write_tree_level(IndexEntry *entries, int count,
                            size_t prefix_len, ObjectID *id_out)
{
    Tree tree;
    tree.count = 0;

    int i = 0;
    while (i < count) {
        // Path relative to this directory level (skip the common prefix)
        const char *rel = entries[i].path + prefix_len;

        // Is there a '/' in the remaining path?
        const char *slash = strchr(rel, '/');

        if (!slash) {
            // ── Plain file in this directory ──────────────────────────────
            // Add a blob entry whose name is just the filename (rel itself).
            if (tree.count >= MAX_TREE_ENTRIES) return -1;

            TreeEntry *e = &tree.entries[tree.count++];
            e->mode = entries[i].mode;
            e->hash = entries[i].hash;                  // blob hash from index
            strncpy(e->name, rel, sizeof(e->name) - 1);
            e->name[sizeof(e->name) - 1] = '\0';

            i++;

        } else {
            // ── Subdirectory: collect all entries that share this component ─
            // dir_name is the component before the slash, e.g. "src"
            size_t dir_len = slash - rel;             // length of component
            char dir_name[256];
            if (dir_len >= sizeof(dir_name)) return -1;
            memcpy(dir_name, rel, dir_len);
            dir_name[dir_len] = '\0';

            // Find how many consecutive entries belong to this subdirectory
            int j = i;
            while (j < count) {
                const char *r2 = entries[j].path + prefix_len;
                // Does r2 start with "dir_name/" ?
                if (strncmp(r2, dir_name, dir_len) == 0 && r2[dir_len] == '/') {
                    j++;
                } else {
                    break;
                }
            }
            // entries[i..j-1] all belong to subdir dir_name
            // new prefix_len for the recursive call skips "dir_name/"
            size_t new_prefix = prefix_len + dir_len + 1;

            ObjectID sub_id;
            if (write_tree_level(entries + i, j - i, new_prefix, &sub_id) != 0)
                return -1;

            // Add a directory entry pointing to the subtree
            if (tree.count >= MAX_TREE_ENTRIES) return -1;

            TreeEntry *e = &tree.entries[tree.count++];
            e->mode = MODE_DIR;
            e->hash = sub_id;
            strncpy(e->name, dir_name, sizeof(e->name) - 1);
            e->name[sizeof(e->name) - 1] = '\0';

            i = j; // jump past all entries we just handled
        }
    }

    // Serialize and write this level's tree to the object store
    void   *data = NULL;
    size_t  len  = 0;
    if (tree_serialize(&tree, &data, &len) != 0) return -1;

    int rc = object_write(OBJ_TREE, data, len, id_out);
    free(data);
    return rc;
}

// ─── Public entry point ─────────────────────────────────────────────────────
int tree_from_index(ObjectID *id_out)
{
    // 1. Load the staging area
    Index idx;
    if (index_load(&idx) != 0) return -1;

    if (idx.count == 0) {
        fprintf(stderr, "error: nothing staged – index is empty\n");
        return -1;
    }

    // 2. The index entries must be sorted by path for the grouping logic to
    //    work correctly (index_save already sorts them, but sort here to be safe).
    //    We use the same comparator that index_save uses.
    // Simple insertion-sort is fine for ≤1024 entries.
    for (int i = 1; i < idx.count; i++) {
        IndexEntry tmp = idx.entries[i];
        int j = i - 1;
        while (j >= 0 && strcmp(idx.entries[j].path, tmp.path) > 0) {
            idx.entries[j + 1] = idx.entries[j];
            j--;
        }
        idx.entries[j + 1] = tmp;
    }

    // 3. Recursively build tree from the root (prefix_len = 0)
    return write_tree_level(idx.entries, idx.count, 0, id_out);
}
/* Phase 2: tree parse implemented */
/* Phase 2: tree serialization implemented */
/* Phase 2: recursive tree building */

#define M61_DISABLE 1
#include "dmalloc.hh"
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cinttypes>
#include <cassert>

// ----- GLOBAL STATE -----
static dmalloc_statistics stats;

static const unsigned long long CANARY_MAGIC = 0xDEADC0DEDEADC0DEULL;

struct allocation_header {
    unsigned long long left_canary;    // detect wild writes before the block

    allocation_header* prev;
    allocation_header* next;

    size_t size;
    const char* file;
    long line;

    bool active;                       // false => already freed
};

// Keep a list of *all* allocations (active or freed)
static allocation_header* allocation_list_head = nullptr;

/// insert_into_allocation_list(node)
///    Insert `node` at the head of the global list of *all* allocations.
static void insert_into_allocation_list(allocation_header* node) {
    node->prev = nullptr;
    node->next = allocation_list_head;
    if (allocation_list_head) {
        allocation_list_head->prev = node;
    }
    allocation_list_head = node;
}

/// We no longer remove freed blocks from the list, so there's no
/// remove_from_allocation_list function. Freed blocks remain in the list
/// with `active == false`.

/// find_block(ptr)
///    Return the allocation header whose user pointer is `ptr`, or nullptr
///    if not found in the list.
static allocation_header* find_block(void* ptr) {
    allocation_header* cur = allocation_list_head;
    while (cur) {
        if ((void*) (cur + 1) == ptr) {
            return cur;
        }
        cur = cur->next;
    }
    return nullptr;
}

// ----- DMALLOC FUNCTIONS -----

void* dmalloc_malloc(size_t sz, const char* file, long line) {
    // 1. Overflow check: add header + right canary
    size_t total;
    if (__builtin_add_overflow(sz, sizeof(allocation_header), &total)) {
        // failed
        stats.nfail++;
        stats.fail_size += sz;
        return nullptr;
    }
    if (__builtin_add_overflow(total, sizeof(unsigned long long), &total)) {
        // failed
        stats.nfail++;
        stats.fail_size += sz;
        return nullptr;
    }

    // 2. Allocate
    allocation_header* header = (allocation_header*) base_malloc(total);
    if (!header) {
        // base_malloc failed
        stats.nfail++;
        stats.fail_size += sz;
        return nullptr;
    }

    // 3. Fill in metadata
    header->left_canary = CANARY_MAGIC;
    header->size = sz;
    header->file = file;
    header->line = line;
    header->active = true;

    insert_into_allocation_list(header);

    // 4. Update statistics
    stats.ntotal++;
    stats.total_size += sz;
    stats.nactive++;
    stats.active_size += sz;

    // 5. Set right canary after the user data
    void* user_ptr = (void*) (header + 1);  // user data follows header
    unsigned long long* right_canary = (unsigned long long*)
        ((char*) user_ptr + sz);
    *right_canary = CANARY_MAGIC;

    // 6. Update heap_min & heap_max with the *user region* boundaries
    uintptr_t start = (uintptr_t) user_ptr;
    uintptr_t end_excl = start + sz; // one past the last valid user byte
    if (stats.heap_min == 0 || start < stats.heap_min) {
        stats.heap_min = start;
    }
    if (end_excl > stats.heap_max) {
        stats.heap_max = end_excl;
    }

    // 7. Return pointer
    return user_ptr;
}


void dmalloc_free(void* ptr, const char* file, long line) {
    if (!ptr) {
        // free(nullptr) => no-op
        return;
    }

    // 1. Check if ptr is in range
    uintptr_t pval = (uintptr_t) ptr;
    if (pval < stats.heap_min || pval >= stats.heap_max) {
        // definitely outside the heap
        fprintf(stderr,
            "MEMORY BUG: %s:%ld: invalid free of pointer %p, not in heap\n",
            file, line, ptr);
        abort();
    }

    // 2. Search for a matching block
    allocation_header* header = find_block(ptr);
    if (!header) {
        // No matching block => "not allocated"
        fprintf(stderr,
            "MEMORY BUG: %s:%ld: invalid free of pointer %p, not allocated\n",
            file, line, ptr);
        abort();
    }

    // 3. If block is already freed => "double free"
    if (!header->active) {
        fprintf(stderr,
            "MEMORY BUG: %s:%ld: invalid free of pointer %p, double free\n",
            file, line, ptr);
        abort();
    }

    // 4. Check canaries
    if (header->left_canary != CANARY_MAGIC) {
        // The left canary is corrupted => might be partial pointer or wild write
        // Usually "not allocated," but check your assignment's exact phrasing.
        fprintf(stderr,
            "MEMORY BUG: %s:%ld: invalid free of pointer %p, not allocated\n",
            file, line, ptr);
        abort();
    }
    unsigned long long* right_c = (unsigned long long*)
        ((char*) ptr + header->size);
    if (*right_c != CANARY_MAGIC) {
        // Right canary was overwritten => wild write
        fprintf(stderr,
            "MEMORY BUG: %s:%ld: detected wild write during free of pointer %p\n",
            file, line, ptr);
        abort();
    }

    // 5. Everything looks good => free for the first time
    header->active = false;    // Mark block as inactive

    // Update stats
    stats.nactive--;
    stats.active_size -= header->size;

    // 6. Actually free the memory
    base_free(header);
}


void* dmalloc_calloc(size_t nmemb, size_t sz, const char* file, long line) {
    // Protect from overflow
    size_t total;
    if (__builtin_mul_overflow(nmemb, sz, &total)) {
        stats.nfail++;
        stats.fail_size += (nmemb * sz);
        return nullptr;
    }
    // Now call dmalloc_malloc, which also checks for overhead
    void* ptr = dmalloc_malloc(total, file, line);
    if (ptr) {
        // Zero out
        memset(ptr, 0, total);
    }
    return ptr;
}

void dmalloc_get_statistics(dmalloc_statistics* s) {
    *s = stats;
}

void dmalloc_print_statistics() {
    dmalloc_statistics s;
    dmalloc_get_statistics(&s);

    printf("alloc count: active %10llu   total %10llu   fail %10llu\n",
           s.nactive, s.ntotal, s.nfail);
    printf("alloc size:  active %10llu   total %10llu   fail %10llu\n",
           s.active_size, s.total_size, s.fail_size);
}

void dmalloc_print_leak_report() {
    // Print only those blocks that are still active
    for (allocation_header* p = allocation_list_head; p; p = p->next) {
        if (p->active) {
            printf("LEAK CHECK: %p size %zu alloc [%s:%ld]\n",
                   (void*) (p + 1), p->size, p->file, p->line);
        }
    }
}

void dmalloc_print_heavy_hitter_report() {
    // Not yet implemented
}

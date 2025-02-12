#define M61_DISABLE 1
#include "dmalloc.hh"
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cinttypes>
#include <cassert>

// ----- GLOBAL STATE -----
// We keep all necessary statistics in a global stats structure.
// Also keep a global doubly-linked list of ALL allocations (active or freed).
static dmalloc_statistics stats;

// A magic pattern stored before/after each block to detect wild writes.
static const unsigned long long CANARY_MAGIC = 0xDEADC0DEDEADC0DEULL;

struct allocation_header {
    unsigned long long left_canary;    // detect wild writes before the block

    allocation_header* prev;
    allocation_header* next;

    size_t size;           // size of the user allocation (not including header, canary)
    const char* file;      // file name of the caller
    long line;             // line number of the caller

    bool active;           // false => the block is already freed
};

// Linked list of *all* allocations (both active and freed).
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

/// find_block(ptr)
///    Return the allocation header whose user pointer is `ptr`, or nullptr
///    if not found in the list.
static allocation_header* find_block(void* ptr) {
    allocation_header* cur = allocation_list_head;
    while (cur) {
        // User data starts immediately after the header
        if ((void*) (cur + 1) == ptr) {
            return cur;
        }
        cur = cur->next;
    }
    return nullptr;
}

// ----- DMALLOC FUNCTIONS -----

void* dmalloc_malloc(size_t sz, const char* file, long line) {
    // 1. Check for overflow: We need space for allocation_header + user data + right canary
    size_t total;
    // total = sz + sizeof(allocation_header)
    if (__builtin_add_overflow(sz, sizeof(allocation_header), &total)) {
        // Allocation would overflow => record failure stats
        stats.nfail++;
        stats.fail_size += sz;
        return nullptr;
    }
    // total += sizeof(CANARY_MAGIC)
    if (__builtin_add_overflow(total, sizeof(unsigned long long), &total)) {
        // Allocation would overflow => record failure stats
        stats.nfail++;
        stats.fail_size += sz;
        return nullptr;
    }

    // 2. Allocate with base_malloc
    allocation_header* header = (allocation_header*) base_malloc(total);
    if (!header) {
        // base_malloc failed => record failure
        stats.nfail++;
        stats.fail_size += sz;
        return nullptr;
    }

    // 3. Fill in metadata + canary
    header->left_canary = CANARY_MAGIC;
    header->size        = sz;
    header->file        = file;
    header->line        = line;
    header->active      = true;

    // Insert into the global list of allocations
    insert_into_allocation_list(header);

    // 4. Update statistics
    stats.ntotal++;
    stats.total_size += sz;
    stats.nactive++;
    stats.active_size += sz;

    // 5. Compute the user pointer and set the right canary after the user region
    void* user_ptr = (void*) (header + 1);     // user data follows header
    unsigned long long* right_canary = (unsigned long long*)
        ((char*) user_ptr + sz);
    *right_canary = CANARY_MAGIC;

    // 6. Update heap_min & heap_max with the *user region* boundaries
    uintptr_t start    = (uintptr_t) user_ptr;
    uintptr_t end_excl = start + sz; // one past last valid user byte
    if (stats.heap_min == 0 || start < stats.heap_min) {
        stats.heap_min = start;
    }
    if (end_excl > stats.heap_max) {
        stats.heap_max = end_excl;
    }

    // 7. Return the user pointer
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
        // definitely outside the heap => error
        fprintf(stderr,
            "MEMORY BUG: %s:%ld: invalid free of pointer %p, not in heap\n",
            file, line, ptr);
        abort();
    }

    // 2. Search for a matching block
    allocation_header* header = find_block(ptr);
    if (!header) {
        // no matching block => "not allocated"
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
    // Check left canary in header
    if (header->left_canary != CANARY_MAGIC) {
        // The left canary is corrupted => user wrote before the block start
        fprintf(stderr,
            "MEMORY BUG: %s:%ld: invalid free of pointer %p, not allocated\n",
            file, line, ptr);
        abort();
    }

    // Check right canary
    unsigned long long* right_canary = (unsigned long long*)
        ((char*) ptr + header->size);
    if (*right_canary != CANARY_MAGIC) {
        // Right canary was overwritten => out-of-bounds write
        fprintf(stderr,
            "MEMORY BUG: %s:%ld: detected wild write during free of pointer %p\n",
            file, line, ptr);
        abort();
    }

    // 5. It's valid => free it
    header->active = false; // mark block as inactive
    stats.nactive--;
    stats.active_size -= header->size;

    base_free(header);
}


void* dmalloc_calloc(size_t nmemb, size_t sz, const char* file, long line) {
    // 1. Check for multiplication overflow (nmemb * sz)
    size_t total;
    if (__builtin_mul_overflow(nmemb, sz, &total)) {
        stats.nfail++;
        stats.fail_size += (nmemb * sz);
        return nullptr;
    }

    // 2. Allocate total bytes via dmalloc_malloc (checks overhead too)
    void* ptr = dmalloc_malloc(total, file, line);
    if (ptr) {
        // If successful, zero out
        memset(ptr, 0, total);
    }
    return ptr;
}


void dmalloc_get_statistics(dmalloc_statistics* s) {
    // Simply copy our global stats into *s
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
    // Task 5: Print each still-active allocation
    // Format:
    // LEAK CHECK: file:line: allocated object 0xADDRESS with size SIZE
    for (allocation_header* p = allocation_list_head; p; p = p->next) {
        if (p->active) {
            // The user pointer starts at (p + 1)
            void* user_ptr = (void*) (p + 1);
            printf("LEAK CHECK: %s:%ld: allocated object %p with size %zu\n",
                   p->file, p->line, user_ptr, p->size);
        }
    }
}


void dmalloc_print_heavy_hitter_report() {
    // Not required for tasks 4 & 5
    // This will be implemented for the heavy hitter analysis (if needed).
}

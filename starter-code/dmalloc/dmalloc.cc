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
    // Left canary
    unsigned long long left_canary;

    // Linked list pointers
    allocation_header* prev;
    allocation_header* next;

    // Original request size
    size_t size;

    // File & line that allocated this block
    const char* file;
    long line;

    // Mark if block is currently active
    bool active;
};

static allocation_header* alloc_list_head = nullptr;

// Insert node at head of active list
static void insert_into_alloc_list(allocation_header* node) {
    node->prev = nullptr;
    node->next = alloc_list_head;
    if (alloc_list_head) {
        alloc_list_head->prev = node;
    }
    alloc_list_head = node;
}

// Remove node from active list
static void remove_from_alloc_list(allocation_header* node) {
    if (node->prev) {
        node->prev->next = node->next;
    } else {
        alloc_list_head = node->next;
    }
    if (node->next) {
        node->next->prev = node->prev;
    }
}

static allocation_header* find_active_allocation(void* ptr) {
    // linear search
    allocation_header* cur = alloc_list_head;
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
    // 1. Overflow check
    size_t total;
    if (__builtin_add_overflow(sz, sizeof(allocation_header), &total)) {
        stats.nfail++;
        stats.fail_size += sz;
        return nullptr;
    }
    // Add space for right canary
    if (__builtin_add_overflow(total, sizeof(unsigned long long), &total)) {
        stats.nfail++;
        stats.fail_size += sz;
        return nullptr;
    }

    // 2. Allocate
    allocation_header* header = (allocation_header*) base_malloc(total);
    if (!header) {
        stats.nfail++;
        stats.fail_size += sz;
        return nullptr;
    }

    // 3. Initialize metadata
    header->left_canary = CANARY_MAGIC;
    header->size = sz;
    header->file = file;
    header->line = line;
    header->active = true;

    // 3b. Insert into active list
    insert_into_alloc_list(header);

    // 4. Update statistics
    stats.ntotal++;
    stats.total_size += sz;
    stats.nactive++;
    stats.active_size += sz;

    // 5. Set right canary
    void* user_ptr = (void*) (header + 1);  // Start of user data
    unsigned long long* right_c = (unsigned long long*)
        ((char*) user_ptr + sz);
    *right_c = CANARY_MAGIC;

    // 6. Update heap_min & heap_max for the *user* region
    uintptr_t user_start = (uintptr_t) user_ptr;
    uintptr_t user_end_exclusive = user_start + sz;
    if (stats.heap_min == 0 || user_start < stats.heap_min) {
        stats.heap_min = user_start;
    }
    if (user_end_exclusive > stats.heap_max) {
        stats.heap_max = user_end_exclusive;
    }

    // 7. Return user pointer
    return user_ptr;
}

void dmalloc_free(void* ptr, const char* file, long line) {
    if (!ptr) {
        return;  // free(nullptr) => no-op
    }

    // Attempt to find this pointer in active allocations
    allocation_header* header = find_active_allocation(ptr);
    if (!header) {
        // Not in active list => invalid free or double free
        // But we also do a quick range check to tailor the message
        uintptr_t pval = (uintptr_t) ptr;
        if (pval < stats.heap_min || pval >= stats.heap_max) {
            fprintf(stderr,
                    "MEMORY BUG: %s:%ld: invalid free of pointer %p, not in heap\n",
                    file, line, ptr);
        } else {
            // Could be double free or partial pointer. 
            // If your tests want a specific "double free" vs "invalid free" 
            // message, you can do more checks. 
            fprintf(stderr,
                    "MEMORY BUG: %s:%ld: invalid free of pointer %p, not allocated\n",
                    file, line, ptr);
        }
        abort();
    }

    // Check left canary
    if (header->left_canary != CANARY_MAGIC) {
        fprintf(stderr,
                "MEMORY BUG: %s:%ld: invalid free of pointer %p, not allocated\n",
                file, line, ptr);
        abort();
    }
    // Check right canary
    unsigned long long* right_c = (unsigned long long*)
        ((char*) ptr + header->size);
    if (*right_c != CANARY_MAGIC) {
        fprintf(stderr,
                "MEMORY BUG: %s:%ld: detected wild write during free of pointer %p\n",
                file, line, ptr);
        abort();
    }

    // Check if already freed => double free
    if (!header->active) {
        fprintf(stderr,
                "MEMORY BUG: %s:%ld: double free of pointer %p\n",
                file, line, ptr);
        abort();
    }

    // OK: remove from active list & mark inactive
    remove_from_alloc_list(header);
    header->active = false;

    // Update stats
    stats.nactive--;
    stats.active_size -= header->size;

    // Free
    base_free(header);
}

void* dmalloc_calloc(size_t nmemb, size_t sz, const char* file, long line) {
    // Protect from overflow: nmemb * sz
    size_t total;
    if (__builtin_mul_overflow(nmemb, sz, &total)) {
        stats.nfail++;
        stats.fail_size += (nmemb * sz);
        return nullptr;
    }

    // Now call dmalloc_malloc, which also checks “+ header + canary”
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
    for (allocation_header* p = alloc_list_head; p; p = p->next) {
        printf("LEAK CHECK: %p size %zu alloc [%s:%ld]\n",
               (void*) (p + 1), p->size, p->file, p->line);
    }
}

void dmalloc_print_heavy_hitter_report() {
    // Not yet implemented
}

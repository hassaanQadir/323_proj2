// dmalloc.cc

#define M61_DISABLE 1
#include "dmalloc.hh"
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cinttypes>
#include <cassert>

// ----- GLOBAL STATE -----

static dmalloc_statistics stats;

struct allocation_header {
    size_t size;
    const char* file;
    long line;
    allocation_header* prev;
    allocation_header* next;
};

static allocation_header* alloc_list_head = nullptr;

static void insert_into_alloc_list(allocation_header* node) {
    node->prev = nullptr;
    node->next = alloc_list_head;
    if (alloc_list_head) {
        alloc_list_head->prev = node;
    }
    alloc_list_head = node;
}

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

// ----- DMALLOC FUNCTIONS -----

void* dmalloc_malloc(size_t sz, const char* file, long line) {
    // 1) Check for overflow
    size_t total_size;
    if (__builtin_add_overflow(sz, sizeof(allocation_header), &total_size)) {
        // record failure
        stats.nfail++;
        stats.fail_size += sz;
        return nullptr;
    }

    // 2) Allocate
    allocation_header* header = (allocation_header*) base_malloc(total_size);
    if (!header) {
        stats.nfail++;
        stats.fail_size += sz;
        return nullptr;
    }

    // 3) Fill in metadata
    header->size = sz;
    header->file = file;
    header->line = line;
    insert_into_alloc_list(header);

    // 4) Update statistics
    stats.ntotal++;
    stats.total_size += sz;
    stats.nactive++;
    stats.active_size += sz;

    uintptr_t start = (uintptr_t) header;
    uintptr_t end   = start + total_size - 1;
    if (stats.heap_min == 0 || start < stats.heap_min) {
        stats.heap_min = start;
    }
    if (end > stats.heap_max) {
        stats.heap_max = end;
    }

    // 5) Return pointer to usable memory
    return (void*) (header + 1);
}

void dmalloc_free(void* ptr, const char* file, long line) {
    (void) file;
    (void) line;

    if (!ptr) {
        return;  // free(nullptr) is no-op
    }

    // 1) Recover our header
    allocation_header* header = (allocation_header*) ptr - 1;

    // 2) Remove from active list
    remove_from_alloc_list(header);

    // 3) Update statistics
    stats.nactive--;
    stats.active_size -= header->size;

    // 4) Free
    base_free(header);
}

void* dmalloc_calloc(size_t nmemb, size_t sz, const char* file, long line) {
    size_t total;
    if (__builtin_mul_overflow(nmemb, sz, &total)) {
        stats.nfail++;
        stats.fail_size += (nmemb * sz);
        return nullptr;
    }
    void* ptr = dmalloc_malloc(total, file, line);
    if (ptr) {
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
        // Example format
        printf("LEAK CHECK: %p size %zu alloc [%s:%ld]\n",
               (void*) (p + 1), p->size, p->file, p->line);
    }
}

void dmalloc_print_heavy_hitter_report() {
    // Not yet implemented for part 1.1
}

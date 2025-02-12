#define M61_DISABLE 1
#include "dmalloc.hh"
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cinttypes>
#include <cassert>

// You need these headers for the data structures
#include <map>
#include <unordered_map>

// ----- GLOBAL STATE -----

static dmalloc_statistics stats;

// We keep a doubly-linked list of all allocations (both active and freed),
// so we can print leak reports. Each allocated block has a `header` in front.
static const unsigned long long CANARY_MAGIC = 0xDEADC0DEDEADC0DEULL;

// Allocation header. Sits *before* the user data.
struct allocation_header {
    // Canary to catch wild writes *before* the user block
    unsigned long long left_canary;

    // Doubly-linked list pointers (for *all* blocks, active or freed)
    allocation_header* prev;
    allocation_header* next;

    size_t size;          // user-requested size
    const char* file;     // file of allocation
    long line;            // line of allocation

    bool active;          // false => block is already freed

    // We place the user data right after this header and left_canary.
    // Then a right_canary after that.
};

// Doubly-linked list of *all* allocations in the program’s history
static allocation_header* allocation_list_head = nullptr;

/// insert_into_allocation_list(node)
///    Insert `node` at the head of the global doubly-linked list.
static void insert_into_allocation_list(allocation_header* node) {
    node->prev = nullptr;
    node->next = allocation_list_head;
    if (allocation_list_head) {
        allocation_list_head->prev = node;
    }
    allocation_list_head = node;
}


/// We will store a fast lookup for "exact pointer matches" (active blocks only).
///    Key = user pointer (the address returned to the application).
///    Value = pointer to allocation_header.
static std::unordered_map<void*, allocation_header*> active_blocks_map;

/// For partial-pointer (inside‐block) detection, we need a structure
/// that can do interval lookups quickly (log(n) time). We’ll store
/// all active blocks keyed by their start address:
///
///     Key = (uintptr_t)(start of user region)
///     Value = allocation_header*
///
/// Then to see if `ptr` might lie inside an active block, we do:
///  1. auto it = intervals.upper_bound(ptr);
///  2. if (it != intervals.begin()) --it;
///  3. check if ptr >= it->first and ptr < it->first + it->second->size
static std::map<uintptr_t, allocation_header*> active_blocks_interval;


// ----- HELPER FUNCTIONS -----

/// find_header_exact(ptr)
///    Returns the `allocation_header*` for pointer `ptr`, if `ptr` matches
///    exactly some active block’s user pointer. Otherwise returns nullptr.
static allocation_header* find_header_exact(void* ptr) {
    auto it = active_blocks_map.find(ptr);
    if (it == active_blocks_map.end()) {
        return nullptr;
    }
    return it->second;
}


/// find_header_containing(ptr)
///    If `ptr` lies strictly within some other active block’s user memory,
///    returns that block’s header; otherwise returns nullptr.
static allocation_header* find_header_containing(uintptr_t p) {
    if (active_blocks_interval.empty()) {
        return nullptr;
    }
    // intervals.upper_bound(p) gives us the first element whose key > p
    auto it = active_blocks_interval.upper_bound(p);
    if (it == active_blocks_interval.begin()) {
        // everything in map has start address > p
        return nullptr;
    }
    // step back one
    --it;
    uintptr_t start = it->first;
    allocation_header* h = it->second;
    uintptr_t end_excl = start + h->size;  // one past the last valid byte
    if (p >= start && p < end_excl) {
        // `p` is inside [start, end_excl)
        return h;
    }
    return nullptr;
}


/// remove_from_active_lists(header)
///    Removes `header` from both active_blocks_map and active_blocks_interval
///    (if it is present). This is called when an active block is freed.
static void remove_from_active_lists(allocation_header* header) {
    void* user_ptr = (void*)(header + 1);
    // Remove from the "exact match" map
    auto it = active_blocks_map.find(user_ptr);
    if (it != active_blocks_map.end()) {
        active_blocks_map.erase(it);
    }
    // Remove from the "interval" map
    uintptr_t start = (uintptr_t) user_ptr;
    auto it2 = active_blocks_interval.find(start);
    if (it2 != active_blocks_interval.end()) {
        active_blocks_interval.erase(it2);
    }
}


// ----- DMALLOC FUNCTIONS -----

void* dmalloc_malloc(size_t user_size, const char* file, long line) {
    // 1. Check for overflow in: header + user data + right canary
    //    total = user_size + sizeof(allocation_header) + sizeof(CANARY_MAGIC)
    size_t total;
    if (__builtin_add_overflow(user_size, sizeof(allocation_header), &total)
     || __builtin_add_overflow(total, sizeof(unsigned long long), &total)) {
        // record failed allocation
        stats.nfail++;
        stats.fail_size += user_size;
        return nullptr;
    }

    // 2. Allocate via base_malloc
    allocation_header* header = (allocation_header*) base_malloc(total);
    if (!header) {
        // base_malloc failed
        stats.nfail++;
        stats.fail_size += user_size;
        return nullptr;
    }

    // 3. Fill in the metadata
    header->left_canary = CANARY_MAGIC;
    header->size        = user_size;
    header->file        = file;
    header->line        = line;
    header->active      = true;

    // Insert in the doubly-linked list (for later leak reports)
    insert_into_allocation_list(header);

    // 4. Write the right canary after the user region
    void* user_ptr = (void*)(header + 1); // user data starts after header
    unsigned long long* right_canary
        = (unsigned long long*)((char*) user_ptr + user_size);
    *right_canary = CANARY_MAGIC;

    // 5. Update statistics
    stats.ntotal++;
    stats.total_size += user_size;
    stats.nactive++;
    stats.active_size += user_size;

    // 6. Update heap_min/heap_max for the user region
    uintptr_t start = (uintptr_t) user_ptr;
    uintptr_t end_excl = start + user_size;
    if (stats.heap_min == 0 || start < stats.heap_min) {
        stats.heap_min = start;
    }
    if (end_excl > stats.heap_max) {
        stats.heap_max = end_excl;
    }

    // 7. Insert into our active-blocks data structures
    active_blocks_map[user_ptr] = header;
    active_blocks_interval[start] = header;

    // 8. Return the user pointer
    return user_ptr;
}


void dmalloc_free(void* ptr, const char* file, long line) {
    if (!ptr) {
        // free(nullptr) => no-op
        return;
    }

    uintptr_t pval = (uintptr_t) ptr;

    // 1. Check if ptr is definitely outside our entire heap range
    if (pval < stats.heap_min || pval >= stats.heap_max) {
        // "not in heap" error
        fprintf(stderr,
            "MEMORY BUG: %s:%ld: invalid free of pointer %p, not in heap\n",
            file, line, ptr);
        abort();
    }

    // 2. Look up exact pointer first
    allocation_header* header = find_header_exact(ptr);

    if (!header) {
        // Not an exact match => maybe it's inside some other block?
        allocation_header* container = find_header_containing(pval);

        if (container) {
            // It's inside another active block => “invalid free … not allocated”
            // plus the "is X bytes inside a Y byte region allocated here" message.
            size_t offset = pval - (uintptr_t)(container + 1);
            fprintf(stderr,
                "MEMORY BUG: %s:%ld: invalid free of pointer %p, not allocated\n",
                file, line, ptr);
            fprintf(stderr,
                "  %s:%ld: %p is %zu bytes inside a %zu byte region allocated here\n",
                container->file, container->line, ptr, offset, container->size);
            abort();
        } else {
            // Not found in any active block
            // Could be in a freed block => we can check the global list
            // to see if it's "double free" or "wild pointer," but the assignment
            // specifically wants "not allocated" unless it's exactly the same
            // pointer as a previously-freed block that’s still recognized.
            // The simplest approach: print "not allocated" & abort.
            //
            // If you *want* to detect “double free” of a pointer that was
            // previously freed, you'd need to keep it around in `active_blocks_map`
            // with an `active = false`. The assignment does require "double free"
            // detection, so let's see if we find it in the global list
            // with active=false:
            //
            // => We’ll do a quick linear or (optional) separate map for freed blocks
            //    to see if it matches exactly that pointer. Then print "double free"
            //    if so. But the instructions define "double free" specifically for
            //    a pointer that matched a previously-active block. So let's do
            //    a small check:

            // check the global list for a matching pointer with active=false
            // (This is O(n), but only hits in “rare” error cases.)
            allocation_header* scan = allocation_list_head;
            while (scan) {
                if ((void*)(scan + 1) == ptr) {
                    // found a match in a freed block => double free
                    if (!scan->active) {
                        fprintf(stderr,
                            "MEMORY BUG: %s:%ld: invalid free of pointer %p, double free\n",
                            file, line, ptr);
                        abort();
                    }
                }
                scan = scan->next;
            }

            // Otherwise, not allocated
            fprintf(stderr,
                "MEMORY BUG: %s:%ld: invalid free of pointer %p, not allocated\n",
                file, line, ptr);
            abort();
        }
    }

    // 3. We found a matching active block in `header`. Check for double free
    if (!header->active) {
        // We discovered it in the data structure but it's not active => double free
        fprintf(stderr,
            "MEMORY BUG: %s:%ld: invalid free of pointer %p, double free\n",
            file, line, ptr);
        abort();
    }

    // 4. Check the canaries
    // Left canary in the header
    if (header->left_canary != CANARY_MAGIC) {
        // The user wrote before the start of the block
        fprintf(stderr,
            "MEMORY BUG: %s:%ld: invalid free of pointer %p, not allocated\n",
            file, line, ptr);
        abort();
    }
    // Right canary at the end of the user region
    unsigned long long* right_canary
        = (unsigned long long*)((char*) ptr + header->size);
    if (*right_canary != CANARY_MAGIC) {
        // The user wrote beyond the end of the block
        fprintf(stderr,
            "MEMORY BUG: %s:%ld: detected wild write during free of pointer %p\n",
            file, line, ptr);
        abort();
    }

    // 5. Mark it inactive, update stats, remove from active structures
    header->active = false;
    stats.nactive--;
    stats.active_size -= header->size;
    remove_from_active_lists(header);

    // 6. Actually free the block's memory
    base_free(header);
}


void* dmalloc_calloc(size_t nmemb, size_t sz, const char* file, long line) {
    // Check for multiplication overflow in nmemb*sz
    size_t total;
    if (__builtin_mul_overflow(nmemb, sz, &total)) {
        // overflow => fail
        stats.nfail++;
        stats.fail_size += (nmemb * sz);
        return nullptr;
    }

    // Then do a normal dmalloc_malloc with that total
    void* ptr = dmalloc_malloc(total, file, line);
    if (ptr) {
        // If successful, zero it
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
    // Print all blocks that remain active => memory leak
    // Format:
    //   LEAK CHECK: file:line: allocated object 0xADDRESS with size SIZE
    for (allocation_header* p = allocation_list_head; p; p = p->next) {
        if (p->active) {
            void* user_ptr = (void*)(p + 1);
            printf("LEAK CHECK: %s:%ld: allocated object %p with size %zu\n",
                   p->file, p->line, user_ptr, p->size);
        }
    }
}

// For Task 7 (heavy hitters), you would implement here:
void dmalloc_print_heavy_hitter_report() {
    // Not required for Task 6
}

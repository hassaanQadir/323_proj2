#define M61_DISABLE 1
#include "dmalloc.hh"
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cinttypes>
#include <cassert>
#include <cstdarg> 

// You need these headers for the data structures
#include <map>
#include <unordered_map>
#include <vector>
#include <algorithm>

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


/// Helper: print out the error message and abort.
/// Use `abort()` or `exit(1)` as you prefer.
// static void memory_bug(const char* file, long line, const char* fmt, ...) {
//     va_list args;
//     va_start(args, fmt);
//     fprintf(stderr, "MEMORY BUG: %s:%ld: ", file, line);
//     vfprintf(stderr, fmt, args);
//     fprintf(stderr, "\n");
//     va_end(args);
//     abort();
// }


// ----- "Heavy Hitters" Data Structures -----
//
// We'll store the total allocated bytes for each (file, line) pair
// in a global unordered_map. Key: (file*, line), Value: total bytes allocated.
//
// Then we have a global "total_alloc_bytes_for_heavy" that accumulates
// the sum of all user-requested bytes. 
//
// You *could* do sampling here to handle large workloads, but an
// efficient map or hash approach (like std::unordered_map) is usually fine
// for up to tens or hundreds of thousands of distinct call sites.
//
// If you do want to do sampling, just sample 1/N allocations and multiply
// by N in your final totals. But the direct approach shown here often works
// for the assignment.

struct fileline {
    const char* file;
    long line;
};

struct fileline_hash {
    // Basic pointer+line combination as hash. 
    // We rely on pointer identity for `file` because the assignment
    // states `file` has static storage duration. 
    std::size_t operator()(fileline const& fl) const {
        // A common pattern is to combine the pointer bits and line bits.
        // Something simple:
        auto h1 = std::hash<const char*>()(fl.file);
        auto h2 = std::hash<long>()(fl.line);
        // combine
        // 0x9e3779b97f4a7c15 is a recommended "magic" constant (from boost)
        static const size_t magic = 0x9e3779b97f4a7c15ULL;
        // just a typical approach
        h1 ^= (h2 + magic + (h1 << 6) + (h1 >> 2));
        return h1;
    }
};

struct fileline_eq {
    bool operator()(fileline const& a, fileline const& b) const {
        return a.file == b.file && a.line == b.line;
    }
};

// Global container for heavy-hitter stats
static std::unordered_map<fileline, unsigned long long, fileline_hash, fileline_eq> heavy_map;
static unsigned long long total_heavy_alloc = 0;  // total user bytes allocated

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

    // Insert in the doubly-linked list (for leak reports)
    insert_into_allocation_list(header);

    // 4. Write the right canary after the user region
    void* user_ptr = (void*)(header + 1); // user data starts after header
    unsigned long long* right_canary
        = (unsigned long long*)((char*) user_ptr + user_size);
    *right_canary = CANARY_MAGIC;

    // 5. Update the aggregator statistics
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

    // 8. Track heavy-hitter data
    fileline fl{file, line};
    heavy_map[fl] += user_size;
    total_heavy_alloc += user_size;

    // 9. Return the user pointer
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
            // It's inside another active block
            size_t offset = pval - (uintptr_t)(container + 1);
            fprintf(stderr,
                "MEMORY BUG: %s:%ld: invalid free of pointer %p, not allocated\n",
                file, line, ptr);
            fprintf(stderr,
                "  %s:%ld: %p is %zu bytes inside a %zu byte region allocated here\n",
                container->file, container->line, ptr, offset, container->size);
            abort();
        } else {
            // Check if it’s a double free (same pointer, now inactive) 
            // or a wild pointer. We'll do a quick scan:
            allocation_header* scan = allocation_list_head;
            while (scan) {
                if ((void*)(scan + 1) == ptr) {
                    // found the same pointer in the global list
                    if (!scan->active) {
                        // double free
                        fprintf(stderr,
                            "MEMORY BUG: %s:%ld: invalid free of pointer %p, double free\n",
                            file, line, ptr);
                        abort();
                    }
                }
                scan = scan->next;
            }
            // Otherwise, truly "not allocated"
            fprintf(stderr,
                "MEMORY BUG: %s:%ld: invalid free of pointer %p, not allocated\n",
                file, line, ptr);
            abort();
        }
    }

    // 3. We found a matching active block in `header`. Check for double free
    if (!header->active) {
        fprintf(stderr,
            "MEMORY BUG: %s:%ld: invalid free of pointer %p, double free\n",
            file, line, ptr);
        abort();
    }

    // 4. Check the canaries
    if (header->left_canary != CANARY_MAGIC) {
        fprintf(stderr,
            "MEMORY BUG: %s:%ld: invalid free of pointer %p, not allocated\n",
            file, line, ptr);
        abort();
    }
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
        // For “fail_size”, some folks add `nmemb * sz`, but it’s already overflowed;
        // either approach is acceptable as long as you fail properly.
        stats.fail_size += (unsigned long long) nmemb * sz;
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


/// dmalloc_print_heavy_hitter_report()
///    Gathers all (file, line) call sites that have allocated user bytes,
///    sorts them in descending order by total bytes, then prints lines
///    until we exceed 80% of total allocation. Only print anything if
///    the top line is >= 20%.
void dmalloc_print_heavy_hitter_report() {
    // If no allocations, nothing to print
    if (total_heavy_alloc == 0) {
        return;
    }

    // 1. Gather all (file, line) => total_bytes into a vector
    std::vector<std::pair<fileline, unsigned long long>> info;
    info.reserve(heavy_map.size());
    for (auto const& kv : heavy_map) {
        info.push_back(kv);
    }

    // 2. Sort descending by total_bytes
    std::sort(info.begin(), info.end(),
              [](auto const& a, auto const& b) {
                  return a.second > b.second;
              });

    // 3. Check if the top line is < 20% => then print nothing
    double top_fraction
        = double(info[0].second) / double(total_heavy_alloc);
    if (top_fraction < 0.20) {
        // no "heavy hitters"
        return;
    }

    // 4. Print lines from top until we exceed 80% total
    double sum_fraction = 0.0;
    for (auto const& p : info) {
        double frac = double(p.second) / double(total_heavy_alloc);
        sum_fraction += frac;

        // Print this line
        double percent = frac * 100.0;
        printf("HEAVY HITTER: %s:%ld: %llu bytes (~%.1f%%)\n",
               p.first.file, p.first.line,
               (unsigned long long) p.second, percent);

        // If we’ve reached 80% or more, stop
        if (sum_fraction >= 0.80) {
            break;
        }
    }
}

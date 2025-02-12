#include "dmalloc.hh"
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cinttypes>
#include <cassert>
#include <cstdarg>
#include <map>
#include <unordered_map>
#include <vector>
#include <algorithm>

static dmalloc_statistics stats;

// A magic number to detect wild writes before the user block.
static const unsigned long long CANARY_MAGIC = 0xDEADC0DEDEADC0DEULL;

struct allocation_header {
    unsigned long long left_canary;   // canary before user data

    // Doubly-linked list pointers for *all* blocks (active or freed).
    allocation_header* prev;
    allocation_header* next;

    size_t size;          // user-requested size
    const char* file;     // file of allocation
    long line;            // line of allocation
    bool active;          // false => block is freed

    // User data follows immediately after this header:
    //    [ allocation_header | user_data... | right_canary ]
};

// A global doubly‐linked list of *all* allocations (active or freed).
// Freed blocks remain here; we never physically free them.
// They are marked inactive, but we keep them for debugging checks.
static allocation_header* allocation_list_head = nullptr;

// A helper function to insert a newly-allocated block at the head of the list.
static void insert_into_allocation_list(allocation_header* node) {
    node->prev = nullptr;
    node->next = allocation_list_head;
    if (allocation_list_head) {
        allocation_list_head->prev = node;
    }
    allocation_list_head = node;
}

// For quick detection of valid active pointers (exact match).
static std::unordered_map<void*, allocation_header*> active_blocks_map;

// For quick detection of partial/inside-block pointers.
static std::map<uintptr_t, allocation_header*> active_blocks_interval;

static allocation_header* find_header_exact(void* ptr) {
    auto it = active_blocks_map.find(ptr);
    return (it != active_blocks_map.end()) ? it->second : nullptr;
}

static allocation_header* find_header_containing(uintptr_t p) {
    if (active_blocks_interval.empty()) {
        return nullptr;
    }
    // Find the first region whose start > p, then step back one.
    auto it = active_blocks_interval.upper_bound(p);
    if (it == active_blocks_interval.begin()) {
        return nullptr;
    }
    --it;
    allocation_header* h = it->second;
    uintptr_t start = (uintptr_t)(h + 1);
    uintptr_t end_excl = start + h->size;
    if (p >= start && p < end_excl) {
        return h; // `p` is inside that block
    }
    return nullptr;
}

// Remove a block from the active‐block maps (exact pointer and interval).
// We still keep it in the global doubly‐linked list, so we do *not* modify
// `allocation_list_head`, `prev`, or `next`.
static void remove_from_active_lists(allocation_header* header) {
    void* user_ptr = (void*)(header + 1);

    auto it = active_blocks_map.find(user_ptr);
    if (it != active_blocks_map.end()) {
        active_blocks_map.erase(it);
    }

    auto it2 = active_blocks_interval.find((uintptr_t) user_ptr);
    if (it2 != active_blocks_interval.end()) {
        active_blocks_interval.erase(it2);
    }
}

// HEAVY HITTER tracking:
struct fileline {
    const char* file;
    long line;
};

struct fileline_hash {
    std::size_t operator()(fileline const& fl) const {
        // Combine pointer hash + line hash.
        auto h1 = std::hash<const char*>()(fl.file);
        auto h2 = std::hash<long>()(fl.line);
        static const size_t magic = 0x9e3779b97f4a7c15ULL;
        h1 ^= (h2 + magic + (h1 << 6) + (h1 >> 2));
        return h1;
    }
};

struct fileline_eq {
    bool operator()(fileline const& a, fileline const& b) const {
        return a.file == b.file && a.line == b.line;
    }
};

static std::unordered_map<fileline, unsigned long long,
                          fileline_hash, fileline_eq> heavy_map;
static unsigned long long total_heavy_alloc = 0;


//----------------------------------------------------------------------
// MALLOC

void* dmalloc_malloc(size_t user_size, const char* file, long line) {
    // Check for overflow: user_size + header + right_canary
    size_t total;
    if (__builtin_add_overflow(user_size, sizeof(allocation_header), &total)
     || __builtin_add_overflow(total, sizeof(unsigned long long), &total)) {
        // fail
        stats.nfail++;
        stats.fail_size += user_size;
        return nullptr;
    }

    // Use base_malloc to physically get the space
    allocation_header* header = (allocation_header*) base_malloc(total);
    if (!header) {
        // fail
        stats.nfail++;
        stats.fail_size += user_size;
        return nullptr;
    }

    // Fill in the header fields
    header->left_canary = CANARY_MAGIC;
    header->size        = user_size;
    header->file        = file;
    header->line        = line;
    header->active      = true;

    insert_into_allocation_list(header);

    // Write the right canary
    unsigned long long* right_canary
        = (unsigned long long*)((char*)(header + 1) + user_size);
    *right_canary = CANARY_MAGIC;

    // Stats
    stats.ntotal++;
    stats.total_size += user_size;
    stats.nactive++;
    stats.active_size += user_size;

    // Update heap min/max
    uintptr_t start = (uintptr_t)(header + 1);
    uintptr_t end_excl = start + user_size;
    if (stats.heap_min == 0 || start < stats.heap_min) {
        stats.heap_min = start;
    }
    if (end_excl > stats.heap_max) {
        stats.heap_max = end_excl;
    }

    // Insert into the “active” maps
    void* user_ptr = (void*)(header + 1);
    active_blocks_map[user_ptr] = header;
    active_blocks_interval[start] = header;

    // Heavy hitters
    fileline fl{file, line};
    heavy_map[fl] += user_size;
    total_heavy_alloc += user_size;

    // Return the user pointer
    return user_ptr;
}


//----------------------------------------------------------------------
// FREE (do NOT call base_free)

void dmalloc_free(void* ptr, const char* file, long line) {
    if (!ptr) {
        // free(nullptr) => no op
        return;
    }

    uintptr_t pval = (uintptr_t) ptr;
    // Check if ptr is outside the overall heap range
    if (pval < stats.heap_min || pval >= stats.heap_max) {
        fprintf(stderr,
            "MEMORY BUG: %s:%ld: invalid free of pointer %p, not in heap\n",
            file, line, ptr);
        abort();
    }

    // Look up exact pointer
    allocation_header* header = find_header_exact(ptr);
    if (!header) {
        // Maybe it's inside some other active block?
        allocation_header* container = find_header_containing(pval);
        if (container) {
            // partial pointer
            size_t offset = pval - (uintptr_t)(container + 1);
            fprintf(stderr,
                "MEMORY BUG: %s:%ld: invalid free of pointer %p, not allocated\n",
                file, line, ptr);
            fprintf(stderr,
                "  %s:%ld: %p is %zu bytes inside a %zu byte region allocated here\n",
                container->file, container->line, ptr, offset, container->size);
            abort();
        } else {
            // Possibly double free or truly wild
            // We can scan the global list to see if it matches an inactive block:
            for (allocation_header* scan = allocation_list_head; scan; scan = scan->next) {
                if ((void*)(scan + 1) == ptr) {
                    // same pointer but presumably not active => double free
                    if (!scan->active) {
                        fprintf(stderr,
                            "MEMORY BUG: %s:%ld: invalid free of pointer %p, double free\n",
                            file, line, ptr);
                        abort();
                    }
                }
            }
            fprintf(stderr,
                "MEMORY BUG: %s:%ld: invalid free of pointer %p, not allocated\n",
                file, line, ptr);
            abort();
        }
    }

    // We found a matching active block
    if (!header->active) {
        // double free
        fprintf(stderr,
            "MEMORY BUG: %s:%ld: invalid free of pointer %p, double free\n",
            file, line, ptr);
        abort();
    }

    // Check canaries
    if (header->left_canary != CANARY_MAGIC) {
        fprintf(stderr,
            "MEMORY BUG: %s:%ld: invalid free of pointer %p, not allocated\n",
            file, line, ptr);
        abort();
    }
    unsigned long long* right_canary
        = (unsigned long long*)((char*) ptr + header->size);
    if (*right_canary != CANARY_MAGIC) {
        // boundary write error
        fprintf(stderr,
            "MEMORY BUG: %s:%ld: detected wild write during free of pointer %p\n",
            file, line, ptr);
        abort();
    }

    // Mark inactive, update stats
    header->active = false;
    stats.nactive--;
    stats.active_size -= header->size;

    // Remove from the active pointer maps
    remove_from_active_lists(header);

    // DO NOT physically free the memory:
}


//----------------------------------------------------------------------
// CALLOC

void* dmalloc_calloc(size_t nmemb, size_t sz, const char* file, long line) {
    // Check for overflow in nmemb*sz
    size_t total;
    if (__builtin_mul_overflow(nmemb, sz, &total)) {
        // fail
        stats.nfail++;
        // Some folks add nmemb*sz to fail_size but it overflowed,
        // either approach is fine as long as you record the error properly.
        stats.fail_size += (unsigned long long) nmemb * sz;
        return nullptr;
    }

    // Use dmalloc_malloc for the actual allocation
    void* ptr = dmalloc_malloc(total, file, line);
    if (ptr) {
        memset(ptr, 0, total);
    }
    return ptr;
}


//----------------------------------------------------------------------
// STATISTICS

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


//----------------------------------------------------------------------
// LEAK REPORT

void dmalloc_print_leak_report() {
    // Print all blocks that remain active => memory leak
    for (allocation_header* p = allocation_list_head; p; p = p->next) {
        if (p->active) {
            void* user_ptr = (void*)(p + 1);
            printf("LEAK CHECK: %s:%ld: allocated object %p with size %zu\n",
                   p->file, p->line, user_ptr, p->size);
        }
    }
}


//----------------------------------------------------------------------
// HEAVY HITTERS

void dmalloc_print_heavy_hitter_report() {
    if (total_heavy_alloc == 0) {
        // no allocations at all
        return;
    }

    // Convert map to a vector
    std::vector<std::pair<fileline, unsigned long long>> info;
    info.reserve(heavy_map.size());
    for (auto& kv : heavy_map) {
        info.push_back(kv);
    }
    // Sort descending by total bytes
    std::sort(info.begin(), info.end(),
              [](auto const& a, auto const& b) {
                  return a.second > b.second;
              });

    double top_fraction
        = double(info[0].second) / double(total_heavy_alloc);
    // If top site < 20%, we consider no heavy hitters
    if (top_fraction < 0.20) {
        return;
    }

    double sum_fraction = 0.0;
    for (auto& kv : info) {
        double frac = double(kv.second) / double(total_heavy_alloc);
        sum_fraction += frac;
        double percent = frac * 100.0;

        // Print this line
        printf("HEAVY HITTER: %s:%ld: %llu bytes (~%.1f%%)\n",
               kv.first.file, kv.first.line,
               (unsigned long long) kv.second, percent);

        if (sum_fraction >= 0.80) {
            break;
        }
    }
}


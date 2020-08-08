#ifndef PYBPF_AUTO_INCLUDES_H
#define PYBPF_AUTO_INCLUDES_H

#include "vmlinux.h"

#include <bpf/bpf_core_read.h> /* for BPF CO-RE helpers */
#include <bpf/bpf_helpers.h> /* most used helpers: SEC, __always_inline, etc */
#include <bpf/bpf_tracing.h> /* for getting kprobe arguments */

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

/* Declare a BPF ringbuf map @NAME with 2^(@PAGES) size */
#define BPF_RINGBUF(NAME, PAGES) \
    struct { \
        __uint(type, BPF_MAP_TYPE_RINGBUF); \
        __uint(max_entries, ((1 << PAGES) * PAGE_SIZE)); \
    } NAME SEC(".maps")

/* Declare a BPF hashmap @NAME with key type @KEY, value type @VALUE, and @SIZE
 * max entries. The map creation flags may be specified with @FLAGS. */
#define BPF_HASH(NAME, KEY, VALUE, SIZE, FLAGS) \
    struct { \
        __uint(type, BPF_MAP_TYPE_HASH); \
        __uint(max_entries, SIZE); \
        __type(key, KEY); \
        __type(value, VALUE); \
        __uint(map_flags, FLAGS); \
    } NAME SEC(".maps")

/* Declare an LRU BPF hashmap @NAME with key type @KEY, value type @VALUE, and
 * @SIZE max entries. The map creation flags may be specified with @FLAGS. */
#define BPF_LRU_HASH(NAME, KEY, VALUE, SIZE, FLAGS) \
    struct { \
        __uint(type, BPF_MAP_TYPE_LRU_HASH); \
        __uint(max_entries, SIZE); \
        __type(key, KEY); \
        __type(value, VALUE); \
        __uint(map_flags, FLAGS); \
    } NAME SEC(".maps")

/* Declare a per-cpu BPF hashmap @NAME with key type @KEY, value type @VALUE, and
 * @SIZE max entries. The map creation flags may be specified with @FLAGS. */
#define BPF_PERCPU_HASH(NAME, KEY, VALUE, SIZE, FLAGS) \
    struct { \
        __uint(type, BPF_MAP_TYPE_PERCPU_HASH); \
        __uint(max_entries, SIZE); \
        __type(key, KEY); \
        __type(value, VALUE); \
        __uint(map_flags, FLAGS); \
    } NAME SEC(".maps")

/* Declare a per-cpu LRU BPF hashmap @NAME with key type @KEY, value type @VALUE,
 * and @SIZE max entries. The map creation flags may be specified with @FLAGS. */
#define BPF_LRU_PERCPU_HASH(NAME, KEY, VALUE, SIZE, FLAGS) \
    struct { \
        __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH); \
        __uint(max_entries, SIZE); \
        __type(key, KEY); \
        __type(value, VALUE); \
        __uint(map_flags, FLAGS); \
    } NAME SEC(".maps")

/* Declare a BPF array @NAME with value type @VALUE, and @SIZE max entries.
 * The map creation flags may be specified with @FLAGS. */
#define BPF_ARRAY(NAME, VALUE, SIZE, FLAGS) \
    struct { \
        __uint(type, BPF_MAP_TYPE_ARRAY); \
        __uint(max_entries, SIZE); \
        __type(key, unsigned int); \
        __type(value, VALUE); \
        __uint(map_flags, FLAGS); \
    } NAME SEC(".maps")

/* Declare a per-cpu BPF array @NAME with value type @VALUE, and @SIZE max
 * entries.  The map creation flags may be specified with @FLAGS. */
#define BPF_PERCPU_ARRAY(NAME, VALUE, SIZE, FLAGS) \
    struct { \
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); \
        __uint(max_entries, SIZE); \
        __type(key, unsigned int); \
        __type(value, VALUE); \
        __uint(map_flags, FLAGS); \
    } NAME SEC(".maps")

/* TODO: add remaining map types */

#endif /* ifndef PYBPF_AUTO_INCLUDES_H */

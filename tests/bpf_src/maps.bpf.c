#include "pybpf.bpf.h" /* Auto generated helpers */

/* A ringbuf */
BPF_RINGBUF(ringbuf, 1);

/* hash map types */
BPF_HASH(hash, int, int, 5, 0);
BPF_LRU_HASH(lru_hash, int, int, 10240, 0);
BPF_PERCPU_HASH(percpu_hash, int, int, 5, 0);
BPF_LRU_PERCPU_HASH(lru_percpu_hash, int, int, 5, 0);

/* array types */
BPF_ARRAY(array, int, 5, 0);
BPF_PERCPU_ARRAY(percpu_array, int, 5, 0);

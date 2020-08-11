#include "pybpf.bpf.h"

BPF_CGROUP_ARRAY(cgroup_fds, 10240, 0);
BPF_CGROUP_STORAGE(cgroup_storage, u64, 0);

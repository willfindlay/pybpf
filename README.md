# PyBPF 🐍💞🐝

An opinionated libbpf/BPF CO-RE (Compile Once---Run Everywhere) library for the Python3 (read Python 3.6+) ecosystem.

**DISCLAIMER:** This library is in **pre-alpha** version and changes may result in
API breakages. Pre-release version API breakages will be accompanied by a minor
version number bump. Versions post 1.0.0 will follow semantic versioning and
breakages will require a bump in major version number.

## Compilation Requirements

- Latest libbpf (https://github.com/libbpf/libbpf)
- Linux kernel compiled with BTF debug info
- bpftool (available from under linux/tools/bpf/bpftool from official kernel repositories)
- Clang/LLVM 10+
- gcc
- Python 3.6+

## Deployment Requirements

- A pre-compiled shared library for your BPF program, generated with PyBPF (see requirements above)
- Linux kernel compiled with BTF debug info
- Python 3.6+

## Development Roadmap

**Completed Features:**
- Python `BPFObjectBuilder` that takes care of BPF program compilation and loading
- Python `BPFObject` that provides an interface into BPF programs and maps
- The following map types:
    - `HASH`
    - `PERCPU_HASH`
    - `LRU_HASH`
    - `LRU_PERCPU_HASH`
    - `ARRAY`
    - `PERCPU_ARRAY`
    - `QUEUE`
    - `STACK`

**Coming Features**
- The following map types:
    - `PROG_ARRAY`
    - `PERF_EVENT_ARRAY`
    - `STACK_TRACE`
    - `CGROUP_ARRAY`
    - `LPM_TRIE`
    - `ARRAY_OF_MAPS`
    - `HASH_OF_MAPS`
    - `DEVMAP`
    - `SOCKMAP`
    - `CPUMAP`
    - `XSKMAP`
    - `SOCKHASH`
    - `CGROUP_STORAGE`
    - `REUSEPORT_SOCKARRAY`
    - `PERCPU_CGROUP_STORAGE`
    - `SK_STORAGE`
    - `DEVMAP_HASH`
    - `STRUCT_OPS`
- USDT, uprobe loading
- `pybpf` CLI tool for bootstrapping PyBPF projects

**Distant Future:**
- Automatic map key/value type inference
- Automatic per-event type inference

## Reference Guide

Coming soon!

## Cool PyBPF Projects

Coming soon!

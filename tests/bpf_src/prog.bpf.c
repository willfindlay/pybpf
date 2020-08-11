#include "pybpf.bpf.h"

SEC("fentry/bpf_modify_return_test")
int fentry_modify_return_test(void *args)
{
    return 0;
}

SEC("fexit/bpf_modify_return_test")
int fexit_modify_return_test(void *args)
{
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int tracepoint_sys_enter(void *args)
{
    return 0;
}

SEC("tp_btf/sys_enter")
int BPF_PROG(tp_btf_sys_enter, struct pt_regs *regs, long id)
{
    return 0;
}

char _license[] SEC("license") = "GPL";

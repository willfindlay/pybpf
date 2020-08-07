// clang-format off
#include "vmlinux.h"
// clang-format on

#include <bpf/bpf_core_read.h> /* for BPF CO-RE helpers */
#include <bpf/bpf_helpers.h> /* most used helpers: SEC, __always_inline, etc */
#include <bpf/bpf_tracing.h> /* for getting kprobe arguments */

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
} ringbuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
} ringbuf2 SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_clock_nanosleep")
SEC("tracepoint/syscalls/sys_enter_nanosleep")
int sys_enter(struct trace_event_raw_sys_enter *args)
{
    int *five = bpf_ringbuf_reserve(&ringbuf, sizeof(int), 0);
    if (five) {
        *five = 5;
        bpf_ringbuf_submit(five, BPF_RB_FORCE_WAKEUP);
    }

    int *ten = bpf_ringbuf_reserve(&ringbuf2, sizeof(int), 0);
    if (ten) {
        *ten = 10;
        bpf_ringbuf_submit(ten, BPF_RB_FORCE_WAKEUP);
    }
    return 0;
}

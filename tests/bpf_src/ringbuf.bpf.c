#include "pybpf.bpf.h" /* Auto generated helpers */

BPF_RINGBUF(ringbuf, 3);
BPF_RINGBUF(ringbuf2, 3);

SEC("tracepoint/syscalls/sys_enter_nanosleep")
int do_nanosleep(struct trace_event_raw_sys_enter *args)
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

SEC("tracepoint/syscalls/sys_enter_clock_nanosleep")
int do_clock_nanosleep(struct trace_event_raw_sys_enter *args)
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

// +build ignore

#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tracing.h"

char __license[] SEC("license") = "GPL";

#define MAX_MANAGED_PIDS 128
#define ONE_SECOND_NS 1000000000ULL

// Data structure for alerts sent to userspace
struct event {
	u32 pid;
	u64 allocation_size;
    u64 threshold;
};

// Perf event map for sending data to userspace
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

// Map to store PIDs of processes we are managing
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_MANAGED_PIDS);
	__type(key, u32); // PID
	__type(value, u8); // 1 if managed
} managed_pids SEC(".maps");

// Map to track allocation stats per PID
struct allocation_stat {
    u64 last_seen_ns;
    u64 bytes_allocated;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_MANAGED_PIDS);
    __type(key, u32); // PID
    __type(value, struct allocation_stat);
} allocation_stats SEC(".maps");


// Configuration from userspace (e.g., allocation threshold)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64); // threshold in bytes
} config_map SEC(".maps");


SEC("kprobe/__x64_sys_mmap")
int BPF_KPROBE(mmap_probe, struct pt_regs *regs, unsigned long addr, unsigned long len)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Check if this is a process we should monitor
    u8 *is_managed = bpf_map_lookup_elem(&managed_pids, &pid);
    if (!is_managed) {
        return 0;
    }

    // Get the allocation threshold from the config map
    u32 config_key = 0;
    u64 *threshold = bpf_map_lookup_elem(&config_map, &config_key);
    if (!threshold) {
        return 0;
    }

    u64 now = bpf_ktime_get_ns();
    struct allocation_stat *stats = bpf_map_lookup_elem(&allocation_stats, &pid);
    struct allocation_stat new_stats = {};

    if (stats) {
        // If the last allocation was over a second ago, reset the counter
        if (now - stats->last_seen_ns > ONE_SECOND_NS) {
            new_stats.bytes_allocated = len;
        } else {
            new_stats.bytes_allocated = stats->bytes_allocated + len;
        }
    } else {
        new_stats.bytes_allocated = len;
    }
    new_stats.last_seen_ns = now;

    bpf_map_update_elem(&allocation_stats, &pid, &new_stats, BPF_ANY);

    // If allocation exceeds threshold, send an event
    if (new_stats.bytes_allocated > *threshold) {
        struct event e = {};
        e.pid = pid;
        e.allocation_size = new_stats.bytes_allocated;
        e.threshold = *threshold;
        
        bpf_perf_event_output(regs, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
        
        // Reset counter after sending event to avoid spamming
        new_stats.bytes_allocated = 0;
        bpf_map_update_elem(&allocation_stats, &pid, &new_stats, BPF_ANY);
    }

    return 0;
}

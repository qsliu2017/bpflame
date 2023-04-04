//go:build ignore

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
  __u64 pid_tgid;
  __u64 ts;
  __u64 cookie;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

SEC("uprobe/dummy")
int uprobe(void *ctx) {
  struct event event = {
      .pid_tgid = bpf_get_current_pid_tgid(),
      .ts = bpf_ktime_get_boot_ns(),
      .cookie = bpf_get_attach_cookie(ctx),
  };

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

  return 0;
}

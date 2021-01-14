/*
 * Author: monkeyyang@tencent.com
 */
#include <linux/kconfig.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/icmp.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/icmpv6.h>
#include <net/inet_sock.h>
#include <linux/netfilter/x_tables.h>
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#include <linux/bpf.h>
#pragma clang diagnostic pop
#include "./bpf_helpers.h"
#define member_copy(destination, struct, member)  \
  do{                                             \
    bpf_probe_read(                               \
      destination,                                \
      sizeof((struct)->member),                   \
      &((struct)->member)                         \
    );                                            \
  } while(0)

struct probe_event_t {
	__u64 cpu;
	__u32 pid;
	__u32 netns;
	__u32 state;
	char comm[TASK_COMM_LEN]; // 16
	char ifname[IFNAMSIZ]; // 16
};

struct bpf_map_def SEC("maps/netns_to_watch") netns_to_watch = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 16,
};

struct bpf_map_def SEC("maps/probe_event") probe_event = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(__u32),
	.max_entries = 1024,
};

SEC("kprobe/dev_change_flags")
int kprobe__dev_change_flags(struct pt_regs *ctx)
{
	struct probe_event_t event = { 0 };
	struct net* net;
	unsigned int old_flags;
	u32 *exists;

	struct net_device *dev = (void *)PT_REGS_PARM1(ctx);
	unsigned int flags = PT_REGS_PARM2(ctx);

	member_copy(&net, &dev->nd_net, net);
	member_copy(&event.netns, &net->ns, inum);

	exists = bpf_map_lookup_elem(&netns_to_watch, &event.netns);
	if (exists == NULL || !*exists)
		return 0;

	member_copy(&old_flags, dev, flags);
	if ((old_flags ^ flags) & IFF_UP) {
		if (old_flags & IFF_UP) {
			event.state = 1; // close	
		} else {
			event.state = 2; //open
		}
	}

	event.cpu = bpf_get_smp_processor_id();
	event.pid = bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.comm, TASK_COMM_LEN);
	bpf_probe_read(&event.ifname, IFNAMSIZ, dev->name);

	bpf_perf_event_output(ctx, &probe_event, event.cpu, &event, sizeof(event));
	return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;

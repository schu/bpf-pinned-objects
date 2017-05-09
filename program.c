#include <linux/kconfig.h>
#include <linux/bpf.h>

#include "bpf_helpers.h"


typedef struct {
	char syscall[64];
	u32 pid;
	u32 fd;
} event_t;

#define PIN_GLOBAL_NS 2

/* This is a key/value store with the keys being the cpu number
 * and the values being a perf file descriptor.
 */
struct bpf_map_def SEC("maps/events") event = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(__u32),
	.max_entries = 1024,
        .map_flags = 0,
	.pinning = PIN_GLOBAL_NS,
	.namespace = "test",
};

SEC("kprobe/SyS_fchownat")
int kprobe__sys_fchownat(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	u32 cpu = bpf_get_smp_processor_id();
	event_t evt = {
		.syscall = "fchownat",
		.pid = pid >> 32,
		.fd = (u32)PT_REGS_PARM1(ctx),
	};

	int ret;
	ret = bpf_perf_event_output(ctx, &event, cpu, &evt, sizeof(evt));
	if (ret < 0) {
		char err[] = "[ELF] error sending perf event: %d\n";
		bpf_trace_printk(err, sizeof(err), ret);
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
// this number will be interpreted by the elf loaderto set the current running
// kernel version
__u32 _version SEC("version") = 0xFFFFFFFE;

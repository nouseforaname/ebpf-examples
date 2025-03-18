//go:build ignore
#include "vmlinux.h"
#include "string.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define FNAME_LEN 128
#define MSG_LEN 128
#define META_LEN 32

struct custom_message_t {
	u32 pid;
	u8 message[MSG_LEN];
	u8 meta[META_LEN];
};

struct exec_data_t {
	u32 pid;
	u8 fname[FNAME_LEN];
	u8 comm[FNAME_LEN];
};
// For Rust libbpf-rs only
struct exec_data_t _edt = {0};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

struct execve_entry_args_t {
	u64 _unused;
	u64 _unused2;

	const char* filename;
	const char* const* argv;
	const char* const* envp;
};

#define LAST_32_BITS(x) x & 0xFFFFFFFF
#define FIRST_32_BITS(x) x >> 32

//SEC("tracepoint/syscalls/sys_enter_execve")
//int enter_execve(struct execve_entry_args_t *args)
//{
//	struct exec_data_t exec_data = {};
//	u64 pid_tgid;
//
//	pid_tgid = bpf_get_current_pid_tgid();
//	exec_data.pid = LAST_32_BITS(pid_tgid);
//	bpf_probe_read_user_str(exec_data.fname,
//		sizeof(exec_data.fname), args->filename);
//
//	bpf_get_current_comm(exec_data.comm, sizeof(exec_data.comm));
//
//	bpf_perf_event_output(args, &events,
//		BPF_F_CURRENT_CPU, &exec_data, sizeof(exec_data));
//
//	return 0;
//}


//SEC("kprobe/do_unlink")
//int BPF_KPROBE(do_unlink, int dfd, struct filename *name)
//{
//    pid_t pid;
//    const char filename[128];
//
//	  struct custom_message_t data = {};
//	  pid = bpf_get_current_pid_tgid();
//	  data.pid = LAST_32_BITS(pid);
//    BPF_CORE_READ_STR_INTO(&filename, name, name);
//    BPF_SNPRINTF((char*)data.message, MSG_LEN, "msg: of %s", filename );
//    BPF_SNPRINTF((char*)data.meta, META_LEN, "%d", pid );
//    struct exec_data_t exec_data = {};
//    bpf_perf_event_output(ctx, &events,
//      BPF_F_CURRENT_CPU, &data, sizeof(data));
//    return 0;
//}

// loops can only use a static size for iterations. else the verifier will not load the module
// even then, the iteration count cannot get too high. so this here is for very basic filtering for events to limit the amount of uninteresting syscalls forwarded to userspace. Proper filtering should be done in the userspace process..
#define FILTERS_LEN 4
static const char *filters[]={
    "/dev/shm\0",
    "/tmp/nix\0",
    "/run/udev\0",
    "unlink.c~'"
};

SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
{

    pid_t pid;
    const char *filename;
    char filename_prefix[32];

	  struct custom_message_t data = {};
	  pid = bpf_get_current_pid_tgid();
	  data.pid = LAST_32_BITS(pid);
    int i = 0;
    filename = BPF_CORE_READ(name, name);
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    bool output = true;
    #pragma unroll
    for (int i=0; i < FILTERS_LEN; i++) {
      const char *f = filters[i];
      size_t s = strlen(f);
      BPF_SNPRINTF(filename_prefix, s, "%s", filename);
      if (strncmp(f, filename_prefix, s-1) == 0 ) {
        output = false;
      }
    }
    if (output) {
      int giduid = bpf_get_current_uid_gid();

      BPF_SNPRINTF((char*)data.message, MSG_LEN, "del on: '%s'", filename); //, sizeof(filename)
      BPF_SNPRINTF((char*)data.meta, META_LEN, "%d", giduid);
      struct exec_data_t exec_data = {};
      bpf_perf_event_output(ctx, &events,
        BPF_F_CURRENT_CPU, &data, sizeof(data));
    }

    return 0;
}

//SEC("kretprobe/do_unlinkat")
//int BPF_KRETPROBE(do_unlinkat_exit, long ret)
//{
//    pid_t pid;
//
//	  struct custom_message_t data = {};
//    pid = bpf_get_current_pid_tgid() >> 32;
//  	bpf_perf_event_output(ctx, &events,
//		BPF_F_CURRENT_CPU, &data, sizeof(data));
//    bpf_printk("pid = %d, delete ret = %s\n", pid, ret);
//    return 0;
//

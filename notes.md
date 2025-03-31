# writing a BPF program

## understand what's there.

There are many hooks available. First understand the subsystem you're targetting. This will mostly depend on what you want to achieve. E.g. if you're targetting network functionality, there's a likelihood you'll want to look at the XDP program type. Further options include kernel and uerprobes, cgroup related options, kernel tracepoints as well as `lsm` hooks ( the same features are used by apparmor and selinux ).


### bpftool

`bpftool feature probe kernel` will list available bpf types for the supported BPF program types.


```
 sudo bpftool feature probe kernel | grep -A2 'kprobe'
eBPF program_type kprobe is available
eBPF program_type sched_cls is available
eBPF program_type sched_act is available
--
eBPF helpers supported for program type kprobe:
        - bpf_map_lookup_elem
        - bpf_map_update_elem
```

# aya-rs usage
`bpf_probe_read_kernel_str_bytes`: https://github.com/lockc-project/lockc/blob/6a2926de422d1f6640629e02413dbfc8f0e3d20f/lockc-ebpf/src/main.rs#L107

// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
//
// recorder.c — eBPF tracepoint hooks for sudo-logger-agent.
//
// Three hooks:
//   1. tracepoint/syscalls/sys_enter_write   → sl_io_event (PTY I/O, tracked cgroups)
//   2. tracepoint/syscalls/sys_enter_execve  → exec_event (sudo/pkexec, any cgroup)
//   3. tracepoint/sched/sched_process_exit   → exit_event (exit, tracked cgroups)
//
// All events share a ring buffer.  The first byte is always event_type so
// userspace can dispatch without additional framing.
//
// Build prerequisites:
//   bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
//   clang -O2 -g -target bpf -D__TARGET_ARCH_x86_64 ...

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_DATA_SIZE 4096

#define EVENT_IO   1
#define EVENT_EXEC 2
#define EVENT_EXIT 3

// Stream type constants — must match protocol package.
#define STREAM_TTYIN  3
#define STREAM_TTYOUT 4

// Linux PTY device major numbers.
#define PTY_SLAVE_MAJOR_MIN 136
#define PTY_SLAVE_MAJOR_MAX 143
#define PTY_MASTER_MAJOR    5

#define MINORBITS 20
#define DEV_MAJOR(dev) ((unsigned int)((dev) >> MINORBITS))

// ── Maps ──────────────────────────────────────────────────────────────────────

// Tracked session cgroups: key = cgroup inode (BPF cgroup ID),
// value = null-terminated session ID (max 63 chars + NUL).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u64);
	__type(value, __u8[64]);
} tracked_cgroups SEC(".maps");

// Tracked sudo PIDs: key = pid (u32), value = u8 marker.
// When the agent registers a plugin session, it inserts the sudo process PID.
// The execve hook checks the invoking process's parent (and grandparent) against
// this map to suppress the child execve that sudo fires when running the target
// command.  This correctly handles sudo's monitor-process architecture where
// sudo may interpose a monitor process between itself and the target.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, __u8);
} tracked_sudo_pids SEC(".maps");

// Ring buffer for all events.  8 MB gives ~2000 full io_events of headroom.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 8 * 1024 * 1024);
} events SEC(".maps");

// ── Event structures ──────────────────────────────────────────────────────────
// Each struct has event_type as its first byte.
// Go-side mirrors must match exactly (little-endian, no implicit padding beyond explicit pads).

// sl_io_event: PTY write event from a tracked cgroup.
// Named sl_io_event to avoid collision with the kernel's struct io_event (POSIX AIO).
// Layout: event_type(1) stream(1) pad(2) data_len(4) cgroup_id(8) timestamp_ns(8) data(4096)
struct sl_io_event {
	__u8  event_type;
	__u8  stream;
	__u8  pad[2];
	__u32 data_len;
	__u64 cgroup_id;
	__u64 timestamp_ns;
	__u8  data[MAX_DATA_SIZE];
};

// exec_event: sudo or pkexec execve from any cgroup.
// Layout: event_type(1) comm(15) pid(4) uid(4) cgroup_id(8) timestamp_ns(8) target(64)
struct exec_event {
	__u8  event_type;
	__u8  comm[15];    // "sudo" or "pkexec" (null-terminated)
	__u32 pid;
	__u32 uid;
	__u64 cgroup_id;   // parent cgroup ID (before pkexec creates a new transient scope)
	__u64 timestamp_ns;
	__u8  target[64];  // path passed to execve — captured at tracepoint time
};

// exit_event: process exit inside a tracked cgroup.
// Layout: event_type(1) pad(3) exit_code(4) cgroup_id(8) timestamp_ns(8)
struct exit_event {
	__u8  event_type;
	__u8  pad[3];
	__u32 exit_code;
	__u64 cgroup_id;
	__u64 timestamp_ns;
};

// ── Helpers ───────────────────────────────────────────────────────────────────

// fd_major walks the current task's file table to return the major device
// number of fd.  Returns 0 on any error.
static __always_inline __u32 fd_major(int fd)
{
	struct task_struct *task;
	struct files_struct *files;
	struct fdtable *fdt;
	struct file **farr;
	struct file *f = NULL;
	struct inode *inode;
	dev_t rdev;

	if (fd < 0)
		return 0;

	task = (struct task_struct *)bpf_get_current_task();
	files = BPF_CORE_READ(task, files);
	if (!files)
		return 0;
	fdt = BPF_CORE_READ(files, fdt);
	if (!fdt)
		return 0;
	farr = BPF_CORE_READ(fdt, fd);
	if (!farr)
		return 0;
	if (bpf_core_read(&f, sizeof(f), &farr[fd]))
		return 0;
	if (!f)
		return 0;
	inode = BPF_CORE_READ(f, f_inode);
	if (!inode)
		return 0;
	rdev = BPF_CORE_READ(inode, i_rdev);
	return DEV_MAJOR(rdev);
}

// ── Hook 1: PTY write ─────────────────────────────────────────────────────────

SEC("tracepoint/syscalls/sys_enter_write")
int record_write(struct trace_event_raw_sys_enter *ctx)
{
	__u64 cgid = bpf_get_current_cgroup_id();
	if (!bpf_map_lookup_elem(&tracked_cgroups, &cgid))
		return 0;

	int fd = (int)ctx->args[0];
	const void *ubuf = (const void *)ctx->args[1];
	__u64 count = (__u64)ctx->args[2];

	if (count == 0)
		return 0;

	__u32 major = fd_major(fd);
	__u8 stream;

	if (major >= PTY_SLAVE_MAJOR_MIN && major <= PTY_SLAVE_MAJOR_MAX)
		stream = STREAM_TTYOUT;
	else if (major == PTY_MASTER_MAJOR)
		stream = STREAM_TTYIN;
	else
		return 0;

	struct sl_io_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->event_type   = EVENT_IO;
	e->stream       = stream;
	e->pad[0]       = e->pad[1] = 0;
	e->cgroup_id    = cgid;
	e->timestamp_ns = bpf_ktime_get_ns();

	__u32 len = count > MAX_DATA_SIZE ? MAX_DATA_SIZE : (__u32)count;
	e->data_len = len;

	if (bpf_probe_read_user(e->data, len, ubuf) < 0) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}

// ── Hook 2: sudo / pkexec ─────────────────────────────────────────────────────
// Fires on any execve where the executing process is named "sudo" or "pkexec".
//
// sudo fires sys_enter_execve twice per invocation:
//   1. When the shell forks and the child exec's sudo (new session — we want this).
//   2. When sudo (or its monitor child) exec's the target command (we skip this).
//
// We distinguish the two by checking whether the process's parent (or
// grandparent) is a PID registered in tracked_sudo_pids.  The agent inserts
// the sudo PID when the plugin opens a session; by the time the second execve
// fires the PID is already in the map.  Two ancestry levels handle sudo's
// optional monitor-process architecture (sudo → monitor → target).

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
	char comm[16];
	bpf_get_current_comm(comm, sizeof(comm));

	bool is_sudo   = (comm[0]=='s' && comm[1]=='u' && comm[2]=='d' && comm[3]=='o' && comm[4]=='\0');
	bool is_pkexec = (comm[0]=='p' && comm[1]=='k' && comm[2]=='e' && comm[3]=='x'
	                  && comm[4]=='e' && comm[5]=='c' && comm[6]=='\0');

	if (!is_sudo && !is_pkexec)
		return 0;

	// Skip if the invoking process is a child of a tracked sudo session.
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct task_struct *parent = BPF_CORE_READ(task, real_parent);
	__u32 ppid = BPF_CORE_READ(parent, tgid);
	if (bpf_map_lookup_elem(&tracked_sudo_pids, &ppid))
		return 0;

	// Also check grandparent to handle sudo's monitor-process architecture.
	struct task_struct *gparent = BPF_CORE_READ(parent, real_parent);
	__u32 pppid = BPF_CORE_READ(gparent, tgid);
	if (bpf_map_lookup_elem(&tracked_sudo_pids, &pppid))
		return 0;

	struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->event_type   = EVENT_EXEC;
	e->cgroup_id    = bpf_get_current_cgroup_id();
	e->timestamp_ns = bpf_ktime_get_ns();
	e->pid          = (bpf_get_current_pid_tgid() >> 32);
	e->uid          = (bpf_get_current_uid_gid() & 0xffffffff);

	__builtin_memcpy(e->comm, comm, 15);
	e->comm[14] = '\0';

	// Capture the path being exec'd.  For pkexec this is the target command
	// (e.g. "/bin/ls"); for sudo this is the sudo binary itself.  Reading
	// at tracepoint time avoids the race where the process dies before Go
	// can read /proc/<pid>/cmdline.
	const char *target_path = (const char *)(long)ctx->args[0];
	bpf_probe_read_user_str(e->target, sizeof(e->target), target_path);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

// ── Hook 3: process exit ──────────────────────────────────────────────────────

SEC("tracepoint/sched/sched_process_exit")
int record_exit(struct trace_event_raw_sched_process_template *ctx)
{
	__u64 cgid = bpf_get_current_cgroup_id();
	if (!bpf_map_lookup_elem(&tracked_cgroups, &cgid))
		return 0;

	struct exit_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->event_type   = EVENT_EXIT;
	e->pad[0]       = e->pad[1] = e->pad[2] = 0;
	e->cgroup_id    = cgid;
	e->timestamp_ns = bpf_ktime_get_ns();

	// Extract WEXITSTATUS from kernel exit_code (bits 8-15).
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	int kcode = BPF_CORE_READ(task, exit_code);
	e->exit_code = ((__u32)kcode >> 8) & 0xff;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
//
// recorder.c — eBPF tracepoint hook for PTY session recording.
//
// Hooks sys_enter_write and filters on:
//   1. The writing process belongs to a tracked cgroup (BPF map lookup).
//   2. The target fd is a PTY device (major 136-143 = slave, 5 = master).
//
// Tracked sessions are registered/unregistered by the userspace daemon via
// the tracked_cgroups hash map.  Events are pushed to userspace via a ring
// buffer.
//
// Build prerequisites (see Makefile):
//   bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
//   clang -O2 -g -target bpf -D__TARGET_ARCH_x86_64 ...

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Maximum payload copied per write() call.  Larger writes are truncated.
#define MAX_DATA_SIZE 4096

// Stream type constants — must match protocol package.
#define STREAM_TTYIN  3   // user keystrokes  (sshd → PTY master)
#define STREAM_TTYOUT 4   // program output   (shell/app → PTY slave)

// Linux PTY device major numbers.
// PTY slave (/dev/pts/N): major 136–143 (up to 8*256 = 2048 concurrent ptys).
// PTY master (fd from posix_openpt / /dev/ptmx): major 5.
#define PTY_SLAVE_MAJOR_MIN 136
#define PTY_SLAVE_MAJOR_MAX 143
#define PTY_MASTER_MAJOR    5

// Upper 12 bits of dev_t encode the major device number on Linux.
#define MINORBITS 20
#define DEV_MAJOR(dev) ((unsigned int)((dev) >> MINORBITS))

// ── Maps ──────────────────────────────────────────────────────────────────────

// Userspace registers sessions here: key = cgroup inode (= BPF cgroup ID),
// value = null-terminated session ID string (max 63 chars + NUL).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u64);
	__type(value, __u8[64]);
} tracked_cgroups SEC(".maps");

// Ring buffer for I/O events delivered to userspace.  8 MB gives ~2000
// full-sized events of headroom before userspace falls behind.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 8 * 1024 * 1024);
} events SEC(".maps");

// ── Event structure ───────────────────────────────────────────────────────────
// Layout must match IoEvent in sessions.go (little-endian, no implicit padding
// beyond the explicit pad[3] field).

struct io_event {
	__u64 cgroup_id;
	__u64 timestamp_ns;
	__u32 data_len;
	__u8  stream;
	__u8  pad[3];
	__u8  data[MAX_DATA_SIZE];
};

// ── Helpers ───────────────────────────────────────────────────────────────────

// fd_major walks the current task's file table to find the major device number
// of the file descriptor fd.  Returns 0 on any error.
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

	// Safe indexed read through BTF-aware helper.
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

// ── Tracepoint ────────────────────────────────────────────────────────────────

SEC("tracepoint/syscalls/sys_enter_write")
int record_write(struct trace_event_raw_sys_enter *ctx)
{
	__u64 cgid = bpf_get_current_cgroup_id();

	// Fast path: skip processes not belonging to a tracked session.
	if (!bpf_map_lookup_elem(&tracked_cgroups, &cgid))
		return 0;

	int fd        = (int)ctx->args[0];
	const void *ubuf = (const void *)ctx->args[1];
	__u64 count   = (__u64)ctx->args[2];

	if (count == 0)
		return 0;

	__u32 major = fd_major(fd);
	__u8 stream;

	if (major >= PTY_SLAVE_MAJOR_MIN && major <= PTY_SLAVE_MAJOR_MAX) {
		// Process writing to PTY slave → terminal output.
		stream = STREAM_TTYOUT;
	} else if (major == PTY_MASTER_MAJOR) {
		// sshd/terminal writing to PTY master → user keystrokes.
		stream = STREAM_TTYIN;
	} else {
		return 0;
	}

	struct io_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->cgroup_id    = cgid;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->stream       = stream;
	e->pad[0]       = e->pad[1] = e->pad[2] = 0;

	__u32 len = count > MAX_DATA_SIZE ? MAX_DATA_SIZE : (__u32)count;
	e->data_len = len;

	if (bpf_probe_read_user(e->data, len, ubuf) < 0) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

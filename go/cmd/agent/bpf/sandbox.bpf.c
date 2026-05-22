// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
//
// sandbox.bpf.c — eBPF LSM hooks for sudo-logger process sandbox.
//
// Enforces write/delete/kill restrictions on processes running inside
// sudo-logger session cgroups, based on operator-configured deny lists.
//
// Hooks:
//   lsm/file_permission  — deny writes to protected inodes (files, sockets, devices, proc)
//   lsm/inode_unlink     — deny deletion of protected inodes
//   lsm/inode_rename     — deny rename of/onto protected inodes (prevents atomic replacement)
//   lsm/task_kill        — deny signals to protected process names
//
// Scoping: only processes whose cgroup ID is in sandboxed_cgroups are restricted.
// The agent registers/unregisters cgroup IDs as sessions start and end.
//
// Requires: CONFIG_BPF_LSM=y, kernel >= 5.7, lsm=bpf in boot parameters.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_SANDBOXED_CGROUPS  256
#define MAX_PROTECTED_INODES   512
#define MAX_PROTECTED_PROCS    64
#define MAX_RESOLVED_DEVS      1024
#define TASK_COMM_LEN          16

// Kernel MAY_* permission bits (from linux/fs.h).
#define MAY_WRITE  0x2
#define MAY_APPEND 0x8

#define EPERM 1

struct inode_key {
	__u64 ino;
	__u32 dev;
	__u32 pad;
};

// agent_pid: the PID of the sudo-logger-agent process.
// Populated by the agent at startup; used to trigger device ID resolution.
volatile const __u32 agent_pid = 0;

// sandboxed_cgroups: set of session cgroup IDs subject to restrictions.
// key = cgroup_id (u64), value = u8 marker.
// Populated by the agent on session start; removed on session end.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_SANDBOXED_CGROUPS);
	__type(key, __u64);
	__type(value, __u8);
} sandboxed_cgroups SEC(".maps");

// resolved_devs: mapping from inode to its actual i_sb->s_dev.
// Used by the agent to resolve real device IDs for Btrfs subvolumes.
// key = inode (u64), value = s_dev (u32).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_RESOLVED_DEVS);
	__type(key, __u64);
	__type(value, __u32);
} resolved_devs SEC(".maps");

// protected_inodes: deny-list of inodes (files, devices, sockets, proc entries).
// key = {inode number, block device id}, value = u8 marker.
// Resolved from configured path strings at agent startup.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PROTECTED_INODES);
	__type(key, struct inode_key);
	__type(value, __u8);
} protected_inodes SEC(".maps");

// protected_procs: deny-list of process names (comm, max 15 chars + NUL).
// key = char[TASK_COMM_LEN], value = u8 marker.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PROTECTED_PROCS);
	__type(key, char[TASK_COMM_LEN]);
	__type(value, __u8);
} protected_procs SEC(".maps");

static __always_inline int in_sandbox(void)
{
	__u64 cgid = bpf_get_current_cgroup_id();
	return bpf_map_lookup_elem(&sandboxed_cgroups, &cgid) != NULL;
}

static __always_inline int inode_protected(struct inode *inode)
{
	if (!inode)
		return 0;
	struct inode_key key = {};
	key.ino = BPF_CORE_READ(inode, i_ino);
	key.dev = (__u32)BPF_CORE_READ(inode, i_sb, s_dev);
	key.pad = 0;
	return bpf_map_lookup_elem(&protected_inodes, &key) != NULL;
}

// Deny write access to protected inodes.
// Covers regular files, device nodes (/dev/*), proc entries, and Unix sockets.
SEC("lsm/file_permission")
int BPF_PROG(sandbox_file_permission, struct file *file, int mask)
{
	if (!(mask & (MAY_WRITE | MAY_APPEND)))
		return 0;
	if (!in_sandbox())
		return 0;

	struct inode *inode = BPF_CORE_READ(file, f_inode);
	if (!inode)
		return 0;

	struct inode_key key = {};
	key.ino = BPF_CORE_READ(inode, i_ino);
	key.dev = (__u32)BPF_CORE_READ(inode, i_sb, s_dev);
	key.pad = 0;

	if (bpf_map_lookup_elem(&protected_inodes, &key)) {
		bpf_printk("sandbox: BLOCKED write ino=%llu dev=%u", key.ino, key.dev);
		return -EPERM;
	}

	// Only log allowed writes when actually in a sandbox to avoid trace_pipe spam
	bpf_printk("sandbox: ALLOWED write ino=%llu dev=%u", key.ino, key.dev);
	return 0;
}

// Resolve real device ID for the agent during stat() calls.
SEC("lsm/inode_getattr")
int BPF_PROG(sandbox_inode_getattr, const struct path *path)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (pid != agent_pid)
		return 0;

	struct inode *inode = BPF_CORE_READ(path, dentry, d_inode);
	if (!inode)
		return 0;

	__u64 ino = BPF_CORE_READ(inode, i_ino);
	__u32 dev = (__u32)BPF_CORE_READ(inode, i_sb, s_dev);

	bpf_printk("sandbox: RESOLVED agent_pid=%u ino=%llu dev=%u", pid, ino, dev);

	bpf_map_update_elem(&resolved_devs, &ino, &dev, BPF_ANY);
	return 0;
}

// Deny deletion of protected inodes.
SEC("lsm/inode_unlink")
int BPF_PROG(sandbox_inode_unlink, struct inode *dir, struct dentry *dentry)
{
	if (!in_sandbox())
		return 0;
	struct inode *inode = BPF_CORE_READ(dentry, d_inode);
	if (inode_protected(inode))
		return -EPERM;
	return 0;
}

// Deny rename of protected inodes, and rename onto protected inodes.
// Without this hook, a process could write a new file then rename it over a
// protected path — atomically replacing the protected content.
SEC("lsm/inode_rename")
int BPF_PROG(sandbox_inode_rename, struct inode *old_dir, struct dentry *old_dentry,
	     struct inode *new_dir, struct dentry *new_dentry, unsigned int flags)
{
	if (!in_sandbox())
		return 0;
	struct inode *old_inode = BPF_CORE_READ(old_dentry, d_inode);
	if (inode_protected(old_inode))
		return -EPERM;
	struct inode *new_inode = BPF_CORE_READ(new_dentry, d_inode);
	if (inode_protected(new_inode))
		return -EPERM;
	return 0;
}

// Deny signals to processes whose name is in the protected_procs deny-list.
SEC("lsm/task_kill")
int BPF_PROG(sandbox_task_kill, struct task_struct *p,
	     struct kernel_siginfo *info, int sig, const struct cred *cred)
{
	if (!in_sandbox())
		return 0;
	char comm[TASK_COMM_LEN] = {};
	// bpf_probe_read_kernel_str avoids a clang-21 bpfeb codegen crash that
	// occurs with __builtin_preserve_access_index on char array fields.
	// The comm offset is stable; vmlinux.h reflects the running kernel layout.
	bpf_probe_read_kernel_str(comm, sizeof(comm), p->comm);
	if (bpf_map_lookup_elem(&protected_procs, comm))
		return -EPERM;
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

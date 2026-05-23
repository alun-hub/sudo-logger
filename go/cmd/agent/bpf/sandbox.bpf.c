// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
//
// sandbox.bpf.c — eBPF LSM hooks for sudo-logger process sandbox.
//
// Enforces write/delete/kill restrictions on processes running inside
// sudo-logger session cgroups, based on operator-configured deny lists.
//
// Hooks:
//   lsm/file_permission      — deny writes to protected inodes (files, sockets, devices, proc)
//   lsm/inode_unlink         — deny deletion of protected inodes
//   lsm/inode_rename         — deny rename of/onto protected inodes (prevents atomic replacement)
//   lsm/task_kill            — deny signals to protected process names
//   tp_btf/sched_process_fork — propagate PID tracking from sudo to all descendants
//   tp_btf/sched_process_exit — clean up PID tracking when a process exits
//
// Scoping: two complementary mechanisms identify restricted processes:
//   1. sandboxed_cgroups — cgroup IDs registered by the agent at session start.
//   2. sandboxed_pids    — PID-based tracking propagated from the sudo root PID
//      via the sched_process_fork hook. This catches processes whose cgroup was
//      changed by pam_systemd after plugin_open() returned but before the command
//      was forked (the "PAM session scope migration" race).
//
// Requires: CONFIG_BPF_LSM=y, kernel >= 5.7, lsm=bpf in boot parameters.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_SANDBOXED_CGROUPS  256
#define MAX_SANDBOXED_PIDS     4096
#define MAX_PROTECTED_INODES   4096
#define MAX_PROTECTED_PROCS    64
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

// sandboxed_cgroups: set of session cgroup IDs subject to restrictions.
// key = cgroup_id (u64), value = u8 marker.
// Populated by the agent on session start; removed on session end.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_SANDBOXED_CGROUPS);
	__type(key, __u64);
	__type(value, __u8);
} sandboxed_cgroups SEC(".maps");

// sandboxed_pids: PID-based sandbox set, propagated from the sudo root PID to
// all descendants via sched_process_fork. Provides sandbox scoping that survives
// pam_systemd moving the sudo process to a new session scope cgroup after the
// plugin's open_session returned but before the command was forked.
// key = tgid (u32), value = u8 marker.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_SANDBOXED_PIDS);
	__type(key, __u32);
	__type(value, __u8);
} sandboxed_pids SEC(".maps");

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

// in_sandbox_cgroup: cgroup-only scoping, used for file/inode hooks.
// PAM scope migration moves short-lived commands out of the session cgroup
// before they can write, so this correctly exempts rpm/dnf etc.
static __always_inline int in_sandbox_cgroup(void)
{
	__u64 cgid = bpf_get_current_cgroup_id();
	return bpf_map_lookup_elem(&sandboxed_cgroups, &cgid) != NULL;
}

// in_sandbox_pid: checks both cgroups and sandboxed_pids, used for task_kill.
// Catches short-lived commands (e.g. sudo pkill auditd) that escape the
// session cgroup via the PAM scope migration race.
static __always_inline int in_sandbox_pid(void)
{
	if (in_sandbox_cgroup())
		return 1;
	__u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	return bpf_map_lookup_elem(&sandboxed_pids, &tgid) != NULL;
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
	if (!in_sandbox_cgroup())
		return 0;

	struct inode *inode = BPF_CORE_READ(file, f_inode);
	if (inode_protected(inode))
		return -EPERM;

	return 0;
}

// Deny deletion of protected inodes.
SEC("lsm/inode_unlink")
int BPF_PROG(sandbox_inode_unlink, struct inode *dir, struct dentry *dentry)
{
	if (!in_sandbox_cgroup())
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
	if (!in_sandbox_cgroup())
		return 0;
	struct inode *old_inode = BPF_CORE_READ(old_dentry, d_inode);
	if (inode_protected(old_inode))
		return -EPERM;
	struct inode *new_inode = BPF_CORE_READ(new_dentry, d_inode);
	if (inode_protected(new_inode))
		return -EPERM;

	// Also prevent renaming a new file INTO a protected directory.
	if (inode_protected(new_dir))
		return -EPERM;

	return 0;
}

// Deny creation of new files/directories inside protected directories.
SEC("lsm/inode_mkdir")
int BPF_PROG(sandbox_inode_mkdir, struct inode *dir, struct dentry *dentry, umode_t mode)
{
	if (!in_sandbox_cgroup())
		return 0;
	if (inode_protected(dir))
		return -EPERM;
	return 0;
}

SEC("lsm/inode_create")
int BPF_PROG(sandbox_inode_create, struct inode *dir, struct dentry *dentry, umode_t mode)
{
	if (!in_sandbox_cgroup())
		return 0;
	if (inode_protected(dir))
		return -EPERM;
	return 0;
}

SEC("lsm/inode_mknod")
int BPF_PROG(sandbox_inode_mknod, struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
	if (!in_sandbox_cgroup())
		return 0;
	if (inode_protected(dir))
		return -EPERM;
	return 0;
}

SEC("lsm/inode_symlink")
int BPF_PROG(sandbox_inode_symlink, struct inode *dir, struct dentry *dentry, const char *old_name)
{
	if (!in_sandbox_cgroup())
		return 0;
	if (inode_protected(dir))
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

// Propagate sandbox membership from parent to child at fork time.
// Fires in the parent's context before the child runs any userspace code,
// making it race-free against the PAM session scope cgroup migration.
SEC("tp_btf/sched_process_fork")
int BPF_PROG(sandbox_process_fork, struct task_struct *parent, struct task_struct *child)
{
	__u32 parent_tgid = BPF_CORE_READ(parent, tgid);
	if (!bpf_map_lookup_elem(&sandboxed_pids, &parent_tgid))
		return 0;
	__u32 child_tgid = BPF_CORE_READ(child, tgid);
	__u8 marker = 1;
	bpf_map_update_elem(&sandboxed_pids, &child_tgid, &marker, BPF_ANY);
	return 0;
}

// Remove a PID from sandbox tracking when the thread-group leader exits.
SEC("tp_btf/sched_process_exit")
int BPF_PROG(sandbox_process_exit, struct task_struct *p)
{
	__u32 tgid = BPF_CORE_READ(p, tgid);
	__u32 pid = BPF_CORE_READ(p, pid);
	// Only delete when the thread-group leader exits (pid == tgid).
	if (pid == tgid)
		bpf_map_delete_elem(&sandboxed_pids, &tgid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

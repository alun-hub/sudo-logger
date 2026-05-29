// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
//
// sandbox.bpf.c — eBPF LSM hooks for sudo-logger process sandbox.
//
// Enforces write/delete/kill restrictions on processes running inside
// sudo-logger session cgroups, based on operator-configured deny lists.
//
// Hooks:
//   lsm/file_open            — deny opening protected inodes for writing (O_WRONLY/O_RDWR)
//   lsm/file_permission      — deny write/append access to protected inodes
//   lsm/path_truncate        — deny truncation of protected paths (truncate() + open O_TRUNC)
//   lsm/inode_setattr        — deny attribute changes (chmod, chown, truncate) on protected inodes
//   lsm/inode_unlink         — deny deletion of protected inodes
//   lsm/inode_rename         — deny rename of/onto protected inodes (prevents atomic replacement)
//   lsm/inode_mkdir          — deny creating directories inside protected directories
//   lsm/inode_create         — deny creating files inside protected directories
//   lsm/inode_mknod          — deny creating device nodes inside protected directories
//   lsm/inode_symlink        — deny creating symlinks inside protected directories
//   lsm/task_kill            — deny signals to protected process names
//   lsm/socket_create        — deny AF_NETLINK sockets for route/firewall/audit tampering
//   lsm/ptrace_access_check  — deny ptrace of processes outside the sandbox
//   lsm/sb_mount             — deny mounting over protected inodes (bind-mount bypass)
//   lsm/capable              — deny CAP_AUDIT_CONTROL, CAP_NET_ADMIN, CAP_SYS_MODULE
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

#define MAX_SANDBOXED_CGROUPS  512
#define MAX_SANDBOXED_PIDS     16384
#define MAX_PROTECTED_INODES   16384
#define MAX_PROTECTED_PROCS    256
#define TASK_COMM_LEN          16

// Kernel MAY_* permission bits (from linux/fs.h).
#define MAY_WRITE  0x2
#define MAY_APPEND 0x8

#define EPERM 1

// File type bits (from linux/stat.h) — not present in vmlinux.h.
#ifndef S_IFMT
#define S_IFMT  00170000
#define S_IFBLK 00060000
#define S_IFCHR 00020000
#endif

// Sandbox alert types for userspace reporting
enum sandbox_alert_type {
	ALERT_FILE_OPEN = 1,
	ALERT_FILE_WRITE = 2,
	ALERT_FILE_TRUNCATE = 3,
	ALERT_FILE_SETATTR = 4,
	ALERT_FILE_UNLINK = 5,
	ALERT_FILE_RENAME = 6,
	ALERT_DIR_MKDIR = 7,
	ALERT_DIR_CREATE = 8,
	ALERT_DIR_MKNOD = 9,
	ALERT_DIR_SYMLINK = 10,
	ALERT_PROCESS_KILL = 11,
	ALERT_BPF_SYSCALL = 12,
	ALERT_SOCKET_CREATE = 13,
	ALERT_PTRACE = 14,
	ALERT_MOUNT = 15,
	ALERT_CAPABLE = 16,
};

struct sandbox_alert {
	__u64 cgroup_id;
	__u32 pid;
	__u32 type;
	char  comm[TASK_COMM_LEN];
	__u64 ino;            // inode of the blocked object (file/dir hooks)
	__u32 dev;            // superblock dev (matches i_sb->s_dev read by BPF)
	__u32 target_pid;     // PROCESS_KILL: PID (tgid) of the target process
	char  target_comm[TASK_COMM_LEN]; // PROCESS_KILL: comm of target
	__u32 sig;            // PROCESS_KILL: signal number
	__u32 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024); // 256 KB ring buffer
} sandbox_alerts SEC(".maps");

static __always_inline void submit_alert(enum sandbox_alert_type type,
					 __u64 ino, __u32 dev)
{
	struct sandbox_alert *a;

	a = bpf_ringbuf_reserve(&sandbox_alerts, sizeof(*a), 0);
	if (!a)
		return;

	a->cgroup_id = bpf_get_current_cgroup_id();
	a->pid = bpf_get_current_pid_tgid() >> 32;
	a->type = type;
	bpf_get_current_comm(&a->comm, sizeof(a->comm));
	a->ino = ino;
	a->dev = dev;
	a->target_pid = 0;
	__builtin_memset(a->target_comm, 0, sizeof(a->target_comm));
	a->sig = 0;
	a->pad = 0;

	bpf_ringbuf_submit(a, 0);
}

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

// sandbox_config: feature-flag array written by the agent from sandbox.yaml.
// key = index (u32), value = u32 (0=disabled, 1=enabled).
// Default when not populated by Go: 0 (disabled) — Go always writes all entries.
#define CFG_DENY_NETLINK           0
#define CFG_DENY_MOUNT             1
#define CFG_DENY_PTRACE            2
#define CFG_DENY_CAP_AUDIT_CONTROL 3
#define CFG_DENY_CAP_NET_ADMIN     4
#define CFG_DENY_CAP_SYS_MODULE    5
#define CFG_COUNT                  6

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, CFG_COUNT);
	__type(key, __u32);
	__type(value, __u32);
} sandbox_config SEC(".maps");

#define PID_MARKER_SANDBOXED 1
#define PID_MARKER_EXEMPT     2

// in_sandbox_cgroup: cgroup-only scoping, used for file/inode hooks.
// PAM scope migration moves short-lived commands out of the session cgroup
// before they can write, so this correctly exempts rpm/dnf etc.
static __always_inline int in_sandbox_cgroup(void)
{
	__u64 cgid = bpf_get_current_cgroup_id();
	return bpf_map_lookup_elem(&sandboxed_cgroups, &cgid) != NULL;
}

// in_sandbox_pid: checks both cgroups and sandboxed_pids.
// Returns the PID marker (1=sandboxed, 2=exempt leader) if in a sandbox, else 0.
static __always_inline int in_sandbox_pid(void)
{
	if (in_sandbox_cgroup())
		return PID_MARKER_SANDBOXED;
	__u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	__u8 *marker = bpf_map_lookup_elem(&sandboxed_pids, &tgid);
	if (marker)
		return *marker;
	return 0;
}

// is_exempt_leader: returns true if the current process is the registered
// session leader (the sudo process itself). Secure replacement for comm name
// checks.
static __always_inline bool is_exempt_leader()
{
	return in_sandbox_pid() == PID_MARKER_EXEMPT;
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

// cfg_enabled returns non-zero if feature flag at index idx is set to 1.
static __always_inline int cfg_enabled(__u32 idx)
{
	__u32 *val = bpf_map_lookup_elem(&sandbox_config, &idx);
	return val != NULL && *val != 0;
}

// Kernel FMODE_* bits (from linux/fs.h).
#define FMODE_WRITE  0x2

// Deny opening protected inodes for writing.
SEC("lsm/file_open")
int BPF_PROG(sandbox_file_open, struct file *file)
{
	if (!in_sandbox_pid())
		return 0;

	// Check if file is opened for writing.
	if (!(BPF_CORE_READ(file, f_mode) & FMODE_WRITE))
		return 0;

	struct inode *inode = BPF_CORE_READ(file, f_inode);
	if (inode_protected(inode)) {
		submit_alert(ALERT_FILE_OPEN,
			     BPF_CORE_READ(inode, i_ino),
			     (__u32)BPF_CORE_READ(inode, i_sb, s_dev));
		return -EPERM;
	}

	return 0;
}

// Deny truncation of protected paths.
// Specifically targets open(..., O_TRUNC) and truncate() syscalls.
SEC("lsm/path_truncate")
int BPF_PROG(sandbox_path_truncate, const struct path *path)
{
	if (!in_sandbox_pid())
		return 0;

	struct inode *inode = BPF_CORE_READ(path, dentry, d_inode);
	if (inode_protected(inode)) {
		submit_alert(ALERT_FILE_TRUNCATE,
			     BPF_CORE_READ(inode, i_ino),
			     (__u32)BPF_CORE_READ(inode, i_sb, s_dev));
		return -EPERM;
	}

	return 0;
}

// Deny write access to protected inodes.
// Covers regular files, device nodes (/dev/*), proc entries, and Unix sockets.
SEC("lsm/file_permission")
int BPF_PROG(sandbox_file_permission, struct file *file, int mask)
{
	if (!(mask & (MAY_WRITE | MAY_APPEND)))
		return 0;
	if (!in_sandbox_pid())
		return 0;

	struct inode *inode = BPF_CORE_READ(file, f_inode);
	if (inode_protected(inode)) {
		submit_alert(ALERT_FILE_WRITE,
			     BPF_CORE_READ(inode, i_ino),
			     (__u32)BPF_CORE_READ(inode, i_sb, s_dev));
		return -EPERM;
	}

	return 0;
}

// Deny truncation and other attribute changes to protected inodes.
// This prevents 'echo > /etc/passwd' from zeroing out the file.
SEC("lsm/inode_setattr")
int BPF_PROG(sandbox_inode_setattr, struct dentry *dentry, struct iattr *attr)
{
	if (!in_sandbox_pid())
		return 0;

	struct inode *inode = BPF_CORE_READ(dentry, d_inode);
	if (inode_protected(inode)) {
		submit_alert(ALERT_FILE_SETATTR,
			     BPF_CORE_READ(inode, i_ino),
			     (__u32)BPF_CORE_READ(inode, i_sb, s_dev));
		return -EPERM;
	}

	return 0;
}

// Deny deletion of protected inodes.
SEC("lsm/inode_unlink")
int BPF_PROG(sandbox_inode_unlink, struct inode *dir, struct dentry *dentry)
{
	if (!in_sandbox_pid())
		return 0;
	struct inode *inode = BPF_CORE_READ(dentry, d_inode);
	if (inode_protected(inode)) {
		submit_alert(ALERT_FILE_UNLINK,
			     BPF_CORE_READ(inode, i_ino),
			     (__u32)BPF_CORE_READ(inode, i_sb, s_dev));
		return -EPERM;
	}
	return 0;
}

// Deny rename of protected inodes, and rename onto protected inodes.
// Without this hook, a process could write a new file then rename it over a
// protected path — atomically replacing the protected content.
SEC("lsm/inode_rename")
int BPF_PROG(sandbox_inode_rename, struct inode *old_dir, struct dentry *old_dentry,
	     struct inode *new_dir, struct dentry *new_dentry, unsigned int flags)
{
	if (!in_sandbox_pid())
		return 0;
	struct inode *old_inode = BPF_CORE_READ(old_dentry, d_inode);
	if (inode_protected(old_inode)) {
		submit_alert(ALERT_FILE_RENAME,
			     BPF_CORE_READ(old_inode, i_ino),
			     (__u32)BPF_CORE_READ(old_inode, i_sb, s_dev));
		return -EPERM;
	}
	struct inode *new_inode = BPF_CORE_READ(new_dentry, d_inode);
	if (inode_protected(new_inode)) {
		submit_alert(ALERT_FILE_RENAME,
			     BPF_CORE_READ(new_inode, i_ino),
			     (__u32)BPF_CORE_READ(new_inode, i_sb, s_dev));
		return -EPERM;
	}

	// Also prevent renaming a new file INTO a protected directory.
	if (inode_protected(new_dir)) {
		submit_alert(ALERT_FILE_RENAME,
			     BPF_CORE_READ(new_dir, i_ino),
			     (__u32)BPF_CORE_READ(new_dir, i_sb, s_dev));
		return -EPERM;
	}

	return 0;
}

// Deny creation of new files/directories inside protected directories.
SEC("lsm/inode_mkdir")
int BPF_PROG(sandbox_inode_mkdir, struct inode *dir, struct dentry *dentry, umode_t mode)
{
	if (!in_sandbox_pid())
		return 0;
	if (inode_protected(dir)) {
		submit_alert(ALERT_DIR_MKDIR,
			     BPF_CORE_READ(dir, i_ino),
			     (__u32)BPF_CORE_READ(dir, i_sb, s_dev));
		return -EPERM;
	}
	return 0;
}

SEC("lsm/inode_create")
int BPF_PROG(sandbox_inode_create, struct inode *dir, struct dentry *dentry, umode_t mode)
{
	if (!in_sandbox_pid())
		return 0;
	if (inode_protected(dir)) {
		submit_alert(ALERT_DIR_CREATE,
			     BPF_CORE_READ(dir, i_ino),
			     (__u32)BPF_CORE_READ(dir, i_sb, s_dev));
		return -EPERM;
	}
	return 0;
}

SEC("lsm/inode_mknod")
int BPF_PROG(sandbox_inode_mknod, struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
	if (!in_sandbox_pid())
		return 0;

	// Block creation of block/char device nodes anywhere inside the sandbox.
	// A fresh node with the same major:minor as a protected device
	// (e.g. mknod /tmp/x b 8 0, or c 1 1 for /dev/mem) is a NEW inode that is
	// not in protected_inodes, so writing through it would bypass the
	// inode-based device protection and reach the raw disk/memory directly.
	// Creating device nodes is essentially never legitimate inside an
	// interactive session; FIFOs and unix sockets (also via mknod) are allowed.
	if ((mode & S_IFMT) == S_IFBLK || (mode & S_IFMT) == S_IFCHR) {
		submit_alert(ALERT_DIR_MKNOD, 0, 0);
		return -EPERM;
	}

	if (inode_protected(dir)) {
		submit_alert(ALERT_DIR_MKNOD,
			     BPF_CORE_READ(dir, i_ino),
			     (__u32)BPF_CORE_READ(dir, i_sb, s_dev));
		return -EPERM;
	}
	return 0;
}

SEC("lsm/inode_symlink")
int BPF_PROG(sandbox_inode_symlink, struct inode *dir, struct dentry *dentry, const char *old_name)
{
	if (!in_sandbox_pid())
		return 0;
	if (inode_protected(dir)) {
		submit_alert(ALERT_DIR_SYMLINK,
			     BPF_CORE_READ(dir, i_ino),
			     (__u32)BPF_CORE_READ(dir, i_sb, s_dev));
		return -EPERM;
	}
	return 0;
}

// Deny signals to processes whose name is in the protected_procs deny-list.
SEC("lsm/task_kill")
int BPF_PROG(sandbox_task_kill, struct task_struct *p,
	     struct kernel_siginfo *info, int sig, const struct cred *cred)
{
	if (!in_sandbox_pid())
		return 0;
	char comm[TASK_COMM_LEN] = {};
	// bpf_probe_read_kernel_str avoids a clang-21 bpfeb codegen crash that
	// occurs with __builtin_preserve_access_index on char array fields.
	// The comm offset is stable; vmlinux.h reflects the running kernel layout.
	bpf_probe_read_kernel_str(comm, sizeof(comm), p->comm);
	if (bpf_map_lookup_elem(&protected_procs, comm)) {
		struct sandbox_alert *a;
		a = bpf_ringbuf_reserve(&sandbox_alerts, sizeof(*a), 0);
		if (!a)
			return -EPERM;
		a->cgroup_id = bpf_get_current_cgroup_id();
		a->pid = bpf_get_current_pid_tgid() >> 32;
		a->type = ALERT_PROCESS_KILL;
		bpf_get_current_comm(&a->comm, sizeof(a->comm));
		a->ino = 0;
		a->dev = 0;
		a->target_pid = (__u32)BPF_CORE_READ(p, tgid);
		bpf_probe_read_kernel_str(a->target_comm, sizeof(a->target_comm), p->comm);
		a->sig = (__u32)sig;
		a->pad = 0;
		bpf_ringbuf_submit(a, 0);
		return -EPERM;
	}
	return 0;
}

// Deny bpf() syscall to prevent manipulation of eBPF maps and programs.
SEC("lsm/bpf")
int BPF_PROG(sandbox_bpf, int cmd, union bpf_attr *attr, unsigned int size)
{
	if (!in_sandbox_pid())
		return 0;

	// We block ALL bpf() syscalls for sandboxed processes.
	submit_alert(ALERT_BPF_SYSCALL, 0, 0);
	return -EPERM;
}

#ifndef AF_NETLINK
#define AF_NETLINK 16
#endif
#ifndef NETLINK_ROUTE
#define NETLINK_ROUTE 0
#endif
#ifndef NETLINK_FIREWALL
#define NETLINK_FIREWALL 3
#endif
#ifndef NETLINK_NETFILTER
#define NETLINK_NETFILTER 12
#endif
#ifndef NETLINK_AUDIT
#define NETLINK_AUDIT 9
#endif

// Deny creation of AF_NETLINK sockets used for firewall tampering.
SEC("lsm/socket_create")
int BPF_PROG(sandbox_socket_create, int family, int type, int protocol, int kern)
{
	if (!in_sandbox_pid())
		return 0;

	// Exempt the sudo process itself from these restrictions.
	if (is_exempt_leader())
		return 0;

	// Gated by the deny_netlink feature flag (sandbox.yaml).
	if (!cfg_enabled(CFG_DENY_NETLINK))
		return 0;

	if (family == AF_NETLINK) {
		// We allow NETLINK_ROUTE because glibc/nss modules use it for basic
		// lookups (getifaddrs, getaddrinfo).
		//
		// We also allow NETLINK_AUDIT (9) at the socket level because many
		// shell integrations and libraries (libaudit) open it for reading
		// or status checks. Actual rule changes are blocked via CAP_AUDIT_CONTROL.
		//
		// We focus on blocking protocols used exclusively for firewall tampering:
		// NETLINK_FIREWALL (3) / NETLINK_NETFILTER (12): iptables, nftables, firewalld
		if (protocol == NETLINK_FIREWALL  ||
		    protocol == NETLINK_NETFILTER) {
			submit_alert(ALERT_SOCKET_CREATE, family, protocol);
			return -EPERM;
		}
	}
	return 0;
}

// Deny ptracing processes outside the sandbox to prevent injecting code into
// root-owned daemons (e.g. systemd or sshd) as an escape vector.
SEC("lsm/ptrace_access_check")
int BPF_PROG(sandbox_ptrace_access_check, struct task_struct *child, unsigned int mode)
{
	if (!in_sandbox_pid())
		return 0;

	// Only block and alert on ATTACH attempts (mode & 2).
	// We allow READ attempts (mode & 1) because tools like 'pkill', 'ps' and 'top'
	// need to read process metadata from /proc to function. Blocking read
	// access causes massive log spam and breaks basic system observability.
	if (!(mode & 2))
		return 0;

	// Exempt sudo itself.
	if (is_exempt_leader())
		return 0;

	// Gated by the deny_ptrace feature flag (sandbox.yaml).
	if (!cfg_enabled(CFG_DENY_PTRACE))
		return 0;

	__u32 target_tgid = BPF_CORE_READ(child, tgid);

	// If the target is NOT also in the sandbox, block it!
	if (!bpf_map_lookup_elem(&sandboxed_pids, &target_tgid)) {
		struct sandbox_alert *a;
		a = bpf_ringbuf_reserve(&sandbox_alerts, sizeof(*a), 0);
		if (!a)
			return -EPERM;
		a->cgroup_id = bpf_get_current_cgroup_id();
		a->pid = bpf_get_current_pid_tgid() >> 32;
		a->type = ALERT_PTRACE;
		bpf_get_current_comm(&a->comm, sizeof(a->comm));
		a->ino = 0;
		a->dev = 0;
		a->target_pid = target_tgid;
		bpf_probe_read_kernel_str(a->target_comm, sizeof(a->target_comm), child->comm);
		a->sig = 0;
		a->pad = 0;
		bpf_ringbuf_submit(a, 0);
		return -EPERM;
	}
	return 0;
}

// Deny mounting over protected inodes. Prevents shadowing a protected file or
// directory (e.g. bind-mounting /tmp/evil over /etc/sudoers) which would give
// the session a different inode not in the protected_inodes map.
// Mounts onto unprotected paths (e.g. sudo mount /dev/sdb1 /mnt) are allowed.
SEC("lsm/sb_mount")
int BPF_PROG(sandbox_sb_mount, const char *dev_name, const struct path *path, const char *type, unsigned long flags, void *data)
{
	if (!in_sandbox_pid())
		return 0;

	// Exempt sudo itself (some PAM modules might check mounts or even do them).
	if (is_exempt_leader())
		return 0;

	// Gated by the deny_mount feature flag (sandbox.yaml).
	if (!cfg_enabled(CFG_DENY_MOUNT))
		return 0;

	struct inode *inode = BPF_CORE_READ(path, dentry, d_inode);
	if (!inode_protected(inode))
		return 0;

	submit_alert(ALERT_MOUNT,
		BPF_CORE_READ(inode, i_ino),
		(__u32)BPF_CORE_READ(inode, i_sb, s_dev));
	return -EPERM;
}

#ifndef CAP_NET_ADMIN
#define CAP_NET_ADMIN     12
#endif
#ifndef CAP_SYS_MODULE
#define CAP_SYS_MODULE    16
#endif
#ifndef CAP_AUDIT_CONTROL
#define CAP_AUDIT_CONTROL 30
#endif

// Deny specific Linux capabilities within a sandbox session.
// Covers escalation paths not blocked by file/socket hooks:
//   CAP_AUDIT_CONTROL: auditctl rule manipulation (complementary to NETLINK_AUDIT block)
//   CAP_NET_ADMIN:     raw socket and netdevice operations outside netlink
//   CAP_SYS_MODULE:    insmod/modprobe kernel module loading
SEC("lsm/capable")
int BPF_PROG(sandbox_capable, const struct cred *cred,
	     struct user_namespace *ns, int cap, unsigned int opts)
{
	if (!in_sandbox_pid())
		return 0;

	// Exempt sudo itself.
	if (is_exempt_leader())
		return 0;

	// Block these critical capabilities for root sessions in the sandbox,
	// each gated by its own deny_cap_* feature flag (sandbox.yaml).
	if ((cap == CAP_AUDIT_CONTROL && cfg_enabled(CFG_DENY_CAP_AUDIT_CONTROL)) ||
	    (cap == CAP_NET_ADMIN     && cfg_enabled(CFG_DENY_CAP_NET_ADMIN))     ||
	    (cap == CAP_SYS_MODULE    && cfg_enabled(CFG_DENY_CAP_SYS_MODULE))) {
		submit_alert(ALERT_CAPABLE, 0, cap);
		return -EPERM;
	}
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

	// All descendants of a sandboxed PID are subject to full restrictions,
	// even if the parent was the exempt leader (the sudo process itself).
	__u32 child_tgid = BPF_CORE_READ(child, tgid);
	__u8 marker = PID_MARKER_SANDBOXED;
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

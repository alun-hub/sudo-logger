package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"gopkg.in/yaml.v3"
)

type sandboxYAML struct {
	Enabled  *bool `yaml:"enabled"` // nil → true; explicit false disables enforcement
	Features struct {
		DenyNetlink         *bool `yaml:"deny_netlink"`
		DenyMount           *bool `yaml:"deny_mount"`
		DenyPtrace          *bool `yaml:"deny_ptrace"`
		DenyCapAuditControl *bool `yaml:"deny_cap_audit_control"`
		DenyCapNetAdmin     *bool `yaml:"deny_cap_net_admin"`
		DenyCapSysModule    *bool `yaml:"deny_cap_sys_module"`
		DenyCapMacAdmin     *bool `yaml:"deny_cap_mac_admin"`
		DenyCapSysRawio     *bool `yaml:"deny_cap_sys_rawio"`
		DenyCapSysBoot      *bool `yaml:"deny_cap_sys_boot"`
		DenySystemdIPC      *bool `yaml:"deny_systemd_ipc"`
	} `yaml:"features"`
	Protect struct {
		Files     []string `yaml:"files"`
		Forbidden []string `yaml:"forbidden"`
		Noexec    []string `yaml:"noexec"`
		Devices   []string `yaml:"devices"`
		Proc      []string `yaml:"proc"`
		Sockets   []string `yaml:"sockets"`
		Processes []string `yaml:"processes"`
	} `yaml:"protect"`
	TrustedPackageManagers struct {
		Enabled       *bool    `yaml:"enabled"` // nil → false; off unless explicitly enabled
		Binaries      []string `yaml:"binaries"`
		AllowCreateIn []string `yaml:"allow_create_in"`
	} `yaml:"trusted_package_managers"`
}

// resolvedFeatures holds feature flags with defaults applied.
// All flags default to true (deny) when absent from sandbox.yaml.
type resolvedFeatures struct {
	DenyNetlink         bool
	DenyMount           bool
	DenyPtrace          bool
	DenyCapAuditControl bool
	DenyCapNetAdmin     bool
	DenyCapSysModule    bool
	DenyCapMacAdmin     bool
	DenyCapSysRawio     bool
	DenyCapSysBoot      bool
	DenySystemdIPC      bool
	// TrustedPkgMgrEnabled gates the trusted_package_managers exemption as a
	// whole. Unlike the deny_* flags above (default true/deny), this one
	// defaults to false — granting an exemption is opt-in, denying is not.
	TrustedPkgMgrEnabled bool
}

// featureDefault returns v's value, or true if v is nil (absent from YAML).
func featureDefault(v *bool) bool {
	if v == nil {
		return true
	}
	return *v
}

// featureDefaultFalse returns v's value, or false if v is nil. Used for
// protections that are off by default because they break common workflows
// (e.g. deny_systemd_ipc also blocks systemctl/loginctl inside a session).
func featureDefaultFalse(v *bool) bool {
	if v == nil {
		return false
	}
	return *v
}

// WatchTarget identifies which BPF map a watched path's inode belongs to, so
// sandbox_watch.go's inotify-triggered refresh writes the refreshed key to
// the right map instead of always assuming protected_inodes.
type WatchTarget int

const (
	WatchProtectedInodes WatchTarget = iota
	WatchTrustedBinaries
	WatchAllowCreateIn
)

// WatchedPath pairs a resolved inode key with the set of BPF maps it belongs
// to. A single path can legitimately belong to more than one — in fact the
// primary use case requires it: allow_create_in only has any effect on a
// directory that is ALSO in protect.files (inode_protected(dir) must be true
// before the trusted-package-manager exemption check even runs — see
// sandbox.bpf.c), so /usr/lib/systemd/system typically needs to be resolved
// into both WatchProtectedInodes and WatchAllowCreateIn simultaneously. All
// of a path's targets must be kept in sync together on an inode change (see
// addWatchedPath and sandbox_watch.go's refreshInode) — updating only one
// would leave the other silently stale.
type WatchedPath struct {
	Key     SandboxInodeKey
	Targets []WatchTarget
}

// addWatchedPath registers path under target, merging with any existing
// entry for the same path instead of overwriting it — see WatchedPath's doc
// comment for why a path can need more than one target.
func addWatchedPath(pathInodes map[string]WatchedPath, path string, key SandboxInodeKey, target WatchTarget) {
	wp, ok := pathInodes[path]
	if !ok {
		pathInodes[path] = WatchedPath{Key: key, Targets: []WatchTarget{target}}
		return
	}
	wp.Key = key // same file; keep the freshest resolution in sync
	for _, t := range wp.Targets {
		if t == target {
			pathInodes[path] = wp
			return
		}
	}
	wp.Targets = append(wp.Targets, target)
	pathInodes[path] = wp
}

type resolvedSandbox struct {
	Features      resolvedFeatures
	Inodes        []SandboxInodeKey
	Forbidden     []SandboxInodeKey     // forbidden_binaries (bprm_check_security)
	Noexec        []SandboxInodeKey     // noexec_inodes (bprm_check_security parent dir check)
	IPCInodes     []SandboxInodeKey     // systemd/D-Bus control-socket inodes (deny_systemd_ipc)
	TrustedBinaries []SandboxInodeKey   // trusted_binaries (bprm_check_security exec-time grant)
	AllowCreateIn []SandboxInodeKey     // allow_create_in (mkdir/create/mknod/symlink exemption)
	PathInodes    map[string]WatchedPath // protected path → its current inode key + target map
	Processes     []string
}

// systemdIPCPaths are the control sockets whose connect() is denied inside the
// sandbox when deny_systemd_ipc is enabled. These are the channels through which
// a session can ask PID 1 to spawn a process outside the sandbox (systemd-run,
// busctl StartTransientUnit, machinectl).
var systemdIPCPaths = []string{
	"/run/systemd/private",
	"/run/dbus/system_bus_socket",
}

// resolveInodeKey resolves an absolute path to its BPF inode key {ino, dev},
// using mountinfo for s_dev to match what the BPF program reads.
func resolveInodeKey(p string) (SandboxInodeKey, bool) {
	var st syscall.Stat_t
	if err := syscall.Stat(p, &st); err != nil {
		debugLog("sandbox: stat %s: %v (skipping)", p, err)
		return SandboxInodeKey{}, false
	}
	dev, err := mountDev(p)
	if err != nil {
		dev = uint32(st.Dev)
	}
	return SandboxInodeKey{Ino: st.Ino, Dev: dev}, true
}

// mountDev returns the kernel dev_t (MKDEV(major, minor)) for the filesystem
// containing path by parsing /proc/self/mountinfo. This matches i_sb->s_dev
// read by the BPF program, which on Btrfs differs from stat().st_dev (the
// subvolume anon_dev) — both are anonymous devices (major 0) but different
// minor numbers.
func mountDev(path string) (uint32, error) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return 0, fmt.Errorf("read mountinfo: %w", err)
	}
	bestLen := -1
	var bestDev uint32
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		mountPoint := fields[4]
		if mountPoint != "/" && path != mountPoint && !strings.HasPrefix(path, mountPoint+"/") {
			continue
		}
		if len(mountPoint) <= bestLen {
			continue
		}
		parts := strings.SplitN(fields[2], ":", 2)
		if len(parts) != 2 {
			continue
		}
		major, err1 := strconv.ParseUint(parts[0], 10, 32)
		minor, err2 := strconv.ParseUint(parts[1], 10, 32)
		if err1 != nil || err2 != nil {
			continue
		}
		bestLen = len(mountPoint)
		bestDev = (uint32(major) << 20) | uint32(minor)
	}
	if bestLen < 0 {
		return 0, fmt.Errorf("no mount entry found for %s", path)
	}
	return bestDev, nil
}

// resolveExactPaths resolves a list of absolute paths to deduped inode keys,
// with no recursion — used for exec targets (forbidden binaries, trusted
// package-manager binaries) rather than directory trees. Also returns a
// path→key map (mirroring resolveProtectedTree's shape) for callers that
// need inotify watcher registration; callers that don't (protect.forbidden
// today has no staleness watching — a pre-existing gap, not touched here)
// can simply discard it.
func resolveExactPaths(paths []string) (inodes []SandboxInodeKey, pathInodes map[string]SandboxInodeKey) {
	seen := make(map[SandboxInodeKey]bool)
	pathInodes = make(map[string]SandboxInodeKey)
	for _, p := range paths {
		if !filepath.IsAbs(p) {
			continue
		}
		var st syscall.Stat_t
		if err := syscall.Stat(p, &st); err != nil {
			continue
		}
		dev, _ := mountDev(p)
		if dev == 0 {
			dev = uint32(st.Dev)
		}
		key := SandboxInodeKey{Ino: st.Ino, Dev: dev}
		pathInodes[p] = key
		if !seen[key] {
			seen[key] = true
			inodes = append(inodes, key)
		}
	}
	return inodes, pathInodes
}

// resolveProtectedTree runs a depth-bounded BFS over roots: resolves each
// root path, recurses into existing subdirectories up to maxDepth (skipping
// recursion — but still protecting the top inode — for dangerousRoots),
// dedups by inode, and returns both a flat inode-key list and a path→key map
// for inotify watcher registration. Shared by protect.files/devices/proc/
// sockets and by trusted_package_managers.allow_create_in, which both need
// pre-existing nested directories (e.g. a systemd unit dir's *.wants/
// subdirectory) covered automatically, not just the literal configured path.
//
// Symlinks are resolved with Lstat and never traversed: the symlink's own
// inode is protected (that is what an unlink/rename of it hits) and the BFS
// does not follow it into another directory tree.
func resolveProtectedTree(roots []string, dangerousRoots map[string]bool) (inodes []SandboxInodeKey, pathInodes map[string]SandboxInodeKey) {
	type node struct {
		path  string
		depth int
	}
	queue := make([]node, 0, len(roots))
	for _, p := range roots {
		queue = append(queue, node{p, 0})
	}

	const maxNodes = 4096
	const maxDepth = 3

	pathInodes = make(map[string]SandboxInodeKey)
	seen := make(map[SandboxInodeKey]bool)

	for i := 0; i < len(queue); i++ {
		if len(pathInodes) >= maxNodes {
			log.Printf("sandbox: max nodes (%d) reached, skipping remaining paths", maxNodes)
			break
		}

		n := queue[i]
		p := n.path

		// Require absolute paths to prevent relative traversal.
		if !filepath.IsAbs(p) {
			log.Printf("sandbox: skipping non-absolute path %q", p)
			continue
		}

		// Lstat, not Stat: a path reached by the BFS may be a symlink, and
		// os.Stat / os.ReadDir would silently follow it. Following it both
		// pulled the target's whole subtree into protected_inodes — the dracut
		// *.wants/ links under /usr/lib/systemd/system dragging in
		// /usr/lib/dracut/modules.d/* (and, with a misconfigured parent root
		// like /usr/lib/systemd, whole sibling trees), blocking unrelated
		// package writes there — and recorded the target's inode instead of
		// the link's, so deleting the link itself was never actually blocked.
		fi, err := os.Lstat(p)
		if err != nil {
			debugLog("sandbox: lstat %s: %v (skipping)", p, err)
			continue
		}

		isSymlink := fi.Mode()&os.ModeSymlink != 0

		// Recurse into real directories only — never step through a symlink
		// into another tree. (An explicitly configured root that is itself a
		// symlink, e.g. /etc/resolv.conf, still gets its own inode protected
		// below so it cannot be swapped; it just is not traversed.)
		if fi.IsDir() && !isSymlink && n.depth < maxDepth && !dangerousRoots[filepath.Clean(p)] {
			entries, err := os.ReadDir(p)
			if err != nil {
				log.Printf("sandbox: readdir %s: %v", p, err)
			} else {
				for _, entry := range entries {
					queue = append(queue, node{filepath.Join(p, entry.Name()), n.depth + 1})
				}
			}
		} else if fi.IsDir() && !isSymlink && dangerousRoots[filepath.Clean(p)] {
			log.Printf("sandbox: skipping recursive scan of large root %q (protecting inode only)", p)
		}

		var st syscall.Stat_t
		if err := syscall.Lstat(p, &st); err != nil {
			continue
		}
		// Use mountinfo to get i_sb->s_dev (what BPF reads) rather than
		// stat().st_dev.
		dev, devErr := mountDev(p)
		if devErr != nil {
			log.Printf("sandbox: mountDev %s: %v (falling back to stat dev)", p, devErr)
			dev = uint32(st.Dev)
		}
		debugLog("sandbox: protecting %s {ino=%d dev=%d}", p, st.Ino, dev)
		key := SandboxInodeKey{Ino: st.Ino, Dev: dev}
		pathInodes[p] = key

		if !seen[key] {
			seen[key] = true
			inodes = append(inodes, key)
		}
	}
	return inodes, pathInodes
}

func loadSandboxConfig(path string) (*resolvedSandbox, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read sandbox config %s: %w", path, err)
	}
	return loadSandboxConfigFromBytes(data)
}

// loadSandboxConfigFromBytes parses and resolves a sandbox YAML payload.
// It is used both by loadSandboxConfig (file path) and reloadSandboxFromContent
// (content received from the log server).
func loadSandboxConfigFromBytes(data []byte) (*resolvedSandbox, error) {
	var cfg sandboxYAML
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse sandbox config: %w", err)
	}

	if cfg.Enabled != nil && !*cfg.Enabled {
		log.Printf("sandbox: config has enabled: false — enforcement disabled")
		return &resolvedSandbox{PathInodes: make(map[string]WatchedPath)}, nil
	}

	res := &resolvedSandbox{
		PathInodes: make(map[string]WatchedPath),
		Features: resolvedFeatures{
			DenyNetlink:          featureDefault(cfg.Features.DenyNetlink),
			DenyMount:            featureDefault(cfg.Features.DenyMount),
			DenyPtrace:           featureDefault(cfg.Features.DenyPtrace),
			DenyCapAuditControl:  featureDefault(cfg.Features.DenyCapAuditControl),
			DenyCapNetAdmin:      featureDefault(cfg.Features.DenyCapNetAdmin),
			DenyCapSysModule:     featureDefault(cfg.Features.DenyCapSysModule),
			DenyCapMacAdmin:      featureDefault(cfg.Features.DenyCapMacAdmin),
			DenyCapSysRawio:      featureDefault(cfg.Features.DenyCapSysRawio),
			DenyCapSysBoot:       featureDefault(cfg.Features.DenyCapSysBoot),
			DenySystemdIPC:       featureDefaultFalse(cfg.Features.DenySystemdIPC),
			TrustedPkgMgrEnabled: featureDefaultFalse(cfg.TrustedPackageManagers.Enabled),
		},
	}

	// Resolve systemd/D-Bus control-socket inodes (for deny_systemd_ipc).
	// Always resolved so the map is populated regardless of the flag's current
	// value; the BPF hook only consults it when deny_systemd_ipc is enabled.
	for _, p := range systemdIPCPaths {
		if key, ok := resolveInodeKey(p); ok {
			res.IPCInodes = append(res.IPCInodes, key)
			debugLog("sandbox: systemd-ipc socket %s {ino=%d dev=%d}", p, key.Ino, key.Dev)
		}
	}
	// Paths that are themselves large filesystem roots. Recursing into them
	// would stat millions of files. We still protect the top-level inode but
	// skip ReadDir. Subdirectories of these (e.g. /usr/lib/systemd/system) are
	// fine — they arrive as explicit entries with their own depth counter.
	dangerousRoots := map[string]bool{
		"/": true, "/usr": true, "/bin": true, "/sbin": true,
		"/lib": true, "/lib64": true, "/lib32": true,
		"/proc": true, "/sys": true, "/dev": true, "/run": true,
	}

	protectRoots := make([]string, 0,
		len(cfg.Protect.Files)+len(cfg.Protect.Devices)+
			len(cfg.Protect.Proc)+len(cfg.Protect.Sockets))
	protectRoots = append(protectRoots, cfg.Protect.Files...)
	protectRoots = append(protectRoots, cfg.Protect.Devices...)
	protectRoots = append(protectRoots, cfg.Protect.Proc...)
	protectRoots = append(protectRoots, cfg.Protect.Sockets...)

	var filePathInodes map[string]SandboxInodeKey
	res.Inodes, filePathInodes = resolveProtectedTree(protectRoots, dangerousRoots)
	for p, key := range filePathInodes {
		addWatchedPath(res.PathInodes, p, key, WatchProtectedInodes)
	}

	// trusted_package_managers.allow_create_in — same BFS as protect.files,
	// resolved regardless of `enabled`'s current value (matches the
	// deny_systemd_ipc/IPCInodes pattern below: cheap to keep resolved, the
	// BPF hooks are what actually gate on the enabled flag), so toggling the
	// feature via a config reload doesn't need a fresh directory walk.
	// Uses addWatchedPath, not a bare assignment: these paths are typically
	// ALSO in protect.files (required for the exemption to do anything —
	// see WatchedPath's doc comment), so a plain overwrite here would drop
	// the WatchProtectedInodes registration just added above.
	allowCreateInodes, allowCreatePathInodes := resolveProtectedTree(cfg.TrustedPackageManagers.AllowCreateIn, dangerousRoots)
	res.AllowCreateIn = allowCreateInodes
	for p, key := range allowCreatePathInodes {
		addWatchedPath(res.PathInodes, p, key, WatchAllowCreateIn)
	}

	// trusted_package_managers.binaries — exact exec targets, no recursion,
	// same treatment as protect.forbidden below. Also always resolved
	// regardless of `enabled`.
	var trustedBinPathInodes map[string]SandboxInodeKey
	res.TrustedBinaries, trustedBinPathInodes = resolveExactPaths(cfg.TrustedPackageManagers.Binaries)
	for p, key := range trustedBinPathInodes {
		addWatchedPath(res.PathInodes, p, key, WatchTrustedBinaries)
	}

	// Each remaining resolved list (forbidden binaries, noexec dirs) gets its
	// own dedup set. A single shared set would silently drop an inode from
	// every list after the first it appeared in, e.g. a path listed in both
	// `files` and `forbidden` would never make it into res.Forbidden.
	seenForbidden := make(map[SandboxInodeKey]bool)
	seenNoexec := make(map[SandboxInodeKey]bool)

	// Resolve forbidden binaries (exact paths, no recursion)
	for _, p := range cfg.Protect.Forbidden {
		if !filepath.IsAbs(p) {
			continue
		}
		var st syscall.Stat_t
		if err := syscall.Stat(p, &st); err != nil {
			continue
		}
		dev, _ := mountDev(p)
		if dev == 0 {
			dev = uint32(st.Dev)
		}
		key := SandboxInodeKey{Ino: st.Ino, Dev: dev}
		if !seenForbidden[key] {
			seenForbidden[key] = true
			res.Forbidden = append(res.Forbidden, key)
		}
	}

	// Resolve noexec directories (exact paths, BPF will traverse up to them).
	// Warn if the resolved inode is 256: on Btrfs every subvolume root gets
	// inode 256 on the same device, so adding /home would also match / and
	// block all execution system-wide. This is safe on ext4/xfs.
	for _, p := range cfg.Protect.Noexec {
		if !filepath.IsAbs(p) {
			continue
		}
		var st syscall.Stat_t
		if err := syscall.Stat(p, &st); err != nil {
			continue
		}
		dev, _ := mountDev(p)
		if dev == 0 {
			dev = uint32(st.Dev)
		}
		if st.Ino == 256 {
			log.Printf("sandbox: WARNING: noexec path %q has inode 256 — this is a Btrfs subvolume root. "+
				"On Btrfs all subvolume roots share inode 256 on the same device, so this entry will also "+
				"match the filesystem root and block ALL execution. Remove this entry unless you are on ext4/xfs.", p)
		}
		key := SandboxInodeKey{Ino: st.Ino, Dev: dev}
		if !seenNoexec[key] {
			seenNoexec[key] = true
			res.Noexec = append(res.Noexec, key)
		}
	}

	for _, name := range cfg.Protect.Processes {
		if len(name) > 15 {
			log.Printf("sandbox: process name %q exceeds 15 chars, truncating", name)
			name = name[:15]
		}
		res.Processes = append(res.Processes, name)
	}

	return res, nil
}

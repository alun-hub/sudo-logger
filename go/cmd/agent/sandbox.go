package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"sudo-logger/internal/protocol"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/fsnotify/fsnotify"
)

// Alert type constants — must match enum sandbox_alert_type in sandbox.bpf.c.
const (
	alertFileOpen     = 1
	alertFileWrite    = 2
	alertFileTruncate = 3
	alertFileSetattr  = 4
	alertFileUnlink   = 5
	alertFileRename   = 6
	alertDirMkdir     = 7
	alertDirCreate    = 8
	alertDirMknod     = 9
	alertDirSymlink   = 10
	alertProcessKill  = 11
	alertBpfSyscall   = 12
	alertSocketCreate = 13
	alertPtrace       = 14
	alertMount        = 15
	alertCapable      = 16
	alertSystemdIpc   = 17
	alertExecBlock    = 18

	// sandbox_config BPF array indices — must match CFG_* in sandbox.bpf.c.
	cfgDenyNetlink         = 0
	cfgDenyMount           = 1
	cfgDenyPtrace          = 2
	cfgDenyCapAuditControl = 3
	cfgDenyCapNetAdmin     = 4
	cfgDenyCapSysModule    = 5
	cfgDenySystemdIPC      = 6
	cfgDenyCapMacAdmin     = 7
	cfgDenyCapSysRawio     = 8
	cfgDenyCapSysBoot      = 9
)

var alertNames = map[uint32]string{
	alertFileOpen:     "FILE_OPEN",
	alertFileWrite:    "FILE_WRITE",
	alertFileTruncate: "FILE_TRUNCATE",
	alertFileSetattr:  "FILE_SETATTR",
	alertFileUnlink:   "FILE_UNLINK",
	alertFileRename:   "FILE_RENAME",
	alertDirMkdir:     "DIR_MKDIR",
	alertDirCreate:    "DIR_CREATE",
	alertDirMknod:     "DIR_MKNOD",
	alertDirSymlink:   "DIR_SYMLINK",
	alertProcessKill:  "PROCESS_KILL",
	alertBpfSyscall:   "BPF_SYSCALL",
	alertSocketCreate: "SOCKET_CREATE",
	alertPtrace:       "PTRACE",
	alertMount:        "MOUNT",
	alertCapable:      "CAPABLE",
	alertSystemdIpc:   "SYSTEMD_IPC",
	alertExecBlock:    "EXEC_BLOCK",
}

// bpfSandboxAlert must match struct sandbox_alert in sandbox.bpf.c
type bpfSandboxAlert struct {
	CgroupID   uint64
	Pid        uint32
	Type       uint32
	Comm       [16]byte
	Ino        uint64
	Dev        uint32
	TargetPid  uint32
	TargetComm [16]byte
	Sig        uint32
	_          uint32 // pad
}

// sigName returns a human-readable signal name for common signals.
func sigName(sig uint32) string {
	names := map[uint32]string{
		1: "SIGHUP", 2: "SIGINT", 3: "SIGQUIT", 4: "SIGILL",
		6: "SIGABRT", 8: "SIGFPE", 9: "SIGKILL", 11: "SIGSEGV",
		13: "SIGPIPE", 14: "SIGALRM", 15: "SIGTERM",
		17: "SIGCHLD", 18: "SIGCONT", 19: "SIGSTOP", 20: "SIGTSTP",
	}
	if name, ok := names[sig]; ok {
		return name
	}
	return fmt.Sprintf("SIG%d", sig)
}

func (s *sandboxSubsystem) pollAlerts() {
	rd, err := ringbuf.NewReader(s.objs.SandboxAlerts)
	if err != nil {
		log.Printf("sandbox: alert reader: %v", err)
		return
	}
	defer rd.Close()

	debugLog("sandbox: alert listener started")

	for {
		record, err := rd.Read()
		if err != nil {
			log.Printf("sandbox: alert read: %v", err)
			return
		}

		var bpfAlert bpfSandboxAlert
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.NativeEndian, &bpfAlert); err != nil {
			log.Printf("sandbox: decode alert: %v", err)
			continue
		}

		comm := string(bytes.TrimRight(bpfAlert.Comm[:], "\x00"))
		targetComm := string(bytes.TrimRight(bpfAlert.TargetComm[:], "\x00"))
		s.reportViolation(bpfAlert.CgroupID, bpfAlert.Pid, bpfAlert.Type, comm,
			bpfAlert.Ino, bpfAlert.Dev, bpfAlert.TargetPid, targetComm, bpfAlert.Sig)
	}
}

// pathForInode returns the protected path for an inode key, or "" if unknown.
// Only called once per reported violation (not a per-syscall hot path), so a
// linear scan is fine for realistic protected-path-set sizes; if that set
// grows large, maintain a reverse ino/dev→path map instead, kept in sync in
// reloadConfig.
func (s *sandboxSubsystem) pathForInode(ino uint64, dev uint32) string {
	if ino == 0 {
		return ""
	}
	key := SandboxInodeKey{Ino: ino, Dev: dev}
	s.mu.Lock()
	defer s.mu.Unlock()
	for path, k := range s.pathInodes {
		if k == key {
			return path
		}
	}
	return ""
}

func (s *sandboxSubsystem) reportViolation(cgid uint64, pid uint32, alertType uint32, comm string,
	ino uint64, dev uint32, targetPid uint32, targetComm string, sig uint32) {
	typeName := alertNames[alertType]
	if typeName == "" {
		typeName = "UNKNOWN"
	}

	path := s.pathForInode(ino, dev)

	alert := protocol.SandboxAlert{
		Pid:  pid,
		Comm: comm,
		Type: alertType,
		Ts:   time.Now().Unix(),
	}

	// Resolve session before logging so sess= is included in the message.
	activeCgsMu.Lock()
	var serverW *protocol.Writer
	for _, cg := range activeCgs {
		if cg.cgroupID == cgid {
			alert.SessionID = cg.cgName
			serverW = cg.serverW
			break
		}
	}
	nSessions := len(activeCgs)
	activeCgsMu.Unlock()

	sess := alert.SessionID
	if sess == "" {
		sess = "?"
	}

	switch {
	case alertType == alertProcessKill:
		log.Printf("SANDBOX VIOLATION action=%s comm=%q pid=%d target=%q target_pid=%d sig=%s sess=%q cgid=%d",
			typeName, comm, pid, targetComm, targetPid, sigName(sig), sess, cgid)
	case alertType == alertSocketCreate:
		log.Printf("SANDBOX VIOLATION action=%s comm=%q pid=%d family=%d protocol=%d sess=%q cgid=%d",
			typeName, comm, pid, ino, dev, sess, cgid)
	case alertType == alertCapable:
		log.Printf("SANDBOX VIOLATION action=%s comm=%q pid=%d cap=%d sess=%q cgid=%d",
			typeName, comm, pid, dev, sess, cgid)
	case alertType >= alertDirMkdir && alertType <= alertDirSymlink:
		if path != "" {
			log.Printf("SANDBOX VIOLATION action=%s comm=%q pid=%d dir=%q sess=%q cgid=%d",
				typeName, comm, pid, path, sess, cgid)
		} else {
			log.Printf("SANDBOX VIOLATION action=%s comm=%q pid=%d sess=%q cgid=%d",
				typeName, comm, pid, sess, cgid)
		}
	default:
		if path != "" {
			log.Printf("SANDBOX VIOLATION action=%s comm=%q pid=%d path=%q sess=%q cgid=%d",
				typeName, comm, pid, path, sess, cgid)
		} else {
			log.Printf("SANDBOX VIOLATION action=%s comm=%q pid=%d sess=%q cgid=%d",
				typeName, comm, pid, sess, cgid)
		}
	}

	if serverW == nil {
		// Primary lookup by session cgroup failed. The alerting process may have
		// escaped its session cgroup before being blocked (e.g. sudo forks a child
		// that moves itself via PAM/namespace before exec-ing the command). Retry
		// after 150 ms — enough for trackDescendants (50 ms poll) to detect the
		// escape and register the aux cgroup entry.
		go s.retryViolation(cgid, alert, nSessions)
		return
	}

	payload, _ := json.Marshal(alert)
	if err := serverW.WriteMessage(protocol.MsgSandboxAlert, payload); err != nil {
		log.Printf("sandbox: send alert to server: %v", err)
	}
}

func (s *sandboxSubsystem) retryViolation(cgid uint64, alert protocol.SandboxAlert, nSessions int) {
	time.Sleep(150 * time.Millisecond)

	var serverW *protocol.Writer
	activeCgsMu.Lock()
	for _, cg := range activeCgs {
		if cg.cgroupID == cgid {
			alert.SessionID = cg.cgName
			serverW = cg.serverW
			break
		}
	}
	activeCgsMu.Unlock()

	if serverW == nil {
		auxCgroupMu.Lock()
		if cg, ok := auxCgroupMap[cgid]; ok {
			alert.SessionID = cg.cgName
			serverW = cg.serverW
		}
		auxCgroupMu.Unlock()
	}

	if serverW == nil {
		log.Printf("sandbox: no session found for cgid=%d (active sessions: %d) — alert dropped", cgid, nSessions)
		return
	}

	payload, _ := json.Marshal(alert)
	if err := serverW.WriteMessage(protocol.MsgSandboxAlert, payload); err != nil {
		log.Printf("sandbox: send alert to server (retry): %v", err)
	}
}

const (
	pidMarkerSandboxed = 1
	pidMarkerExempt    = 2
)

// registerPID marks a PID (tgid) as sandboxed in the BPF map.
// The sched_process_fork hook propagates membership to all descendants.
func (s *sandboxSubsystem) registerPID(pid uint32) {
	if s == nil || s.objs == nil || pid == 0 {
		return
	}
	if pid == uint32(os.Getpid()) {
		debugLog("sandbox: skipping registration of agent self pid %d", pid)
		return
	}
	// The root PID (sudo itself) is marked as EXEMPT so it can complete
	// session setup (PAM modules, audit, etc). Descendants forked via
	// sched_process_fork are automatically marked as SANDBOXED (1).
	marker := uint8(pidMarkerExempt)
	if err := s.objs.SandboxedPids.Put(pid, marker); err != nil {
		log.Printf("sandbox: register pid %d: %v", pid, err)
	}
	debugLog("sandbox: pid %d registered (EXEMPT)", pid)
}

// registerChildPID marks a PID as sandboxed (not exempt). Used for secondary
// captures (e.g. aux pkexec) where we want immediate full enforcement.
func (s *sandboxSubsystem) registerChildPID(pid uint32) {
	if s == nil || s.objs == nil || pid == 0 {
		return
	}
	marker := uint8(pidMarkerSandboxed)
	if err := s.objs.SandboxedPids.Put(pid, marker); err != nil {
		log.Printf("sandbox: register child pid %d: %v", pid, err)
	}
	debugLog("sandbox: child pid %d registered (SANDBOXED)", pid)
}

// unregisterPID removes a PID from the sandbox restriction set.
func (s *sandboxSubsystem) unregisterPID(pid uint32) {
	if s == nil || s.objs == nil {
		return
	}
	if err := s.objs.SandboxedPids.Delete(pid); err != nil {
		debugLog("sandbox: unregister pid %d: %v", pid, err)
	}
}

// sandboxSubsystem enforces filesystem and process-kill restrictions on
// processes running inside sudo-logger session cgroups, via eBPF LSM hooks.
type sandboxSubsystem struct {
	objs          *SandboxObjects
	links         []link.Link
	mu            sync.Mutex
	pathInodes    map[string]SandboxInodeKey // protected path → inode key currently in BPF map
	watcher       *fsnotify.Watcher
	selfCgroupID  uint64                     // agent's own cgroup ID, excluded from sandbox
	lastFeatures  resolvedFeatures           // feature flags as of the last reload, for weakening detection
}

var sandboxSys *sandboxSubsystem

// auxCgroupMap maps cgroup IDs of escaped session processes to their sessions.
// Populated by cgroup.go when trackDescendants detects a PID that has escaped
// to a different cgroup, so that children of the escaped PID (which inherit
// that cgroup) can still be attributed to the correct session.
var (
	auxCgroupMu  sync.Mutex
	auxCgroupMap = map[uint64]*cgroupSession{}
)

func (s *sandboxSubsystem) registerAuxCgroup(cgid uint64, cg *cgroupSession) {
	if s == nil || cgid == 0 {
		return
	}
	auxCgroupMu.Lock()
	auxCgroupMap[cgid] = cg
	auxCgroupMu.Unlock()
	debugLog("sandbox: aux cgroup %d registered for session %s", cgid, cg.cgName)
}

func (s *sandboxSubsystem) unregisterAuxCgroups(cg *cgroupSession) {
	if s == nil {
		return
	}
	auxCgroupMu.Lock()
	for id, sess := range auxCgroupMap {
		if sess == cg {
			delete(auxCgroupMap, id)
		}
	}
	auxCgroupMu.Unlock()
}

// applyFeatures writes the resolved feature flags into the sandbox_config BPF
// array map. Called on start and on every config reload so that changes to
// sandbox.yaml take effect without an agent restart.
func applyFeatures(objs *SandboxObjects, f resolvedFeatures) {
	flag := func(idx uint32, enabled bool) {
		var val uint32
		if enabled {
			val = 1
		}
		if err := objs.SandboxConfig.Put(idx, val); err != nil {
			log.Printf("sandbox: write feature[%d]=%d: %v", idx, val, err)
		}
	}
	flag(cfgDenyNetlink, f.DenyNetlink)
	flag(cfgDenyMount, f.DenyMount)
	flag(cfgDenyPtrace, f.DenyPtrace)
	flag(cfgDenyCapAuditControl, f.DenyCapAuditControl)
	flag(cfgDenyCapNetAdmin, f.DenyCapNetAdmin)
	flag(cfgDenyCapSysModule, f.DenyCapSysModule)
	flag(cfgDenySystemdIPC, f.DenySystemdIPC)
	flag(cfgDenyCapMacAdmin, f.DenyCapMacAdmin)
	flag(cfgDenyCapSysRawio, f.DenyCapSysRawio)
	flag(cfgDenyCapSysBoot, f.DenyCapSysBoot)
}

func startSandbox(configPath string) {
	s := &sandboxSubsystem{}
	sandboxSys = s // Set global variable BEFORE starting, so ResolveDeviceID works during init
	if err := s.start(configPath); err != nil {
		log.Printf("sandbox: %v — sandbox enforcement disabled", err)
		sandboxSys = nil
		return
	}
}

func (s *sandboxSubsystem) start(configPath string) error {
	s.selfCgroupID = cgroupInodeOf(os.Getpid())
	if s.selfCgroupID != 0 {
		debugLog("sandbox: agent self cgroup id: %d", s.selfCgroupID)
	}

	// Clean up any stale BPF pins from a previous crashed run. If the agent
	// died while its own cgroup was being sandboxed, stuck pins in /sys/fs/bpf
	// could prevent the new agent from reading its own config.
	pinPath := "/sys/fs/bpf/sudo-logger"
	if _, err := os.Stat(pinPath); err == nil {
		debugLog("sandbox: cleaning up stale BPF pins at %s", pinPath)
		if err := os.RemoveAll(pinPath); err != nil {
			log.Printf("sandbox: warning: failed to remove stale pins: %v", err)
		}
	}

	spec, err := LoadSandbox()
	if err != nil {
		return fmt.Errorf("load Sandbox spec: %w", err)
	}

	objs := &SandboxObjects{}
	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinPath,
		},
	}
	if err := spec.LoadAndAssign(objs, opts); err != nil {
		return fmt.Errorf("load BPF objects: %w", err)
	}
	s.objs = objs

	res, err := loadSandboxConfig(configPath)
	if err != nil {
		objs.Close()
		return err
	}

	marker := uint8(1)

	for _, key := range res.Inodes {
		if err := objs.ProtectedInodes.Put(key, marker); err != nil {
			log.Printf("sandbox: insert inode {ino=%d dev=%d}: %v", key.Ino, key.Dev, err)
		}
	}

	for _, key := range res.IPCInodes {
		if err := objs.SystemdIpcInodes.Put(key, marker); err != nil {
			log.Printf("sandbox: insert systemd-ipc inode {ino=%d dev=%d}: %v", key.Ino, key.Dev, err)
		}
	}

	for _, key := range res.Forbidden {
		if err := objs.ForbiddenBinaries.Put(key, marker); err != nil {
			log.Printf("sandbox: insert forbidden binary {ino=%d dev=%d}: %v", key.Ino, key.Dev, err)
		}
	}

	for _, key := range res.Noexec {
		if err := objs.NoexecInodes.Put(key, marker); err != nil {
			log.Printf("sandbox: insert noexec inode {ino=%d dev=%d}: %v", key.Ino, key.Dev, err)
		} else {
			log.Printf("sandbox: successfully inserted noexec inode {ino=%d dev=%d}", key.Ino, key.Dev)
		}
	}

	for _, name := range res.Processes {
		var key [16]byte
		copy(key[:], name)
		if err := objs.ProtectedProcs.Put(key, marker); err != nil {
			log.Printf("sandbox: insert proc %q: %v", name, err)
		}
	}

	var attached []link.Link
	closeAttached := func() {
		for _, l := range attached {
			_ = l.Close()
		}
		objs.Close()
	}

	attachLSM := func(prog *ebpf.Program, name string) error {
		l, err := link.AttachLSM(link.LSMOptions{Program: prog})
		if err != nil {
			closeAttached()
			return fmt.Errorf("attach lsm/%s: %w", name, err)
		}
		attached = append(attached, l)
		return nil
	}

	attachTracepoint := func(prog *ebpf.Program, name string) error {
		l, err := link.AttachTracing(link.TracingOptions{Program: prog})
		if err != nil {
			closeAttached()
			return fmt.Errorf("attach tp/%s: %w", name, err)
		}
		attached = append(attached, l)
		return nil
	}

	if err := attachLSM(objs.SandboxFilePermission, "file_permission"); err != nil {
		return err
	}
	if err := attachLSM(objs.SandboxInodeUnlink, "inode_unlink"); err != nil {
		return err
	}
	if err := attachLSM(objs.SandboxInodeRename, "inode_rename"); err != nil {
		return err
	}
	if err := attachLSM(objs.SandboxTaskKill, "task_kill"); err != nil {
		return err
	}
	if err := attachLSM(objs.SandboxInodeMkdir, "inode_mkdir"); err != nil {
		return err
	}
	if err := attachLSM(objs.SandboxInodeCreate, "inode_create"); err != nil {
		return err
	}
	if err := attachLSM(objs.SandboxInodeMknod, "inode_mknod"); err != nil {
		return err
	}
	if err := attachLSM(objs.SandboxInodeSymlink, "inode_symlink"); err != nil {
		return err
	}
	if err := attachLSM(objs.SandboxInodeSetattr, "inode_setattr"); err != nil {
		return err
	}
	if err := attachLSM(objs.SandboxFileOpen, "file_open"); err != nil {
		return err
	}
	if err := attachLSM(objs.SandboxPathTruncate, "path_truncate"); err != nil {
		return err
	}
	if err := attachTracepoint(objs.SandboxProcessFork, "sched_process_fork"); err != nil {
		return err
	}
	if err := attachTracepoint(objs.SandboxProcessExit, "sched_process_exit"); err != nil {
		return err
	}

	applyFeatures(objs, res.Features)

	if err := attachLSM(objs.SandboxBpf, "bpf"); err != nil {
		return err
	}
	if err := attachLSM(objs.SandboxSocketCreate, "socket_create"); err != nil {
		return err
	}
	if err := attachLSM(objs.SandboxPtraceAccessCheck, "ptrace_access_check"); err != nil {
		return err
	}
	if err := attachLSM(objs.SandboxSbMount, "sb_mount"); err != nil {
		return err
	}
	if err := attachLSM(objs.SandboxCapable, "capable"); err != nil {
		return err
	}
	if err := attachLSM(objs.SandboxUnixConnect, "unix_stream_connect"); err != nil {
		return err
	}
	if err := attachLSM(objs.SandboxBprmCheckSecurity, "bprm_check_security"); err != nil {
		return err
	}

	s.links = attached

	go s.pollAlerts()
	s.startWatcher(res.PathInodes)

	log.Printf("sandbox: LSM hooks attached (%d protected inodes, %d protected processes)",
		len(res.Inodes), len(res.Processes))
	return nil
}

// registerCgroup marks a cgroup as subject to sandbox restrictions.
// Called when a sudo session cgroup is created.
func (s *sandboxSubsystem) registerCgroup(cgroupID uint64) {
	if s == nil || s.objs == nil || cgroupID == 0 {
		return
	}
	if cgroupID == s.selfCgroupID {
		debugLog("sandbox: skipping registration of agent self cgroup %d", cgroupID)
		return
	}
	marker := uint8(1)
	if err := s.objs.SandboxedCgroups.Put(cgroupID, marker); err != nil {
		log.Printf("sandbox: register cgroup %d: %v", cgroupID, err)
	}
	debugLog("sandbox: cgroup %d registered", cgroupID)
}

// unregisterCgroup removes a cgroup from the sandbox restriction set.
// Called when a sudo session cgroup is removed.
func (s *sandboxSubsystem) unregisterCgroup(cgroupID uint64) {
	if s == nil || s.objs == nil {
		return
	}
	if err := s.objs.SandboxedCgroups.Delete(cgroupID); err != nil {
		debugLog("sandbox: unregister cgroup %d: %v", cgroupID, err)
	}
}

func (s *sandboxSubsystem) stop() {
	if s == nil {
		return
	}
	if s.watcher != nil {
		s.watcher.Close()
	}
	for _, l := range s.links {
		l.Close()
	}
	if s.objs != nil {
		s.objs.Close()
	}
}

// reloadConfig atomically replaces the protected inode and process sets in the
// BPF maps and restarts the inotify watcher for the new path set. The LSM hooks
// themselves remain attached — only the map contents change.
func (s *sandboxSubsystem) reloadConfig(res *resolvedSandbox, logChange bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	marker := uint8(1)

	// 1. Write/insert all new inodes from the new configuration first.
	newInodes := make(map[SandboxInodeKey]bool)
	for _, key := range res.Inodes {
		newInodes[key] = true
		if err := s.objs.ProtectedInodes.Put(key, marker); err != nil {
			log.Printf("sandbox reload: insert inode {ino=%d dev=%d}: %v", key.Ino, key.Dev, err)
		}
	}

	// 2. Iterate over active keys in the map, find and delete obsolete ones.
	var obsoleteInodes []SandboxInodeKey
	{
		var k SandboxInodeKey
		var v uint8
		iter := s.objs.ProtectedInodes.Iterate()
		for iter.Next(&k, &v) {
			if !newInodes[k] {
				obsoleteInodes = append(obsoleteInodes, k)
			}
		}
	}
	for _, k := range obsoleteInodes {
		if err := s.objs.ProtectedInodes.Delete(k); err != nil {
			log.Printf("sandbox reload: delete obsolete inode {ino=%d dev=%d}: %v", k.Ino, k.Dev, err)
		}
	}

	// 1. Write/insert all new processes from the new configuration first.
	newProcs := make(map[[16]byte]bool)
	for _, name := range res.Processes {
		var key [16]byte
		copy(key[:], name)
		newProcs[key] = true
		if err := s.objs.ProtectedProcs.Put(key, marker); err != nil {
			log.Printf("sandbox reload: insert proc %q: %v", name, err)
		}
	}

	// 2. Iterate over active keys in the map, find and delete obsolete ones.
	var obsoleteProcs [][16]byte
	{
		var k [16]byte
		var v uint8
		iter := s.objs.ProtectedProcs.Iterate()
		for iter.Next(&k, &v) {
			if !newProcs[k] {
				obsoleteProcs = append(obsoleteProcs, k)
			}
		}
	}
	for _, k := range obsoleteProcs {
		name := strings.TrimRight(string(k[:]), "\x00")
		if err := s.objs.ProtectedProcs.Delete(k); err != nil {
			log.Printf("sandbox reload: delete obsolete proc %q: %v", name, err)
		}
	}

	oldFeatures := s.lastFeatures
	applyFeatures(s.objs, res.Features)

	// Insert new, then delete obsolete — for each set below, same diff-based
	// approach as ProtectedInodes/ProtectedProcs above, so there is never a
	// window where a map is empty and the corresponding check is unenforced.

	// systemd-ipc inodes.
	newIPCInodes := make(map[SandboxInodeKey]bool)
	for _, key := range res.IPCInodes {
		newIPCInodes[key] = true
		if err := s.objs.SystemdIpcInodes.Put(key, marker); err != nil {
			log.Printf("sandbox reload: insert systemd-ipc inode {ino=%d dev=%d}: %v", key.Ino, key.Dev, err)
		}
	}
	var obsoleteIPCInodes []SandboxInodeKey
	{
		var k SandboxInodeKey
		var v uint8
		iter := s.objs.SystemdIpcInodes.Iterate()
		for iter.Next(&k, &v) {
			if !newIPCInodes[k] {
				obsoleteIPCInodes = append(obsoleteIPCInodes, k)
			}
		}
	}
	for _, k := range obsoleteIPCInodes {
		_ = s.objs.SystemdIpcInodes.Delete(k)
	}

	// Forbidden binary inodes.
	newForbidden := make(map[SandboxInodeKey]bool)
	for _, key := range res.Forbidden {
		newForbidden[key] = true
		if err := s.objs.ForbiddenBinaries.Put(key, marker); err != nil {
			log.Printf("sandbox reload: insert forbidden binary {ino=%d dev=%d}: %v", key.Ino, key.Dev, err)
		}
	}
	var obsoleteForbidden []SandboxInodeKey
	{
		var k SandboxInodeKey
		var v uint8
		iter := s.objs.ForbiddenBinaries.Iterate()
		for iter.Next(&k, &v) {
			if !newForbidden[k] {
				obsoleteForbidden = append(obsoleteForbidden, k)
			}
		}
	}
	for _, k := range obsoleteForbidden {
		_ = s.objs.ForbiddenBinaries.Delete(k)
	}

	// Noexec directory inodes.
	newNoexec := make(map[SandboxInodeKey]bool)
	for _, key := range res.Noexec {
		newNoexec[key] = true
		if err := s.objs.NoexecInodes.Put(key, marker); err != nil {
			log.Printf("sandbox reload: insert noexec inode {ino=%d dev=%d}: %v", key.Ino, key.Dev, err)
		}
	}
	var obsoleteNoexec []SandboxInodeKey
	{
		var k SandboxInodeKey
		var v uint8
		iter := s.objs.NoexecInodes.Iterate()
		for iter.Next(&k, &v) {
			if !newNoexec[k] {
				obsoleteNoexec = append(obsoleteNoexec, k)
			}
		}
	}
	for _, k := range obsoleteNoexec {
		_ = s.objs.NoexecInodes.Delete(k)
	}

	// Restart the inotify watcher for the new set of parent directories.
	if s.watcher != nil {
		s.watcher.Close()
		s.watcher = nil
	}
	s.startWatcher(res.PathInodes)

	// Detect and flag a config push that removes protection the previous
	// config had (A-3: a compromised or careless server-pushed sandbox.yaml
	// can silently defeat enforcement fleet-wide). This does not block the
	// reload — it only makes a weakening reload loud instead of silent.
	logSandboxWeakening(oldFeatures, res.Features, len(obsoleteInodes), len(obsoleteProcs),
		len(obsoleteIPCInodes), len(obsoleteForbidden), len(obsoleteNoexec))
	s.lastFeatures = res.Features

	if logChange {
		log.Printf("sandbox: config reloaded (%d protected inodes, %d protected processes)",
			len(res.Inodes), len(res.Processes))
	} else {
		debugLog("sandbox: configuration refreshed (periodic)")
	}
}

// logSandboxWeakening compares a reload's old and new feature flags and
// obsolete-entry counts, and logs a loud, distinctly-marked warning if the
// new config removes any protection the old one had — whether a feature
// flag flipped from enabled to disabled, or a previously-protected
// inode/process/systemd-ipc-socket/forbidden-binary/noexec-dir is no longer
// covered. A reload that only adds protections, or swaps one set of paths
// for another without a net loss, does not trigger this.
func logSandboxWeakening(oldF, newF resolvedFeatures, removedInodes, removedProcs, removedIPC, removedForbidden, removedNoexec int) {
	var reasons []string

	disabled := func(name string, old, new bool) {
		if old && !new {
			reasons = append(reasons, name+" disabled")
		}
	}
	disabled("deny_netlink", oldF.DenyNetlink, newF.DenyNetlink)
	disabled("deny_mount", oldF.DenyMount, newF.DenyMount)
	disabled("deny_ptrace", oldF.DenyPtrace, newF.DenyPtrace)
	disabled("deny_cap_audit_control", oldF.DenyCapAuditControl, newF.DenyCapAuditControl)
	disabled("deny_cap_net_admin", oldF.DenyCapNetAdmin, newF.DenyCapNetAdmin)
	disabled("deny_cap_sys_module", oldF.DenyCapSysModule, newF.DenyCapSysModule)
	disabled("deny_cap_mac_admin", oldF.DenyCapMacAdmin, newF.DenyCapMacAdmin)
	disabled("deny_cap_sys_rawio", oldF.DenyCapSysRawio, newF.DenyCapSysRawio)
	disabled("deny_cap_sys_boot", oldF.DenyCapSysBoot, newF.DenyCapSysBoot)
	disabled("deny_systemd_ipc", oldF.DenySystemdIPC, newF.DenySystemdIPC)

	if removedInodes > 0 {
		reasons = append(reasons, fmt.Sprintf("%d protected path(s) no longer protected", removedInodes))
	}
	if removedProcs > 0 {
		reasons = append(reasons, fmt.Sprintf("%d protected process(es) no longer protected", removedProcs))
	}
	if removedIPC > 0 {
		reasons = append(reasons, fmt.Sprintf("%d systemd-ipc socket(s) no longer blocked", removedIPC))
	}
	if removedForbidden > 0 {
		reasons = append(reasons, fmt.Sprintf("%d forbidden-binary rule(s) removed", removedForbidden))
	}
	if removedNoexec > 0 {
		reasons = append(reasons, fmt.Sprintf("%d noexec rule(s) removed", removedNoexec))
	}

	if len(reasons) > 0 {
		log.Printf("sandbox: SECURITY WARNING: protection reduced by config reload — %s",
			strings.Join(reasons, "; "))
	}
}

// reloadSandboxFromContent parses yamlText and applies it to the running
// sandbox subsystem. Called by the sandbox poller when the server delivers
// an updated sandbox.yaml.
func reloadSandboxFromContent(yamlText string, logChange bool) error {
	if sandboxSys == nil {
		return fmt.Errorf("sandbox not running")
	}
	res, err := loadSandboxConfigFromBytes([]byte(yamlText))
	if err != nil {
		return fmt.Errorf("parse sandbox config from server: %w", err)
	}
	sandboxSys.reloadConfig(res, logChange)
	return nil
}

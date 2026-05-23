package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"sudo-logger/internal/protocol"

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
}

// bpfSandboxAlert must match struct sandbox_alert in sandbox.bpf.c
type bpfSandboxAlert struct {
	CgroupID uint64
	Pid      uint32
	Type     uint32
	Comm     [16]byte
}

func (s *sandboxSubsystem) pollAlerts() {
	rd, err := ringbuf.NewReader(s.objs.SandboxAlerts)
	if err != nil {
		log.Printf("sandbox: alert reader: %v", err)
		return
	}
	defer rd.Close()

	log.Printf("sandbox: alert listener started")

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
		s.reportViolation(bpfAlert.CgroupID, bpfAlert.Pid, bpfAlert.Type, comm)
	}
}

func (s *sandboxSubsystem) reportViolation(cgid uint64, pid uint32, alertType uint32, comm string) {
	typeName := alertNames[alertType]
	if typeName == "" {
		typeName = "UNKNOWN"
	}

	log.Printf("SANDBOX VIOLATION: Process %q (PID %d) blocked by %s [cgid=%d]",
		comm, pid, typeName, cgid)

	alert := protocol.SandboxAlert{
		Pid:  pid,
		Comm: comm,
		Type: alertType,
		Ts:   time.Now().Unix(),
	}

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

// registerPID marks a PID (tgid) as sandboxed in the BPF map.
// The sched_process_fork hook propagates membership to all descendants.
func (s *sandboxSubsystem) registerPID(pid uint32) {
	if s == nil || s.objs == nil {
		return
	}
	marker := uint8(1)
	if err := s.objs.SandboxedPids.Put(pid, marker); err != nil {
		log.Printf("sandbox: register pid %d: %v", pid, err)
	}
	debugLog("sandbox: pid %d registered", pid)
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
	objs       *SandboxObjects
	links      []link.Link
	mu         sync.Mutex
	pathInodes map[string]SandboxInodeKey // protected path → inode key currently in BPF map
	watcher    *fsnotify.Watcher
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
	log.Printf("sandbox: aux cgroup %d registered for session %s", cgid, cg.cgName)
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
	spec, err := LoadSandbox()
	if err != nil {
		return fmt.Errorf("load Sandbox spec: %w", err)
	}

	objs := &SandboxObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
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

	for _, name := range res.Processes {
		var key [16]byte
		copy(key[:], name)
		if err := objs.ProtectedProcs.Put(key, marker); err != nil {
			log.Printf("sandbox: insert proc %q: %v", name, err)
		}
	}

	lsmFile, err := link.AttachLSM(link.LSMOptions{Program: objs.SandboxFilePermission})
	if err != nil {
		objs.Close()
		return fmt.Errorf("attach lsm/file_permission: %w", err)
	}
	lsmUnlink, err := link.AttachLSM(link.LSMOptions{Program: objs.SandboxInodeUnlink})
	if err != nil {
		lsmFile.Close()
		objs.Close()
		return fmt.Errorf("attach lsm/inode_unlink: %w", err)
	}
	lsmRename, err := link.AttachLSM(link.LSMOptions{Program: objs.SandboxInodeRename})
	if err != nil {
		lsmFile.Close()
		lsmUnlink.Close()
		objs.Close()
		return fmt.Errorf("attach lsm/inode_rename: %w", err)
	}
	lsmKill, err := link.AttachLSM(link.LSMOptions{Program: objs.SandboxTaskKill})
	if err != nil {
		lsmFile.Close()
		lsmUnlink.Close()
		lsmRename.Close()
		objs.Close()
		return fmt.Errorf("attach lsm/task_kill: %w", err)
	}
	lsmMkdir, err := link.AttachLSM(link.LSMOptions{Program: objs.SandboxInodeMkdir})
	if err != nil {
		lsmFile.Close()
		lsmUnlink.Close()
		lsmRename.Close()
		lsmKill.Close()
		objs.Close()
		return fmt.Errorf("attach lsm/inode_mkdir: %w", err)
	}
	lsmCreate, err := link.AttachLSM(link.LSMOptions{Program: objs.SandboxInodeCreate})
	if err != nil {
		lsmFile.Close()
		lsmUnlink.Close()
		lsmRename.Close()
		lsmKill.Close()
		lsmMkdir.Close()
		objs.Close()
		return fmt.Errorf("attach lsm/inode_create: %w", err)
	}
	lsmMknod, err := link.AttachLSM(link.LSMOptions{Program: objs.SandboxInodeMknod})
	if err != nil {
		lsmFile.Close()
		lsmUnlink.Close()
		lsmRename.Close()
		lsmKill.Close()
		lsmMkdir.Close()
		lsmCreate.Close()
		objs.Close()
		return fmt.Errorf("attach lsm/inode_mknod: %w", err)
	}
	lsmSymlink, err := link.AttachLSM(link.LSMOptions{Program: objs.SandboxInodeSymlink})
	if err != nil {
		lsmFile.Close()
		lsmUnlink.Close()
		lsmRename.Close()
		lsmKill.Close()
		lsmMkdir.Close()
		lsmCreate.Close()
		lsmMknod.Close()
		objs.Close()
		return fmt.Errorf("attach lsm/inode_symlink: %w", err)
	}
	lsmSetattr, err := link.AttachLSM(link.LSMOptions{Program: objs.SandboxInodeSetattr})
	if err != nil {
		lsmFile.Close()
		lsmUnlink.Close()
		lsmRename.Close()
		lsmKill.Close()
		lsmMkdir.Close()
		lsmCreate.Close()
		lsmMknod.Close()
		lsmSymlink.Close()
		objs.Close()
		return fmt.Errorf("attach lsm/inode_setattr: %w", err)
	}
	lsmOpen, err := link.AttachLSM(link.LSMOptions{Program: objs.SandboxFileOpen})
	if err != nil {
		lsmFile.Close()
		lsmUnlink.Close()
		lsmRename.Close()
		lsmKill.Close()
		lsmMkdir.Close()
		lsmCreate.Close()
		lsmMknod.Close()
		lsmSymlink.Close()
		lsmSetattr.Close()
		objs.Close()
		return fmt.Errorf("attach lsm/file_open: %w", err)
	}
	lsmTrunc, err := link.AttachLSM(link.LSMOptions{Program: objs.SandboxPathTruncate})
	if err != nil {
		lsmFile.Close()
		lsmUnlink.Close()
		lsmRename.Close()
		lsmKill.Close()
		lsmMkdir.Close()
		lsmCreate.Close()
		lsmMknod.Close()
		lsmSymlink.Close()
		lsmSetattr.Close()
		lsmOpen.Close()
		objs.Close()
		return fmt.Errorf("attach lsm/path_truncate: %w", err)
	}
	tpFork, err := link.AttachTracing(link.TracingOptions{Program: objs.SandboxProcessFork})
	if err != nil {
		lsmFile.Close()
		lsmUnlink.Close()
		lsmRename.Close()
		lsmKill.Close()
		lsmMkdir.Close()
		lsmCreate.Close()
		lsmMknod.Close()
		lsmSymlink.Close()
		lsmSetattr.Close()
		lsmOpen.Close()
		lsmTrunc.Close()
		objs.Close()
		return fmt.Errorf("attach tp/sched_process_fork: %w", err)
	}
	tpExit, err := link.AttachTracing(link.TracingOptions{Program: objs.SandboxProcessExit})
	if err != nil {
		lsmFile.Close()
		lsmUnlink.Close()
		lsmRename.Close()
		lsmKill.Close()
		lsmMkdir.Close()
		lsmCreate.Close()
		lsmMknod.Close()
		lsmSymlink.Close()
		lsmSetattr.Close()
		lsmOpen.Close()
		lsmTrunc.Close()
		tpFork.Close()
		objs.Close()
		return fmt.Errorf("attach tp/sched_process_exit: %w", err)
	}
	s.links = []link.Link{lsmFile, lsmUnlink, lsmRename, lsmKill, lsmMkdir, lsmCreate, lsmMknod, lsmSymlink, lsmSetattr, lsmOpen, lsmTrunc, tpFork, tpExit}

	go s.pollAlerts()
	s.startWatcher(res.PathInodes)

	log.Printf("sandbox: LSM hooks attached (%d protected inodes, %d protected processes)",
		len(res.Inodes), len(res.Processes))
	return nil
}

// registerCgroup marks a cgroup as subject to sandbox restrictions.
// Called when a sudo session cgroup is created.
func (s *sandboxSubsystem) registerCgroup(cgroupID uint64) {
	if s == nil || s.objs == nil {
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

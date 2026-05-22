package main

import (
	"fmt"
	"log"
	"sync"

	"github.com/cilium/ebpf/link"
	"github.com/fsnotify/fsnotify"
)

// sandboxSubsystem enforces filesystem and process-kill restrictions on
// processes running inside sudo-logger session cgroups, via eBPF LSM hooks.
type sandboxSubsystem struct {
	objs       *SandboxObjects
	links      []link.Link
	mu         sync.Mutex
	pathInodes map[string]inodeKey // protected path → inode key currently in BPF map
	watcher    *fsnotify.Watcher
}

var sandboxSys *sandboxSubsystem

func startSandbox(configPath string) {
	s := &sandboxSubsystem{}
	if err := s.start(configPath); err != nil {
		log.Printf("sandbox: %v — sandbox enforcement disabled", err)
		return
	}
	sandboxSys = s
}

func (s *sandboxSubsystem) start(configPath string) error {
	res, err := loadSandboxConfig(configPath)
	if err != nil {
		return err
	}

	objs := &SandboxObjects{}
	if err := LoadSandboxObjects(objs, nil); err != nil {
		return fmt.Errorf("load BPF objects: %w", err)
	}
	s.objs = objs

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
	s.links = []link.Link{lsmFile, lsmUnlink, lsmRename, lsmKill}

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

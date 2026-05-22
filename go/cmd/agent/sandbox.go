package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"

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
	s.links = []link.Link{lsmFile, lsmUnlink, lsmRename, lsmKill, lsmMkdir, lsmCreate, lsmMknod, lsmSymlink}

	s.startWatcher(res.PathInodes)

	log.Printf("sandbox: LSM hooks attached (%d protected inodes, %d protected processes)",
		len(res.Inodes), len(res.Processes))
	return nil
}

// ResolveDeviceID returns the kernel-internal s_dev for the filesystem
// containing path. On Btrfs, this is the physical device ID, while stat()
// returns an anonymous ID. We parse /proc/self/mountinfo to find the real one.
func (s *sandboxSubsystem) ResolveDeviceID(path string) (uint32, error) {
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

		majMin := fields[2]
		parts := strings.SplitN(majMin, ":", 2)
		if len(parts) == 2 {
			major, _ := strconv.ParseUint(parts[0], 10, 32)
			minor, _ := strconv.ParseUint(parts[1], 10, 32)

			if major == 0 {
				source := ""
				for i := 6; i < len(fields); i++ {
					if fields[i] == "-" && i+1 < len(fields) {
						source = fields[i+2]
						break
					}
				}
				if source != "" && strings.HasPrefix(source, "/dev/") {
					var srcSt syscall.Stat_t
					if err := syscall.Stat(source, &srcSt); err == nil {
						bestDev = uint32(srcSt.Rdev)
						bestLen = len(mountPoint)
						continue
					}
				}
			}

			bestDev = (uint32(major) << 20) | uint32(minor)
			bestLen = len(mountPoint)
		}
	}
	if bestLen < 0 {
		return 0, fmt.Errorf("no mount entry found for %s", path)
	}
	return bestDev, nil
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

package main

import (
	"log"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/fsnotify/fsnotify"
)

// startWatcher sets up inotify watches on the parent directories of all
// protected paths and launches a goroutine that refreshes the protected_inodes
// BPF map whenever a path is atomically replaced (rename/create).
//
// Atomic editors (vi, cp, install) write to a temp file then rename it over
// the target, assigning a new inode. Without this watcher the BPF map would
// hold a stale inode and miss writes to the replaced file.
func (s *sandboxSubsystem) startWatcher(pathInodes map[string]WatchedPath) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("sandbox: inotify watcher unavailable: %v — protected inodes will not auto-refresh", err)
		return
	}
	s.watcher = watcher
	s.pathInodes = pathInodes

	dirs := make(map[string]struct{})
	for p := range pathInodes {
		parent := filepath.Dir(p)
		dirs[parent] = struct{}{}
	}
	for dir := range dirs {
		// Skip pseudo-filesystems: procfs and sysfs entries are virtual files
		// that are never atomically replaced (rename/create), so inotify watches
		// on them are pointless and may fail or generate no useful events.
		if strings.HasPrefix(dir, "/proc/") || strings.HasPrefix(dir, "/sys/") {
			debugLog("sandbox: skipping watch on pseudo-fs path %s", dir)
			continue
		}
		if err := watcher.Add(dir); err != nil {
			log.Printf("sandbox: watch %s: %v", dir, err)
		}
	}
	debugLog("sandbox: watching %d parent directories for inode changes", len(dirs))
	go s.watchLoop()
}

func (s *sandboxSubsystem) watchLoop() {
	for {
		select {
		case event, ok := <-s.watcher.Events:
			if !ok {
				return
			}
			// fsnotify maps both IN_CREATE and IN_MOVED_TO to Create.
			// IN_MOVED_TO fires when an atomic rename lands on a watched path.
			if event.Has(fsnotify.Create) {
				s.refreshInode(event.Name)
			}
		case err, ok := <-s.watcher.Errors:
			if !ok {
				return
			}
			log.Printf("sandbox: watcher error: %v", err)
		}
	}
}

// targetMap returns the BPF map that a WatchTarget's inodes belong to.
func (s *sandboxSubsystem) targetMap(t WatchTarget) *ebpf.Map {
	switch t {
	case WatchTrustedBinaries:
		return s.objs.TrustedBinaries
	case WatchAllowCreateIn:
		return s.objs.AllowCreateIn
	default:
		return s.objs.ProtectedInodes
	}
}

// refreshInode re-stats path and updates every BPF map path belongs to
// (routed via the watched path's Targets — a path can be registered in more
// than one, e.g. protected_inodes AND allow_create_in for the same
// directory) if the inode changed. Called after a Create/IN_MOVED_TO event
// on the parent dir.
func (s *sandboxSubsystem) refreshInode(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	old, ok := s.pathInodes[path]
	if !ok {
		// File is not a watched path — a new unrelated file was created in a
		// watched parent directory. Do not auto-protect/auto-trust it.
		return
	}

	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		// File removed — check if we were tracking it
		log.Printf("sandbox: %s removed — dropping from tracked inodes (targets=%v)", path, old.Targets)
		for _, t := range old.Targets {
			_ = s.targetMap(t).Delete(old.Key)
		}
		delete(s.pathInodes, path)
		return
	}

	dev, devErr := mountDev(path)
	if devErr != nil {
		log.Printf("sandbox: mountDev %s: %v (falling back to stat dev)", path, devErr)
		dev = uint32(st.Dev)
	}
	newKey := SandboxInodeKey{Ino: st.Ino, Dev: dev}

	if newKey == old.Key {
		return // inode unchanged, nothing to do
	}

	// Insert the new inode into every target map BEFORE removing the old one
	// from any of them, so there is never a window where a target is
	// unenforced (matches the documented-safe order reloadConfig already
	// uses in sandbox.go) — an atomic file replacement landing in a
	// delete-then-insert gap would otherwise pass unenforced.
	marker := uint8(1)
	for _, t := range old.Targets {
		if err := s.targetMap(t).Put(newKey, marker); err != nil {
			log.Printf("sandbox: track inode for %s (target %v): %v", path, t, err)
			return
		}
	}

	// Only delete the old key from a target map if no other watched path
	// registered under that SAME target still uses it.
	for _, t := range old.Targets {
		shared := false
		for otherPath, wp := range s.pathInodes {
			if otherPath == path || wp.Key != old.Key {
				continue
			}
			for _, ot := range wp.Targets {
				if ot == t {
					shared = true
					break
				}
			}
			if shared {
				break
			}
		}
		if !shared {
			_ = s.targetMap(t).Delete(old.Key)
		}
	}
	log.Printf("sandbox: refreshed tracked inode for %s: {ino=%d dev=%d} → {ino=%d dev=%d} (targets=%v)",
		path, old.Key.Ino, old.Key.Dev, newKey.Ino, newKey.Dev, old.Targets)

	s.pathInodes[path] = WatchedPath{Key: newKey, Targets: old.Targets}
}

package main

import (
	"log"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/fsnotify/fsnotify"
)

// startWatcher sets up inotify watches on the parent directories of all
// protected paths and launches a goroutine that refreshes the protected_inodes
// BPF map whenever a path is atomically replaced (rename/create).
//
// Atomic editors (vi, cp, install) write to a temp file then rename it over
// the target, assigning a new inode. Without this watcher the BPF map would
// hold a stale inode and miss writes to the replaced file.
func (s *sandboxSubsystem) startWatcher(pathInodes map[string]SandboxInodeKey) {
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

// refreshInode re-stats path and updates the protected_inodes BPF map if the
// inode changed. Called after a Create/IN_MOVED_TO event on the parent dir.
func (s *sandboxSubsystem) refreshInode(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		// File removed — check if we were tracking it
		if old, ok := s.pathInodes[path]; ok {
			log.Printf("sandbox: %s removed — dropping from protected inodes", path)
			_ = s.objs.ProtectedInodes.Delete(old)
			delete(s.pathInodes, path)
		}
		return
	}

	dev, devErr := mountDev(path)
	if devErr != nil {
		log.Printf("sandbox: mountDev %s: %v (falling back to stat dev)", path, devErr)
		dev = uint32(st.Dev)
	}
	newKey := SandboxInodeKey{Ino: st.Ino, Dev: dev}

	old, ok := s.pathInodes[path]
	if ok {
		if newKey == old {
			return // inode unchanged, nothing to do
		}

		// Only delete the old key if no other protected path still uses it.
		shared := false
		for otherPath, k := range s.pathInodes {
			if otherPath != path && k == old {
				shared = true
				break
			}
		}
		if !shared {
			_ = s.objs.ProtectedInodes.Delete(old)
		}
		log.Printf("sandbox: refreshed protected inode for %s: {ino=%d dev=%d} → {ino=%d dev=%d}",
			path, old.Ino, old.Dev, newKey.Ino, newKey.Dev)
	} else {
		// New file created in a watched directory
		log.Printf("sandbox: protecting newly created file %s: {ino=%d dev=%d}",
			path, newKey.Ino, newKey.Dev)
	}

	marker := uint8(1)
	if err := s.objs.ProtectedInodes.Put(newKey, marker); err != nil {
		log.Printf("sandbox: protect inode for %s: %v", path, err)
		return
	}

	s.pathInodes[path] = newKey
}

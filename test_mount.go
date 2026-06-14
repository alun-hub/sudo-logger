package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

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
		major, _ := strconv.ParseUint(parts[0], 10, 32)
		minor, _ := strconv.ParseUint(parts[1], 10, 32)
		dev := uint32((major << 20) | minor)
		bestLen = len(mountPoint)
		bestDev = dev
	}
	return bestDev, nil
}

func check(path string) {
	dev, _ := mountDev(path)
	fi, err := os.Stat(path)
	if err == nil {
		fmt.Printf("%s -> ino:%d dev:%d\n", path, fi.Sys().(*syscall.Stat_t).Ino, dev)
	}
}

func main() {
	check("/tmp")
	check("/var/tmp")
	check("/dev/shm")
	check("/run/user")
	check("/usr/bin")
	check("/usr")
	check("/bin")
	check("/")
}

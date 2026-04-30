// Package main is the sudo-logger-agent daemon.
//
// Before building, generate vmlinux.h and the bpf2go bindings:
//
//	make vmlinux-agent          # generates go/cmd/agent/bpf/vmlinux.h
//	go generate ./cmd/agent/    # compiles BPF C → Go bindings
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -Wno-missing-declarations -Wno-missing-prototypes -D__TARGET_ARCH_x86_64" Recorder bpf/recorder.c -- -I./bpf
package main

// Package main is the ebpf-recorder daemon.
//
// Before building, generate vmlinux.h and the bpf2go bindings:
//
//	make -C ../../../ vmlinux          # generates bpf/vmlinux.h
//	go generate ./cmd/ebpf-recorder/  # compiles BPF C → Go bindings
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86_64" Recorder bpf/recorder.c -- -I./bpf
package main

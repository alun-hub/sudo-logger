# sudo-logger build targets
#
# Typical first-time setup for ebpf-recorder on Fedora:
#   sudo dnf install clang llvm libbpf-devel bpftool linux-headers-$(uname -r)
#   make vmlinux
#   make generate
#   make ebpf-recorder

GOPATH  ?= $(shell go env GOPATH)
KERNEL  ?= $(shell uname -r)
ARCH    ?= $(shell uname -m | sed 's/x86_64/x86_64/;s/aarch64/arm64/')

.PHONY: all ebpf-recorder vmlinux generate tidy test clean

all: ebpf-recorder

# Generate vmlinux.h from the running kernel's BTF data.
# Must be re-run after a kernel upgrade before rebuilding ebpf-recorder.
vmlinux: go/cmd/ebpf-recorder/bpf/vmlinux.h

go/cmd/ebpf-recorder/bpf/vmlinux.h: /sys/kernel/btf/vmlinux
	bpftool btf dump file $< format c > $@
	@echo "vmlinux.h generated for kernel $(KERNEL)"

# Compile BPF C → Go bindings (bpf2go).
# Requires vmlinux.h to exist first.
generate: go/cmd/ebpf-recorder/bpf/vmlinux.h
	cd go && go generate ./cmd/ebpf-recorder/

# Build the ebpf-recorder binary.
ebpf-recorder: generate
	cd go && go build -o ../bin/ebpf-recorder ./cmd/ebpf-recorder/

# Tidy and verify module dependencies.
tidy:
	cd go && go mod tidy

# Run tests (all packages that have them).
test:
	cd go && go test ./...

clean:
	rm -f go/cmd/ebpf-recorder/recorder_bpf*.go
	rm -f go/cmd/ebpf-recorder/recorder_bpf*.o
	rm -f go/cmd/ebpf-recorder/bpf/vmlinux.h
	rm -f bin/ebpf-recorder

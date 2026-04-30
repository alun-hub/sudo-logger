# sudo-logger build targets
#
# Typical first-time setup on Fedora:
#   sudo dnf install clang llvm libbpf-devel bpftool linux-headers-$(uname -r)
#   make vmlinux-agent
#   make generate-agent
#   make agent

GOPATH  ?= $(shell go env GOPATH)
KERNEL  ?= $(shell uname -r)
ARCH    ?= $(shell uname -m | sed 's/x86_64/x86_64/;s/aarch64/arm64/')

.PHONY: all agent ebpf-recorder vmlinux vmlinux-agent generate generate-agent tidy test clean

all: agent

# ── sudo-logger-agent (merged shipper + eBPF recorder) ───────────────────────

vmlinux-agent: go/cmd/agent/bpf/vmlinux.h

go/cmd/agent/bpf/vmlinux.h: /sys/kernel/btf/vmlinux
	bpftool btf dump file $< format c > $@
	@echo "vmlinux.h generated for kernel $(KERNEL)"

generate-agent: go/cmd/agent/bpf/vmlinux.h
	cd go && go generate ./cmd/agent/

agent: generate-agent
	cd go && go build -o ../bin/sudo-logger-agent ./cmd/agent/

# ── Legacy ebpf-recorder (kept for reference, not installed) ─────────────────

vmlinux: go/cmd/ebpf-recorder/bpf/vmlinux.h

go/cmd/ebpf-recorder/bpf/vmlinux.h: /sys/kernel/btf/vmlinux
	bpftool btf dump file $< format c > $@
	@echo "vmlinux.h generated for kernel $(KERNEL)"

generate: go/cmd/ebpf-recorder/bpf/vmlinux.h
	cd go && go generate ./cmd/ebpf-recorder/

ebpf-recorder: generate
	cd go && go build -o ../bin/ebpf-recorder ./cmd/ebpf-recorder/

# ── Common ────────────────────────────────────────────────────────────────────

tidy:
	cd go && go mod tidy

test:
	cd go && go test ./...

clean:
	rm -f go/cmd/agent/recorder_bpf*.go
	rm -f go/cmd/agent/recorder_bpf*.o
	rm -f go/cmd/agent/bpf/vmlinux.h
	rm -f go/cmd/ebpf-recorder/recorder_bpf*.go
	rm -f go/cmd/ebpf-recorder/recorder_bpf*.o
	rm -f go/cmd/ebpf-recorder/bpf/vmlinux.h
	rm -f bin/sudo-logger-agent bin/ebpf-recorder

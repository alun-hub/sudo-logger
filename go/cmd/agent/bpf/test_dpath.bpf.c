#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("lsm/bprm_check_security")
int BPF_PROG(sandbox_bprm_check_security, struct linux_binprm *bprm)
{
	char buf[256];
	bpf_d_path((struct path *)&bprm->file->f_path, buf, sizeof(buf));
	return 0;
}
char LICENSE[] SEC("license") = "GPL";

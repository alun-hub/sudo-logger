NAME    = sudo_logger
POLDEV  = /usr/share/selinux/devel

all: $(NAME).pp

$(NAME).pp: $(NAME).te $(NAME).fc $(NAME).if
	make -f $(POLDEV)/Makefile $(NAME).pp

# Load in permissive mode first — use 'make enforce' once stable
install: $(NAME).pp
	semodule --priority=100 -i $(NAME).pp
	restorecon -Rv \
		/usr/bin/sudo-shipper \
		/usr/libexec/sudo/sudo_logger_plugin.so \
		/run/sudo-logger \
		/etc/sudo-logger
	semodule --list | grep sudo_logger

# Check current mode for this module
status:
	semodule --list | grep sudo_logger
	sestatus

# Switch this module to permissive (denials logged, not blocked)
permissive:
	semanage permissive -a sudo_shipper_t

# Switch this module to enforcing
enforce:
	semanage permissive -d sudo_shipper_t

# Collect AVC denials and show suggested rules
audit:
	ausearch -m avc -ts recent --comm sudo-shipper 2>/dev/null | audit2allow
	ausearch -m avc -ts recent --comm sudo        2>/dev/null | audit2allow

# Generate a refinement module from recent AVC denials
refine:
	ausearch -m avc -ts recent | audit2allow -M $(NAME)_local
	@echo ""
	@echo "Review $(NAME)_local.te, then:"
	@echo "  semodule -i $(NAME)_local.pp"

uninstall:
	semodule -r $(NAME) 2>/dev/null || true

clean:
	rm -f $(NAME).pp $(NAME).mod $(NAME).tmp $(NAME)_local.*

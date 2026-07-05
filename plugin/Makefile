CC      = gcc

# Single source of truth for the version string is the RPM spec; falls back
# to "dev" for checkouts without rpm/ (e.g. a stripped-down source tarball).
VERSION := $(shell grep -m1 '^Version:' ../rpm/sudo-logger-client.spec 2>/dev/null | awk '{print $$2}')
VERSION := $(if $(VERSION),$(VERSION),dev)

CFLAGS  = -Wall -Wextra -O2 -fPIC -shared \
          -Iinclude \
          -D_GNU_SOURCE \
          -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
          -fstack-clash-protection -fcf-protection \
          -Wformat -Werror=format-security \
          -DPLUGIN_VERSION=\"$(VERSION)\"
LDFLAGS = -Wl,-z,relro -Wl,-z,now

TARGET  = sudo_logger_plugin.so
SRC     = plugin.c

.PHONY: all install clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test: test_plugin.c $(SRC)
	$(CC) -Wall -Wextra -O0 -g -Iinclude -D_GNU_SOURCE test_plugin.c -o test_plugin -lpthread
	./test_plugin

install: $(TARGET)
	install -m 0755 $(TARGET) /usr/libexec/sudo/
	@echo "Add to /etc/sudo.conf:"
	@echo "  Plugin sudo_logger_plugin $(TARGET)"

clean:
	rm -f $(TARGET)

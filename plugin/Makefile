CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -fPIC -shared \
          -I/usr/include/sudo \
          -D_GNU_SOURCE

TARGET  = sudo_logger_plugin.so
SRC     = plugin.c

.PHONY: all install clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^

install: $(TARGET)
	install -m 0755 $(TARGET) /usr/libexec/sudo/
	@echo "Add to /etc/sudo.conf:"
	@echo "  Plugin sudo_logger_plugin $(TARGET)"

clean:
	rm -f $(TARGET)

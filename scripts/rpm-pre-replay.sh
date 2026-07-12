#!/bin/sh
# sudoreplay is a separate identity from sudologger (the log server's user)
# specifically so that a compromise of the replay server (the larger,
# browser-facing attack surface) cannot read the log server's ack-sign.key
# off disk via shared group membership.
getent group sudoreplay >/dev/null || groupadd -r sudoreplay
getent passwd sudoreplay >/dev/null || \
    useradd -r -g sudoreplay -s /sbin/nologin \
            -d /var/log/sudoreplay sudoreplay

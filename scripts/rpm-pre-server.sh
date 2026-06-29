#!/bin/sh
getent group sudologger >/dev/null || groupadd -r sudologger
getent passwd sudologger >/dev/null || \
    useradd -r -g sudologger -s /sbin/nologin \
            -d /var/log/sudoreplay sudologger

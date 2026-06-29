# Screencast script — sudo-logger demo

**Target length:** 60–90 seconds
**Tool options:**
- `vhs` (https://github.com/charmbracelet/vhs) — generates GIF/MP4 from a script file, no screen capture required
- `asciinema rec demo.cast` — interactive recording, embed as `[![asciicast](...)](asciinema.org/a/...)`
- `peek` / `Kooha` — screen recording to GIF on Linux desktop

**Recommended:** asciinema (zero install friction for viewers, supports pause/rewind)

---

## Scene 1 — Normal sudo session (15 s)

```
$ sudo -i
[sudo] password for alice:
root@server:~# cat /etc/shadow | head -3
root:$6$...
daemon:*:...
bin:*:...
root@server:~# exit
```

Show that the session appears immediately in the replay UI.

---

## Scene 2 — Replay in browser (20 s)

Cut to the replay-server at https://sudo-logger.unixkonsult.se (or localhost):

1. The session from scene 1 appears in the list with user, host, command, duration
2. Click it → terminal player opens
3. Scrub to show the `cat /etc/shadow` output
4. Point out the risk score badge (if the rule fires)

---

## Scene 3 — Freeze demo (30 s)

```
$ sudo bash
root@server:~# # (stop the log server now)
root@server:~# echo "still working?"
                    ← freeze banner appears here, ~800 ms after server stops
[sudo-logger] ⚠ Connection to log server lost. Terminal frozen.
              Press Ctrl+C to terminate this session.
^C
```

This is the memorable part. Keep it short.

---

## Scene 4 — Replay UI shows the incomplete session (10 s)

Back to the browser: the session from scene 3 has an amber ⏱ badge
and is marked "connection lost". The I/O up to the freeze point is
fully recorded and replayable.

---

## Adding to README

After recording, add to README.md immediately after the intro paragraphs
and before the Table of Contents:

```markdown
## Demo

[![asciicast](https://asciinema.org/a/YOUR_ID.svg)](https://asciinema.org/a/YOUR_ID)

_Scene: normal session recorded → session visible in replay UI → server
stopped → terminal freezes in ~800 ms._
```

Or for a GIF:

```markdown
![sudo-logger demo](docs/demo.gif)
```

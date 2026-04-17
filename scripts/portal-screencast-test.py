#!/usr/bin/env python3
"""
portal-screencast-test.py  —  testar XDG ScreenCast portal + PipeWire + GStreamer
Kör som vanlig användare (inte root).
Krav: python3-dbus  gstreamer1-plugins-good  gstreamer1-plugins-ugly (x264)
"""
import subprocess, signal
import dbus, dbus.mainloop.glib
from gi.repository import GLib

dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

BUS  = "org.freedesktop.portal.Desktop"
PATH = "/org/freedesktop/portal/desktop"
SC   = "org.freedesktop.portal.ScreenCast"
REQ  = "org.freedesktop.portal.Request"

bus  = dbus.SessionBus()
loop = GLib.MainLoop()
sc   = dbus.Interface(bus.get_object(BUS, PATH), SC)

_session = None
_seq     = 0

def tok():
    global _seq; _seq += 1; return f"sl{_seq}"

def on_response(handle, cb):
    def handler(code, results, **_):
        if code != 0:
            print(f"Avbruten eller fel (code={code})")
            loop.quit(); return
        cb(results)
    bus.add_signal_receiver(handler, "Response", REQ, path=handle)

# ── 1. Skapa session ──────────────────────────────────────────────────────────
def step1():
    h = sc.CreateSession(dbus.Dictionary(
        {"handle_token": tok(), "session_handle_token": tok()},
        signature="sv"))
    on_response(h, step2)

# ── 2. Välj källa — visar dialogrutan ────────────────────────────────────────
def step2(r):
    global _session
    _session = r["session_handle"]
    h = sc.SelectSources(_session, dbus.Dictionary({
        "handle_token": tok(),
        "types":       dbus.UInt32(1),     # 1=monitor, 2=fönster, 3=båda
        "multiple":    dbus.Boolean(False),
        "cursor_mode": dbus.UInt32(2),     # 2=cursor inbäddad i stream
    }, signature="sv"))
    on_response(h, step3)

# ── 3. Starta ─────────────────────────────────────────────────────────────────
def step3(_):
    h = sc.Start(_session, "", dbus.Dictionary(
        {"handle_token": tok()}, signature="sv"))
    on_response(h, step4)

# ── 4. Spela in ───────────────────────────────────────────────────────────────
def step4(r):
    streams = r.get("streams", [])
    if not streams:
        print("Inga streams från portalen."); loop.quit(); return

    node = int(streams[0][0])
    print(f"\n✓  PipeWire node ID: {node}")
    print(f"   Props: {dict(streams[0][1])}\n")

    # Testa encoders i tur och ordning
    jobs = [
        ("/tmp/portal-test.mp4",
         ["gst-launch-1.0", "-e",
          "pipewiresrc", f"path={node}",
          "!", "videoconvert",
          "!", "x264enc", "tune=zerolatency",
          "!", "mp4mux",
          "!", "filesink", "location=/tmp/portal-test.mp4"]),

        ("/tmp/portal-test.webm",
         ["gst-launch-1.0", "-e",
          "pipewiresrc", f"path={node}",
          "!", "videoconvert",
          "!", "vp8enc",
          "!", "webmmux",
          "!", "filesink", "location=/tmp/portal-test.webm"]),
    ]

    for outfile, cmd in jobs:
        print(f"Försöker encoder: {cmd[4]} …  (spelar in 10 s)")
        proc = subprocess.Popen(cmd)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.send_signal(signal.SIGINT)
            proc.wait()

        if proc.returncode in (0, -2, 130):
            print(f"\n✓  Sparad: {outfile}")
            print(f"   Spela:  mpv {outfile}")
            break
        print(f"   Misslyckades (exit {proc.returncode}), provar nästa …")
    else:
        print("Ingen encoder fungerade.")
        print("Installera: sudo dnf install gstreamer1-plugins-ugly")

    loop.quit()

# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("Begär skärminspelning via XDG Desktop Portal…")
    print("(En dialogruta ska dyka upp i din skärmsession)\n")
    step1()
    try:
        loop.run()
    except KeyboardInterrupt:
        loop.quit()

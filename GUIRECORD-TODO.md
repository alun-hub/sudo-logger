# GUI Screen Recording — TODO

## Vald approach: Wayland-proxy + pure Go frame capture

### Klientkrav
**Noll extra paket.** Allt som behövs:
- `libwayland-client` + `libwayland-server` — alltid installerat på Wayland-desktops
- sudo-logger-binären (statisk Go-binary, distribueras med paketet)

---

## Arkitektur

```
sudo gvim
  |
  +- plugin.c: lägger till WAYLAND_DISPLAY=/run/sudo-logger/<session>.sock
  |            i user_env[] innan exec()
  |
  +- gvim ansluter till vår proxy-socket
       |
       +- proxy (Go) vidarebefordrar allt Wayland-protokoll till riktiga
       |  kompositoren transparent -- gvim marker inget
       |
       +- proxy interceptar wl_surface_commit + laser wl_shm-buffert
            |
            +- Go image/jpeg encodar frame (noll externa beroenden)
            |
            +- skickar STREAM_SCREEN (0x05) chunks till server lopande
                 |
                 +- server: sparar frames
                      |
                      +- replay-server: JS-slideshow eller
                         server-side ffmpeg -> MP4 vid replay
```

### Varfor inte portal
- Portal kraver att anvandaren valjer inspelningskalla -- kan valjas bort
- Proxy spelar in exakt det sudo spawnande, inget annat
- Fungerar pa GNOME, KDE, alla Wayland-kompositorer
- Ingen PipeWire, ingen ffmpeg pa klienten

---

## Filer att skapa/andra

| Fil | Andring |
|-----|---------|
| `plugin/plugin.c` | Injicera WAYLAND_DISPLAY i user_env[] vid GUI-session |
| `go/cmd/wayland-proxy/main.go` | NY: Wayland-proxy, interceptar wl_surface_commit |
| `go/internal/protocol/protocol.go` | STREAM_SCREEN = 0x05 |
| `go/cmd/shipper/main.go` | Spawna proxy vid tty_path=="", vidarebefordra frames |
| `go/cmd/server/` | Ta emot + lagra STREAM_SCREEN-frames |
| `go/cmd/replay-server/main.go` | JS-slideshow for STREAM_SCREEN-sessioner |
| `go/go.mod` | github.com/rajveermalviya/go-wayland |

---

## Wayland-protokoll att implementera i proxyn

Maste proxas transparent (pass-through):
- wl_display, wl_registry
- wl_compositor, wl_surface  (intercepta commit har)
- wl_shm, wl_shm_pool, wl_buffer  (las pixeldata har)
- xdg_wm_base, xdg_surface, xdg_toplevel
- wl_seat, wl_keyboard, wl_pointer (pass-through)

SHM-buffertar (delat minne) ar enklast -- las direkt via mmap.
DMA-buf (GPU-minne) -- skippa i forsta versionen, logga varning.

---

## Frame-kodning (pure Go)

Per wl_surface_commit:
1. Las wl_shm-buffert ([]uint32 ARGB) som image.RGBA
2. Encoda med image/jpeg, kvalitet 75
3. Skicka som STREAM_SCREEN chunk via befintligt protokoll

Kvalitet 75 JPEG ca 50-150 KB/frame. Vid 1 fps ca 5 MB/min.
Server-side ffmpeg kan konvertera frames till MP4 vid replay.

---

## Testat och verifierat (portal-approachen)
- scripts/portal-screencast-test.py -- fungerar pa GNOME/KDE Wayland
- Portal-approachen overlaten pa grund av att anvandaren kan valja fel kalla

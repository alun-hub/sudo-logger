---
Fas 1: Kodgenomgång — Rapport

1. Arkitekturöversikt

Systemet består av fem komponenter:

sudo C-plugin → [Unix socket] → shipper → [TLS/mTLS] → log-server → logDir/
↓
replay-server (HTTP)
↓ SIEM

Dataflöde: Plugin → Shipper (local daemon) → Log-server (remote TLS) → Cast-filer (local/S3) + PostgreSQL metadata
→ Replay-server (browser)

Arkitekturen är genomtänkt och väl separerad. Abstractions är rena (SessionStore, SessionWriter). Nedanstående
fynd är förbättringsförslag, inte kritik av grunddesignen.

---
2. Buggar

B1 — TSID-kollision vid samtida sessioner (båda backends)

Fil: store/distributed.go:194, store/local.go:73

DistributedStore.CreateSession bygger TSID som user/host_YYYYMMDD-HHMMSS. Startar samma användare två sessioner på
samma host inom samma sekund → identisk TSID. I distributed-backend gör ON CONFLICT (tsid) DO NOTHING att den
andra sessionens metadata tappas tyst. I local-backend skriver iolog.NewWriter till samma katalog och trunkerar
cast-filen.

Förslag: Lägg till nanosekunder eller ett kort random-suffix i TSID (t.ex. user/host_20260413-120000-3f7a).
Namnrymden är redan säker för URL-transport.

---
B2 — S3-upload utan konkurrensbegränsning

Fil: store/distributed.go:726

go dw.uploadToS3()

Close() anropas från server-goroutinen. Vid en burst av avslutade sessioner (t.ex. återstart av klienter) spawnas
godtyckligt många goroutiner parallellt mot S3. Inga semaforer, ingen backpressure.

Förslag: Begränsa med en buffrad kanal eller golang.org/x/sync/semaphore (t.ex. max 8 parallella uppladdningar).

---
B3 — lingerCgroup öppnar ny TLS-anslutning var 2:a sekund

Fil: shipper/main.go:619-641

serverReachable() i lingering-goroutinen gör en komplett TLS-handskakning var pollInterval = 2s för att
kontrollera om servern är nåbar. Det är dyrt och upplevs som misstänkt nätverkstrafik på servern (en ny anslutning
som avslutas direkt utan att skicka SESSION_START). Servern loggar inget om detta men det är onödigt.

Förslag: En TCP-anslutning utan TLS-handskakning räcker för reachability-check. Eller öka pollInterval till 10s.

---
B4 — iolog.Writer saknar fsync

Fil: iolog/iolog.go

Cast-filen stängs med castF.Close() men utan föregående castF.Sync(). Vid kernel-krasch eller strömavbrott kan de
sista sekunderna av en session gå förlorade. För ett säkerhetsloggningssystem är detta en tydlig lucka.

Förslag: Lägg till w.castF.Sync() i Close() innan castF.Close().

---
B5 — GetConfig i DistributedStore använder Query istället för QueryRow

Fil: store/distributed.go:529-541

Manuell rows.Next()-loop för en fråga som returnerar max en rad. Ingen funktionell bugg, men om rows.Err()
returnerar ett fel efter att rows.Next() returnerat false (nätverksavbrott mitt i svar) ignoreras det i praktiken
eftersom return "", rows.Err() körs. Med QueryRow hade detta hanterats automatiskt och korrekt.

Förslag: Byt till d.db.QueryRow(...).Scan(&value) med pgx.ErrNoRows-hantering.

---
B6 — sessionCache.rebuild håller skrivlåset under I/O och scoring

Fil: replay-server/main.go:397-428

func (c *sessionCache) rebuild(ctx context.Context) ([]SessionInfo, error) {
c.mu.Lock()
defer c.mu.Unlock()
// ... läser DB, läser cast-filer, gör risk-scoring

Hela rebuild-operationen sker under sync.Mutex (inte RWMutex). Alla läsare (HTTP-requests till /api/sessions)
blockeras under rebuild. Vid 1000+ sessioner med content-scanning kan detta ta flera sekunder.

Förslag: Bygg listan utanför låset, byt sen under låset atomärt. Alternativt: använd sync/atomic med en pointer
till snapshoten.

---
3. Säkerhet

S1 — API saknar validering av YAML-content vid PUT /api/rules och /api/siem-config

Fil: replay-server/main.go (handlePutRules, handlePutSiemConfig)

En autentiserad GUI-användare kan skriva godtycklig YAML till risk-rules.yaml och siem.yaml, inklusive godtyckliga
sökvägar (t.ex. cert: /etc/passwd). Det finns ingen content-validering utöver YAML-parsning.

Risk: Medium — kräver autentisering, men en komprometterad GUI-session ger skrivrättigheter till
SIEM-konfigurationen inkl. cert-sökvägar.

Förslag: Validera att YAML kan parsas till respektive struct (RuleSet, Config) och avvisa requests med okända
fält.

---
S2 — TLS 1.2 i SIEM-klient vs TLS 1.3 överallt annars

Fil: siem/sender.go:216

cfg := &tls.Config{MinVersion: tls.VersionTLS12}

Shipper och log-server kräver TLS 1.3. SIEM-klienten accepterar TLS 1.2. Inkonsekvent säkerhetspolicy.

Förslag: Höj till tls.VersionTLS13 om SIEM-mottagarna stöder det, annars dokumentera varför 1.2 behövs.

---
S3 — SIEM-klienten skapar ny http.Client per event (ingen connection pool)

Fil: siem/sender.go:93-96

client := &http.Client{
Transport: &http.Transport{TLSClientConfig: tlsCfg},
Timeout:   5 * time.Second,
}

Ny http.Transport per event → ingen TCP/TLS connection reuse → en ny handskakning per session → tidsfördröjning
och resursslöseri. Vid hög sessionstakt kan detta bli en flaskhals.

Förslag: Cachet en *http.Client per unik TLSCfg-kombination (paketscoped sync.Map eller liknande).

---
S4 — maxPayloadSize 1 MB gäller även SESSION_START JSON

Fil: protocol/protocol.go:138

En autentiserad (mTLS) men komprometterad shipper kan skicka ett SESSION_START med 1 MB JSON. Log-servern
allokerar 1 MB per godkänd anslutning. Inte en kritisk bugg men en DoS-vektor mot minnet.

Förslag: Lägg till typspecifika gränser: SESSION_START ≤ 64 KB, CHUNK ≤ 1 MB (nuvarande gäller chunkar).

---
4. Kodkvalitet och förenklingar

K1 — riskLevel() är duplicerad

Fil: store/local.go:768-779, replay-server/main.go (separat impl)

Samma funktion med identiska thresholds finns i två filer. En logisk förändring av riskgränser måste göras på två
ställen.

Förslag: Flytta till internal/store/store.go som exporterad funktion.

---
K2 — reportSessionFreezing och reportSessionAbandon delar 90% av koden

Fil: shipper/main.go:657-743

Båda funktionerna bygger TLS-anslutning, hanterar ServerName, sätter deadline, skriver ett meddelande. Enda
skillnaden är message type och dial timeout.

Förslag: Extrahera en privat reportSessionMsg(server string, cfg *tls.Config, msgType uint8, payload []byte,
timeout time.Duration) error.

---
K3 — goto i WatchSessions

Fil: store/distributed.go:404-408

goto acquired

Onödigt goto i en retry-loop. Gör koden svårare att följa.

Förslag: Omstrukturera till en for-loop med explicit break eller extrahera lock-acquisition till en hjälpfunktion.

---
K4 — Flagga-definitioner duplicerade mellan server och replay-server

Fil: cmd/server/main.go:63-75, cmd/replay-server/main.go:66-76

Identiska S3/DB-flagga-definitioner med identiska defaults i två binärer. Vid default-ändring måste båda
uppdateras.

Förslag: Extrahera till internal/config/flags.go eller dokumentera explicit att de är synkroniserade.

---
K5 — trackDescendants pollar /proc var 10ms

Fil: shipper/cgroup.go:202

10ms polling-intervall per session × N parallella sessioner → N × 100 /proc-läsningar per sekund. Med 50 aktiva
sessioner är det 5000 systemanrop/s bara för cgroup-tracking.

Förslag: Öka till 50-100ms. Cgroup-freeze-latensen är fortfarande under heartbeat-fönstret (800ms).

---
K6 — applySchema körs vid varje uppstart

Fil: store/distributed.go:116-177

DDL-queries (CREATE TABLE IF NOT EXISTS, ALTER TABLE ADD COLUMN IF NOT EXISTS) körs vid varje start mot
PostgreSQL. Idempotent men onödigt vid production-drift.

Förslag: Versionshantera schema med en migrations-tabell (lägg till schema_version-rad, skippa migration om
version stämmer).

---
5. Saknad testcoverage

┌───────────────────┬───────────────────────┬─────────────────────────────────────────────────────────────────┐
│     Komponent     │         Täckt         │                             Saknas                              │
├───────────────────┼───────────────────────┼─────────────────────────────────────────────────────────────────┤
│ protocol          │ Delvis (test-fil      │ Protocol round-trip, felfall för korta payloads                 │
│                   │ finns)                │                                                                 │
├───────────────────┼───────────────────────┼─────────────────────────────────────────────────────────────────┤
│ iolog             │ Ja (iolog_test.go)    │ Concurrent writes, fsync-beteende                               │
├───────────────────┼───────────────────────┼─────────────────────────────────────────────────────────────────┤
│ store/local       │ Bra                   │ WatchSessions (kräver fsnotify), GetBlockedPolicy,              │
│                   │                       │ SaveBlockedPolicy                                               │
├───────────────────┼───────────────────────┼─────────────────────────────────────────────────────────────────┤
│ store/distributed │ Saknas                │ Hela paketet (kräver Postgres + S3, men testbara med            │
│                   │                       │ testcontainers)                                                 │
├───────────────────┼───────────────────────┼─────────────────────────────────────────────────────────────────┤
│ shipper/main      │ Delvis                │ handlePluginConn integration, lingerCgroup, freeze-timeout      │
├───────────────────┼───────────────────────┼─────────────────────────────────────────────────────────────────┤
│ shipper/cgroup    │ Saknas                │ trackDescendants, freeze/unfreeze, escape-logik (kräver root,   │
│                   │                       │ men mockbar)                                                    │
├───────────────────┼───────────────────────┼─────────────────────────────────────────────────────────────────┤
│ server/main       │ Saknas helt           │ Session open/close, cert-host-matching, block-policy,           │
│                   │                       │ ACK-signering                                                   │
├───────────────────┼───────────────────────┼─────────────────────────────────────────────────────────────────┤
│ replay-server     │ Delvis (auth)         │ Session list/filter/scoring, SIEM-forwarding, cache rebuild,    │
│                   │                       │ report API                                                      │
├───────────────────┼───────────────────────┼─────────────────────────────────────────────────────────────────┤
│ siem              │ Saknas helt           │ HTTPS-transport, syslog-format, CEF/OCSF-encoding               │
└───────────────────┴───────────────────────┴─────────────────────────────────────────────────────────────────┘

---
6. Dependency-flaggor

github.com/aws/aws-sdk-go-v2          → Check for CVEs (aktiv uppdateringstakt)
github.com/jackc/pgx/v5               → v5.7+ rekommenderas (pool-fixes)
github.com/fsnotify/fsnotify          → Kontrollera senaste version
golang.org/x/crypto (bcrypt)          → Håll uppdaterad (säkerhetskritisk)

Inga kända HIGH/CRITICAL CVEs identifierade i koden som sådan, men dependency-versioner bör granskas med go list
-m -u all och govulncheck.

---
Sammanfattning: prioritetsordning för åtgärder

┌────────────┬─────────────────────────────────────────────────────────────────────────────────────────────┐
│ Prioritet  │                                            Fynd                                             │
├────────────┼─────────────────────────────────────────────────────────────────────────────────────────────┤
│ Hög        │ B4 (fsync), S1 (YAML-validering), B1 (TSID-kollision), B2 (S3-backpressure)                 │
├────────────┼─────────────────────────────────────────────────────────────────────────────────────────────┤
│ Medium     │ B6 (cache lock), S3 (SIEM HTTP client), K1 (riskLevel-duplicering), K2 (report*-funktioner) │
├────────────┼─────────────────────────────────────────────────────────────────────────────────────────────┤
│ Låg        │ B3 (lingerCgroup TLS), S2 (TLS 1.2), K3 (goto), K5 (cgroup polling)                         │
├────────────┼─────────────────────────────────────────────────────────────────────────────────────────────┤
│ Arkitektur │ B1 (diskutera TSID-format), K4 (flag-duplicering), K6 (schema-migrations)                   │
└────────────┴─────────────────────────────────────────────────────────────────────────────────────────────┘

---

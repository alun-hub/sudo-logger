# Installationsguide för sudo-logger

Denna guide beskriver hur du installerar och konfigurerar `sudo-logger` i två olika scenarier: **Local Storage** (enkel installation på en maskin) och **Distributed Storage** (skalbar installation med Kubernetes, PostgreSQL och S3).

---

## Arkitekturöversikt

1.  **Sudo Plugin (`sudo_logger_plugin.so`)**: Laddas av `sudo` för att skicka data till agenten.
2.  **Agent (`sudo-logger-agent`)**: En lokal tjänst som spelar in sessionen (via eBPF) och streamar den till servern.
3.  **Logserver (`sudo-logserver`)**: Tar emot strömmar och lagrar dem i filsystemet eller S3/DB.
4.  **Replay Server (`sudo-replay-server`)**: Webbgränssnitt för att titta på inspelningar och hantera JIT-godkännanden.

---

## 1. Förutsättningar

*   **OS:** Linux (rekommenderat Fedora/RHEL eller Ubuntu).
*   **Sudo:** Version 1.9.0 eller senare.
*   **Kärna:** 5.8+ (för eBPF-stöd).
*   **Certifikat:** TLS-certifikat krävs för kryptering mellan Agent -> Logserver.

---

## 2. Scenario: Local Storage (Enkel maskin)

Används för mindre miljöer eller test. All data lagras lokalt på logservern.

### A. Installera Logserver & Replay
Installera RPM-paketen på servern:
```bash
rpm -ivh sudo-logger-server-*.rpm sudo-logger-replay-*.rpm
```

Konfigurera `/etc/sudo-logger/server.conf`:
```yaml
# Lagringstyp
storage: local
logdir: /var/log/sudoreplay

# JIT Approval inställningar
approval_policy: /etc/sudo-logger/approval-policy.yaml
```

Starta tjänsterna:
```bash
systemctl enable --now sudo-logserver sudo-replay
```

### B. Installera Agent & Plugin på klienten
Installera RPM:
```bash
rpm -ivh sudo-logger-client-*.rpm
```

Konfigurera `/etc/sudo-logger/agent.conf`:
```yaml
server_address: "din-server.internal:9876"
tls_ca: /etc/sudo-logger/certs/ca.crt
tls_cert: /etc/sudo-logger/certs/client.crt
tls_key: /etc/sudo-logger/certs/client.key
```

Aktivera plugin i `/etc/sudo.conf`:
```conf
Plugin sudo_logger_plugin /usr/lib64/sudo-logger/sudo_logger_plugin.so
```

---

## 3. Scenario: Distributed Storage (Kubernetes/Scalable)

Används i produktion. Sessioner lagras i S3 (Minio/AWS) och metadata i PostgreSQL.

### A. Förbered Databas & S3
1.  **PostgreSQL:** Skapa databasen `sudologger`.
2.  **S3:** Skapa en bucket (t.ex. `sudo-logs`).

### B. Deployment i Kubernetes (Helt automatiserad)
För att köra `sudo-logger` skalbart används Kubernetes. Det finns färdiga manifest i mappen `/k8s`.

#### 1. Förbered TLS-certifikat
Logservern kräver mTLS för att ta emot sessioner. Du behöver följande filer i en mapp (t.ex. `./pki`):
*   `ca.crt` (Root CA)
*   `server.crt` & `server.key` (Serverns certifikat)
*   `ack-sign.key` (Nyckel för att signera kvitto till agenten)

#### 2. Kör deploy-skriptet
Det enklaste sättet att deploya är att använda det medföljande bash-skriptet som skapar namespace, hemligheter och startar alla tjänster:

```bash
cd k8s
# Ange valfri docker-image (standard är ghcr.io/alun-hub/sudo-logserver:latest)
./deploy-local.sh --image din-repo/sudo-logserver:1.20.94
```

Skriptet utför följande steg automatiskt:
1.  Skapar namespace `sudo-logger`.
2.  Skapar Kubernetes Secrets (`sudo-logger-tls` och `sudo-logger-distributed`) från dina certifikat och miljövariabler.
3.  Deployar **PostgreSQL** (metadata) och **MinIO** (S3-lagring).
4.  Startar **sudo-logserver** i distribuerat läge.
5.  Startar **sudo-replay-server** (UI).

#### 3. Manuella steg (vid behov)
Om du vill deploya manuellt utan skriptet, se till att:
1.  Skapa secrets för databas-lösenord och S3-nycklar.
2.  Applicera manifesten i ordning:
    ```bash
    kubectl apply -f k8s/namespace.yaml
    kubectl apply -f k8s/postgresql.yaml
    kubectl apply -f k8s/minio.yaml
    kubectl apply -f k8s/service.yaml
    kubectl apply -f k8s/deployment-distributed.yaml
    kubectl apply -f k8s/replay-server.yaml
    ```

#### 4. Åtkomst
Efter lyckad deployment når du tjänsterna via din Node-IP:
*   **Replay UI:** `http://<NODE_IP>:30080`
*   **Logserver (för agenter):** `<NODE_IP>:9876` (Använder mTLS)

---

### C. JIT Approval via UI (Rekommenderat)
I distribuerat läge lagras inställningarna i databasen så att alla noder ser dem.
1.  Logga in i **Replay UI**.
2.  Gå till **Settings -> JIT Approval**.
3.  Aktivera (Enabled) och fyll i Webhook-URL till Mattermost/Slack.
4.  Klicka **Save**.

---

## 4. Konfigurera JIT Approval (Policy)

Om du inte använder UI:t kan du editera YAML-filen manuellt.

Exempel på `/etc/sudo-logger/approval-policy.yaml`:
```yaml
enabled: true
default_window: 30m
exempt:
  - user: root       # Root behöver inte godkännande
notifications:
  webhook_url: "http://mattermost:8065/hooks/xxxx"
  mention_user: true
```

---

## 5. Verifiering

1.  **Testa Sudo:** Kör `sudo -i` på en klient.
2.  **Utmaning:** Om JIT är på, ska du få frågan: `Sudo authorization required. Please provide justification:`.
3.  **Godkänn:** Godkänn förfrågan i Replay UI eller via Webhook-länken.
4.  **Kör:** När du är godkänd, kör kommandot igen. Det ska nu fungera direkt utan fråga.
5.  **Titta:** Gå till Replay UI och verifiera att inspelningen dyker upp och går att spela upp.

---

## Felsökning

*   **Ingen kontakt:** Kontrollera `systemctl status sudo-logger-agent`. Se till att logserverns IP är nåbar.
*   **Certifikatfel:** Om agenten klagar på TLS, verifiera att serverns certifikat har rätt SAN (Subject Alternative Name).
*   **Read-only filesystem:** I Kubernetes, se till att du använder UI:t för att spara inställningar så att de hamnar i databasen istället för i den monterade (skrivskyddade) ConfigMappen.

# sudo-logger Helm Chart

This chart installs the sudo-logger central log server and replay server.

## Prerequisites

- Kubernetes 1.19+
- Helm 3.2.0+
- (Optional) Ingress controller if exposing the replay server externally

## Installation

### Local Storage (Default)

By default, the chart uses a single PersistentVolumeClaim for session storage. This is suitable for small installations.

```bash
helm install sudo-logger ./charts/sudo-logger
```

### Distributed Storage

For high availability and scalability, you can use PostgreSQL and S3-compatible storage (like MinIO).

```bash
helm install sudo-logger ./charts/sudo-logger \
  --set storage.type=distributed \
  --set postgresql.enabled=true \
  --set minio.enabled=true
```

## Configuration

The following table lists the configurable parameters of the sudo-logger chart and their default values.

| Parameter | Description | Default |
| --- | --- | --- |
| `replicaCount` | Number of logserver replicas | `1` |
| `image.repository` | Logserver image repository | `ghcr.io/alun-hub/sudo-logserver` |
| `image.tag` | Logserver image tag | `1.0` |
| `storage.type` | Storage type (`local` or `distributed`) | `local` |
| `storage.local.size` | PVC size for local storage | `10Gi` |
| `tls.mode` | TLS mode (`self-signed`, `provided`, `cert-manager`) | `self-signed` |
| `postgresql.enabled` | Enable bundled PostgreSQL | `false` |
| `minio.enabled` | Enable bundled MinIO | `false` |
| `replay.replicaCount` | Number of replay-server replicas | `1` |
| `ingress.enabled` | Enable ingress for replay-server | `false` |

Refer to [values.yaml](values.yaml) for full configuration details.

## Uninstallation

To uninstall/delete the `sudo-logger` deployment:

```bash
helm uninstall sudo-logger
```

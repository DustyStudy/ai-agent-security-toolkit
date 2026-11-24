# Audit log in Grafana Loki (small staging host)

Keeps the gateway's audit log searchable in Loki for 30 days. Tried on the staging t3.small
(2 vCPU, 1.9 GB RAM, no swap at first) beside Keycloak, the gateway and Caddy on 2026-11-24.

The gateway's `audit.siem` export can't send to Loki directly: it posts raw JSON or CEF records,
not Loki's push format. Grafana Alloy tails `audit.jsonl` read-only and pushes it instead. The
local file stays the source of truth: keep running `agentsec audit verify` on it.

## Setup

1. Add 1 GB of swap so a Keycloak JVM spike doesn't OOM-kill anything:

   ```bash
   sudo fallocate -l 1G /swapfile && sudo chmod 600 /swapfile
   sudo mkswap /swapfile && sudo swapon /swapfile
   echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
   ```

2. Create the data folders for the containers' non-root user:

   ```bash
   sudo install -d -o 10001 -g 10001 /opt/loki/data /opt/alloy/data
   ```

3. Check the audit file path in `compose.yaml` matches `audit.file` in your gateway config,
   then `docker compose up -d`. Neither container publishes a port.

## Check

```bash
docker compose exec loki wget -qO- http://localhost:3100/ready      # "ready"
# Count of records Loki holds; compare with `wc -l audit.jsonl`:
docker compose exec loki wget -qO- 'http://localhost:3100/loki/api/v1/query' \
  --post-data 'query=sum(count_over_time({job="agentsec-audit"}[3d]))'
docker stats --no-stream; free -m
```

## What staging showed

| | Memory |
| --- | --- |
| Available before Loki | 987 MB |
| Loki (cap 384 MB) | 91 to 150 MB |
| Alloy (cap 96 MB) | 36 to 38 MB |
| Available with both, after a SAML test | 784 MB, 46 MB swap used |

No container was OOM-killed. All 232 audit records reached Loki, and no token, password or
SCIM secret appeared in it (the gateway writes fingerprints, not values). If Keycloak grows,
move to a t3.medium rather than raising Loki's cap.

# IPFIX Monitoring Stack

A self-contained Docker Compose stack for collecting, enriching and analyzing network traffic from IPFIX/NetFlow exports.

```
Router / switch (IPFIX export, UDP 4739)          ┐
            or                                    ├─→ ipfixcol2 ─→ ClickHouse ─→ Grafana
Built-in synthetic traffic generator (demo mode)  ┘   (collector)  (storage +    (dashboards)
                                                                    enrichment)
```

- **ipfixcol2** (CESNET) receives IPFIX over UDP and writes flow records to ClickHouse through its ClickHouse output plugin.
- **ClickHouse** stores the flows. A materialized view enriches every record at insert time (protocol names, traffic direction, QoS priority, ECN, readable TCP flags).
- **Grafana** visualizes them. The ClickHouse datasource and a first dashboard are provisioned from the repository, so they are there on the first start.
- An optional **synthetic IPFIX generator** produces realistic demo traffic, so the whole stack can be tried without a real exporter.

Everything runs on a single host (tested on Debian 12 with 4 vCPU, 16 GB RAM and a 50 GB disk).

> **Want it deployed or extended for your network?** This repository is the free, self-service edition. I also deploy the stack and build extensions to order, see [Custom deployment and support](#custom-deployment-and-support).

**Contents:** [Quick start](#quick-start) · [Services](#services) · [Repository layout](#repository-layout) · [Configuration](#configuration) · [Data model and enrichment](#data-model-and-enrichment) · [Demo mode](#demo-mode) · [Connecting a real exporter](#connecting-a-real-exporter) · [Grafana](#grafana) · [Verifying that data flows](#verifying-that-data-flows) · [Disk usage and housekeeping](#disk-usage-and-housekeeping) · [Security notes](#security-notes) · [Limitations](#limitations) · [Custom deployment and support](#custom-deployment-and-support) · [Troubleshooting](#troubleshooting) · [Operations cheat sheet](#operations-cheat-sheet)

---

## Quick start

Requirements: Docker Engine with Docker Compose v2. The first start needs internet access (source build, Grafana plugin download).

```bash
git clone https://github.com/danhanuska/ipfix-monitoring-stack.git net-monitor
cd net-monitor

cp .env.example .env
chmod 600 .env                # the file holds both passwords
openssl rand -hex 24          # paste the output as CLICKHOUSE_PASSWORD in .env
openssl rand -hex 24          # paste the output as GRAFANA_ADMIN_PASSWORD in .env
```

Then pick one of the two modes:

```bash
# A) "I just want to try it" – starts the stack plus the synthetic traffic generator
docker compose --profile demo up -d --build

# B) "I have a real exporter" – starts the stack only
docker compose up -d --build
```

The first build takes several minutes, because `ipfixcol2`, `libfds` and the ClickHouse output plugin are compiled from source. Later starts are instant.

```bash
docker compose ps             # clickhouse should be "healthy", the rest "Up"
```

Then open Grafana at <http://localhost:3000> (on a remote host through an SSH tunnel, see [Grafana](#grafana)) and log in as `admin` with the `GRAFANA_ADMIN_PASSWORD` you set. The ClickHouse datasource and the *Network Security Overview* dashboard are already there.

> Do not run demo mode on an instance that also receives real traffic. Both sources write into the same table and cannot be cleanly separated afterwards.

---

## Services

| Service | Image | Purpose | Profile |
|---|---|---|---|
| `permissions` | `busybox:1.38.0` | One-shot init container. Makes sure `data/clickhouse` (UID 101) and `data/grafana` (UID 472) are owned by the right users, then exits. | always |
| `clickhouse` | `clickhouse/clickhouse-server:23.8` | Flow storage and enrichment. Pinned to 23.8, see [Troubleshooting](#clickhouse-crashes-with-illegal-instruction). | always |
| `ipfixcol2` | built locally (`net-monitor-ipfixcol2`) | IPFIX collector with the ClickHouse output plugin, built from pinned upstream sources. Listens on UDP `4739`. | always |
| `grafana` | `grafana/grafana:13.2.1` | Dashboards, with the ClickHouse datasource plugin (pinned to `4.22.1`) installed at start. Published on `127.0.0.1:3000` only. | always |
| `ipfix-generator` | `python:3.12-alpine` | Synthetic IPFIX traffic for demos. | `demo` |
| `schema-helper` | same image as `ipfixcol2` | Discovers which IPFIX fields a real exporter sends. | `setup` |

Startup order is enforced with `depends_on`: `permissions` must complete successfully, then `clickhouse` must be **healthy**, and only then do `ipfixcol2` and `grafana` start. ClickHouse counts as healthy once its HTTP `/ping` endpoint answers, which needs no credentials.

**Pinned versions.** The collector sources are pinned in the inline Dockerfile in `docker-compose.yml`: `libfds` to the commit of its tag `v0.6.0` and `ipfixcol2` to a fixed commit, because the ClickHouse output plugin is not part of any tagged ipfixcol2 release yet. To move to a newer collector, change them there and run `docker compose build ipfixcol2`. Grafana is pinned through its image tag and the plugin through `GF_PLUGINS_PREINSTALL_SYNC=grafana-clickhouse-datasource@<version>`. To upgrade, change either value and run `docker compose up -d grafana`. Do not downgrade Grafana over an existing `data/grafana`.

---

## Repository layout

```
.
├── docker-compose.yml                  # all services; the ipfixcol2 Dockerfile is inline
├── .env.example                        # template for .env (secrets, demo tuning)
├── configs/
│   ├── clickhouse/
│   │   ├── init_tables.sql             # database, tables, dictionaries, materialized view
│   │   └── config.d/
│   │       └── system_logs.xml         # retention (TTL) for ClickHouse system log tables
│   ├── ipfixcol2/
│   │   └── startup.xml.tpl             # collector config template (password injected at start)
│   └── grafana/provisioning/
│       ├── datasources/                # ClickHouse datasource (created at Grafana start)
│       └── dashboards/
│           ├── dashboards.yml          # dashboard provider: where Grafana looks for JSON files
│           └── network-security-overview.json
├── scripts/
│   ├── ipfix-generator/
│   │   └── ipfix_generator.py          # synthetic IPFIX generator (demo mode)
│   └── generated-configs/              # output of schema-helper (review by hand)
└── data/                               # runtime data – never commit (git-ignored)
    ├── clickhouse/
    └── grafana/
```

---

## Configuration

All secrets and tunables live in `.env` (git-ignored). `.env.example` is the committed template.

| Variable | Required | Default | Description |
|---|---|---|---|
| `CLICKHOUSE_PASSWORD` | yes | – | Password for the ClickHouse `default` user. Used by ClickHouse itself, injected into the ipfixcol2 config at startup and passed to Grafana for its datasource. |
| `GRAFANA_ADMIN_PASSWORD` | yes | – | Password of the Grafana `admin` user. Applied on every start of the Grafana container, see [Admin password](#admin-password). |
| `DEMO_SESSIONS_PER_SEC` | no | `5` | Average number of synthetic sessions per second at peak (demo mode). One session is typically 2 flows. |
| `DEMO_IPV6_RATIO` | no | `0.15` | Share of IPv6 traffic in demo mode (0–1). |
| `DEMO_INCIDENT_INTERVAL_MIN` | no | `20` | Average minutes between simulated security incidents in demo mode; `0` turns them off. |

Compose refuses to start if a required variable is missing. Generate both passwords as hex (`openssl rand -hex 24`): hex contains no characters that could break XML, shell quoting, URLs or the variable substitution in `docker-compose.yml`.

ipfixcol2 cannot expand environment variables in its XML config, so the config is kept as a template (`configs/ipfixcol2/startup.xml.tpl`) containing `<password>${CLICKHOUSE_PASSWORD}</password>`. The container entrypoint renders it with `envsubst` at start. The rendered file exists only inside the running container; the password is never written to the repository or baked into the image.

---

## Data model and enrichment

```
ipfixcol2 ──INSERT──▶ flows_raw (ENGINE = Null) ──▶ flows_mv (materialized view) ──▶ flows (MergeTree)
                        nothing is stored here        enrichment happens here         what you query
```

### `flows_raw`
The landing table for ipfixcol2. Its columns must match the `<columns>` block in `startup.xml.tpl` exactly. It uses the `Null` engine: rows are not stored, they only trigger the materialized view.

### `flows_mv`
Transforms each inserted row and writes it into `flows`:

| Output column | Derived from | Meaning |
|---|---|---|
| `device` | constant | Exporter label, a constant set in the view. Change it there to name your exporter. |
| `tcpflags_str` | `tcpflags` | Readable flags, e.g. `. ACK PSH . SYN FIN`. Empty for non-TCP flows. |
| `flowstart`, `flowend` | nanosecond timestamps | Truncated to `DateTime` (second precision). |
| `priority` | `ipClassOfService >> 5` | IP precedence name (`Best Effort` … `Network Control`) via `priority_dict`. |
| `ecn` | `ipClassOfService & 3` | ECN state via `ecn_dict`. |
| `protocol_name` | `protocol` | IANA protocol name (TCP, UDP, ICMP, ICMPv6, …) via `protocol_dict`. |
| `direction` | source/destination address | `Internal`, `Outbound`, `Inbound` or `External`. |
| `is_internal` | same | `1` when both ends are local. |

"Local" means RFC 1918 private ranges, link-local, loopback, multicast, broadcast, IPv6 ULA (`fc00::/7`), IPv6 link-local and multicast. All addresses are stored as `IPv6`; IPv4 is kept in IPv4-mapped form (`::ffff:a.b.c.d`).

### `flows`
- `MergeTree`, partitioned by month (`toYYYYMM(flowstart)`), ordered by `(flowstart, device, srcip, dstip)`.
- **Retention:** `TTL flowstart + INTERVAL 3 MONTH` with `ttl_only_drop_parts = 1`, so ClickHouse drops whole data parts instead of rewriting them. Because the table is partitioned by month, a month of data disappears at once and the effective retention is 3 to 4 months.
- Projection `p_ip_analysis` keeps a copy sorted by `(srcip, dstip, flowstart)`, which speeds up per-IP queries at the cost of extra disk space.

### Dictionaries
`protocol_dict`, `priority_dict` and `ecn_dict` are loaded from the `*_source` tables. ClickHouse reads them through the dedicated `dict_reader` user, which has no password but is restricted to `HOST LOCAL` and to `SELECT` on those three tables only.

### The init script runs only once
`init_tables.sql` is mounted into `/docker-entrypoint-initdb.d/` and runs automatically **only when `data/clickhouse` is empty**, i.e. on the very first start. Later edits to the file do not reach an existing instance on their own.

The script is safe to run again by hand. Every object is created with `IF NOT EXISTS`, and the lookup tables behind the dictionaries are emptied and refilled, so a re-run adds whatever is new without duplicating anything:

```bash
docker exec -i clickhouse sh -c 'clickhouse-client -n --password "$CLICKHOUSE_PASSWORD"' < configs/clickhouse/init_tables.sql
```

A re-run does **not** change objects that already exist. If you edit the definition of an existing table or of `flows_mv`, apply it manually (`ALTER TABLE …`, or drop and recreate the view). If the data is disposable, you can instead stop the stack, empty `data/clickhouse` and start again.

---

## Demo mode

```bash
docker compose --profile demo up -d
docker compose logs -f ipfix-generator
```

Expected log output:

```
[generator] start: 5.0 sessions/s at peak, IPv6 15%, diurnal pattern on, incidents every ~20 min
[generator] sending IPFIX to 172.18.0.3:4739 (ODID 1)
[generator] sent 1234 flows / 60 messages total, current rate 11.2 flows/s (load 97%)
```

Data appears in ClickHouse within about 10–15 seconds, which is the ipfixcol2 insert batching delay.

### What it generates
`scripts/ipfix-generator/ipfix_generator.py` uses only the Python standard library. It models a small company network:

- **VLAN 10** clients, **VLAN 20** internal servers (DNS, file server, mail), **VLAN 30** IoT devices, **VLAN 50** DMZ with a public web server, in IPv4 and IPv6 (dual-stack).
- **Traffic mix:** HTTPS, QUIC, HTTP, internal and upstream DNS, NTP, SMB, admin SSH, inbound and outbound SMTP, inbound web traffic to the DMZ, VoIP (SIP signalling marked CS3, RTP media marked EF), port scans from the internet, ping (ICMP/ICMPv6) and IoT MQTT to cloud endpoints.
- **Realistic shape:** a few popular servers and heavy clients dominate the traffic, so top-N panels look natural. Load follows a daily curve that peaks at 13:00 UTC, drops to 20 % at night and to half on weekends.
- **Simulated incidents:** on average every 20 minutes the generator injects one short attack that clearly exceeds a detection threshold: a SYN or ACK flood on the web server, an SSH brute-force attempt, a vertical port scan, a ping sweep of the DMZ, a large upload from a client (exfiltration), or a server IP that suddenly appears with a second MAC address (ARP spoofing). Normal traffic stays below the thresholds, so the detection panels stay empty between incidents. Each incident is logged, e.g. `[generator] incident: port_scan 203.0.113.77 -> 192.168.50.12 (612 ports), 612 flows`.
- **Privacy-safe:** internal hosts use RFC 1918 / ULA addresses; "internet" hosts use only documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`). No real addresses are ever produced, so demo dashboards can be shown publicly.
- **Volume:** the default 5 sessions/s produces about 11 flows/s at peak, roughly 1 million rows per day.

### Generator settings
Set through `environment:` in `docker-compose.yml`. `SESSIONS_PER_SEC`, `IPV6_RATIO` and `INCIDENT_INTERVAL_MIN` can also be set in `.env` as `DEMO_SESSIONS_PER_SEC`, `DEMO_IPV6_RATIO` and `DEMO_INCIDENT_INTERVAL_MIN`; apply a change with `docker compose --profile demo up -d ipfix-generator`.

| Variable | Default | Description |
|---|---|---|
| `SESSIONS_PER_SEC` | `5` | Average sessions per second at peak. |
| `IPV6_RATIO` | `0.15` | Share of IPv6 for dual-stack scenarios. |
| `TARGET_HOST` / `TARGET_PORT` | `ipfixcol2` / `4739` | Collector address. |
| `DIURNAL` | `1` | `1` = daily/weekly pattern, `0` = constant load. |
| `PEAK_HOUR_UTC` | `13` | Hour of peak traffic (UTC). |
| `OBSERVATION_DOMAIN` | `1` | ODID in the IPFIX header. |
| `INCIDENT_INTERVAL_MIN` | `20` | Average minutes between simulated incidents, `0` = off. Set it to `2` to see the detection panels fill quickly. |
| `SEED` | – | Fixed random seed for reproducible output. |

### Stopping the generator
```bash
docker compose stop ipfix-generator
```
The generator has `restart: unless-stopped`, so it keeps running until you stop it explicitly. A plain `docker compose up -d` without `--profile demo` does not start it, but does not stop a running one either.

### Demo vs. real data
Demo and real flows land in the same `flows` table with the same `device` value, so keep demo mode on a separate installation. On a mixed instance, demo flows that touch the "internet" can be recognized by the documentation address ranges above. Purely internal demo flows cannot be told apart from a real LAN.

---

## Connecting a real exporter

Configure your router or switch to export IPFIX (NetFlow v10) to `<host-ip>:4739/udp`.

1. Run [schema-helper](#running-schema-helper) once to see which fields your exporter actually sends.
2. Compare them with the `<columns>` block in `configs/ipfixcol2/startup.xml.tpl` and [adjust the fields](#adjusting-the-collected-flow-fields) if needed.
3. Restrict UDP 4739 to the exporter's IP address. See [Security notes](#security-notes).

### Running schema-helper

`schema-helper` listens on the IPFIX port itself, so `ipfixcol2` has to be stopped while it runs:

```bash
docker compose stop ipfixcol2
docker compose --profile setup run --rm --service-ports schema-helper
docker compose start ipfixcol2
```

- `--service-ports` is required. Without it, `docker compose run` does not publish the container's ports and the helper receives nothing.
- IPFIX export is bursty; template and data packets can be more than a minute apart. The compose file uses `-i 60` (seconds); raise it to 300–600 for a reliable result.
- Output goes to `scripts/generated-configs/schema.sql` and `scripts/generated-configs/config.xml`.

### Adjusting the collected flow fields

Exporters differ in which IPFIX fields they send, so the column mapping is expected to be adjusted per deployment. A field is defined in **four places that must stay in sync**:

1. `configs/ipfixcol2/startup.xml.tpl`: the `<column>` in the `<columns>` block (IPFIX source → column name).
2. `configs/clickhouse/init_tables.sql` → `flows_raw`: the landing column.
3. `init_tables.sql` → `flows`: the stored column.
4. `init_tables.sql` → `flows_mv`: the `SELECT` that copies or derives it.

If 1 and 2 disagree, ipfixcol2 still starts but every insert fails. If 3 and 4 are missing, the field is silently dropped.

Look up the field and its exact source name in `scripts/generated-configs/config.xml` and edit all four places in the same change. Because [the init script does not re-run](#the-init-script-runs-only-once), apply the change to a running instance with `ALTER TABLE … ADD COLUMN` on `flows_raw` and `flows`, and recreate `flows_mv`. Never copy schema-helper output over the real configs; review and merge by hand.

---

## Grafana

### Access

Grafana is published on `127.0.0.1:3000` only, so it can be reached from the host itself but not from the network. If the stack runs on your own machine, open <http://localhost:3000> directly. On a remote host, use an SSH tunnel:

```bash
ssh -L 3000:localhost:3000 <user>@<host>
```

Then open <http://localhost:3000> and log in as `admin` with the password from `GRAFANA_ADMIN_PASSWORD` in `.env`.

To publish Grafana on the network instead, change the port mapping of the `grafana` service in `docker-compose.yml` from `"127.0.0.1:3000:3000"` to `"3000:3000"`. Read the [Security notes](#security-notes) first.

### Admin password

`.env` is the single source of truth for the admin password. Grafana itself reads `GF_SECURITY_ADMIN_PASSWORD` only once, when it creates its database on the very first start. The `grafana` service therefore has a small entrypoint wrapper that runs `grafana cli admin reset-admin-password` with the value from the environment before the server starts.

To change the password, edit `.env` and run `docker compose up -d grafana`. Two consequences:

- A password changed in the Grafana UI lasts only until the next start of the container.
- A browser session that is already logged in can stay logged in after the change. Use a private window to check the new password.

### Datasource

Provisioned from `configs/grafana/provisioning/datasources/`: the datasource `ClickHouse` with the fixed UID `clickhouse` connects to the `clickhouse` service over HTTP (port `8123`) as the `default` user. The password is not stored in the file; Grafana takes it from `CLICKHOUSE_PASSWORD` in its container environment.

The dashboards refer to the datasource by its UID, so do not change it. Changes to the datasource file take effect after `docker compose restart grafana`. To test the connection, open **Connections → Data sources → ClickHouse** and run the test, or ask the API:

```bash
curl -s -u "admin:$(grep '^GRAFANA_ADMIN_PASSWORD=' .env | cut -d= -f2)" \
  http://localhost:3000/api/datasources/uid/clickhouse/health
# {"message":"Data source is working","status":"OK"}
```

### Dashboards

`dashboards/dashboards.yml` tells Grafana to load every JSON file in that directory. Grafana rescans it every 10 seconds, so a changed file is picked up without a restart.

| Dashboard | File | Content |
|---|---|---|
| Network Security Overview | `network-security-overview.json` | Flow-based detection of suspicious activity: SYN/ACK floods, brute-force attempts on remote-access services, port scans and host sweeps, ARP and IP spoofing and possible data exfiltration, plus a filterable flow table. Filters for source and destination IP (single address or CIDR), port and MAC. |

### Changing a dashboard

A provisioned dashboard can be edited and saved in the UI, but Grafana saves such a change to its own database only and never writes back to the JSON file. On the next restart, or when the file changes, the version from the file wins. To keep a change:

1. Edit and save the dashboard in Grafana.
2. Export it as JSON from the dashboard's export menu. Leave the option that prepares the export for another instance switched off; it replaces the datasource reference with a placeholder that provisioning cannot resolve.
3. Overwrite `configs/grafana/provisioning/dashboards/network-security-overview.json` with the export. Keep the file name and the dashboard UID.

The file uses Grafana's current dashboard format (`dashboard.grafana.app/v2`), where the dashboard UID is the `metadata.name` field and panels refer to the datasource as `"datasource": {"name": "clickhouse"}`.

---

## Verifying that data flows

ClickHouse reads the password from its own container environment, so it does not need to be typed:

```bash
docker exec -i clickhouse sh -c 'clickhouse-client -n --password "$CLICKHOUSE_PASSWORD" -f PrettyCompact' <<'SQL'
-- Is data arriving? (run twice a minute apart: count grows, last_flow is fresh)
SELECT count() AS flows, max(flowstart) AS last_flow FROM net_monitor.flows;

-- Breakdown of the last 5 minutes
SELECT direction, protocol_name, count() AS flows, formatReadableSize(sum(bytes)) AS volume
FROM net_monitor.flows
WHERE flowstart > now() - INTERVAL 5 MINUTE
GROUP BY direction, protocol_name
ORDER BY flows DESC;

-- Dictionaries loaded correctly? (all LOADED, empty last_exception)
SELECT name, status, last_exception FROM system.dictionaries WHERE database = 'net_monitor';
SQL
```

An interactive shell:

```bash
docker exec -it clickhouse sh -c 'clickhouse-client --password "$CLICKHOUSE_PASSWORD"'
```

A silent `ipfixcol2` log is a good sign. It only logs on problems.

---

## Disk usage and housekeeping

Three things would otherwise grow without limit. All of them are capped out of the box:

| What | Limit | Where it is set |
|---|---|---|
| Flow data (`net_monitor.flows`) | 3 to 4 months | `TTL` and `SETTINGS` of `flows` in `configs/clickhouse/init_tables.sql` |
| ClickHouse system logs | `query_log` and `part_log` 14 days; `trace_log`, `metric_log` and `asynchronous_metric_log` 7 days | `configs/clickhouse/config.d/system_logs.xml` |
| Container logs (`docker compose logs`) | 3 files of 10 MB per container | `x-logging` block at the top of `docker-compose.yml` |

To see what takes up space:

```bash
docker system df                 # images, containers, build cache
du -sh data/*                    # ClickHouse and Grafana data

docker exec -i clickhouse sh -c 'clickhouse-client --password "$CLICKHOUSE_PASSWORD" -f PrettyCompact' <<'SQL'
SELECT database, table, formatReadableSize(sum(bytes_on_disk)) AS size, sum(rows) AS rows
FROM system.parts
WHERE active
GROUP BY database, table
ORDER BY sum(bytes_on_disk) DESC
LIMIT 10;
SQL
```

- `docker builder prune -f` removes unused build cache and is safe at any time. The next build of `ipfixcol2` just takes longer.
- A changed TTL in `system_logs.xml` takes effect after `docker compose restart clickhouse`. ClickHouse then keeps the previous log table under a numbered name such as `system.query_log_0`; drop it once you no longer need it.
- To change the flow retention on a running instance, use `ALTER TABLE net_monitor.flows MODIFY TTL …` and update `init_tables.sql` as well, so fresh installs match.

---

## Security notes

- **Secrets:** the ClickHouse password and the Grafana admin password live only in `.env` (git-ignored) and are injected at runtime. Never commit `.env`, and never hard-code a password in the configs.
- **ClickHouse ports** `8123` (HTTP) and `9000` (native) are bound to `127.0.0.1` only. The other containers reach ClickHouse over the internal Docker network. From the host, use `docker exec` or an SSH tunnel.
- **UDP 4739** must be reachable by the exporter, so it listens on all interfaces. Restrict it to the exporter's IP; otherwise anyone who can reach the host can inject forged flows. Docker publishes ports through NAT and **bypasses `ufw` and the regular `INPUT` chain**, so use one of these:
  - a firewall in front of the host: allow UDP 4739 from the exporter, drop the rest;
  - or the `DOCKER-USER` chain on the host:
    ```bash
    iptables -I DOCKER-USER -i <external-if> -p udp --dport 4739 ! -s <exporter-ip> -j DROP
    ```
    Persist it with `iptables-persistent`. The `-i <external-if>` match keeps container-to-container traffic, such as the demo generator, unaffected.
- **`dict_reader`** has no password but is limited to `HOST LOCAL` and read access on the dictionary source tables.
- **Grafana** is bound to `127.0.0.1:3000`, like the ClickHouse ports. Use the SSH tunnel, or put it behind a TLS reverse proxy if it has to be reachable from the network. There is no default `admin`/`admin` login, and self-registration is switched off.
- **Grafana's access to ClickHouse:** the datasource connects as the ClickHouse `default` user, which has full rights. Grafana does not restrict the SQL it forwards, so anyone who can run queries in Grafana can also change or delete data. That includes users with the Viewer role, who can send their own queries through the Grafana API. Give Grafana access only to people you trust, and do not enable anonymous access as long as the datasource uses `default`.
- **Privacy:** IP and MAC addresses from real traffic are personal data under GDPR. Do not publish dashboards, screenshots or dumps of real traffic. Use demo mode for anything public.

---

## Limitations

- No GeoIP or ASN enrichment, and ports are shown as numbers without service names.
- `device` is a single constant label, so flows from several exporters are not told apart.
- The detection panels use simple heuristic thresholds (e.g. more than 50 SYN-only flows per connection in 30 s, more than 200 ports per minute for a port scan, more than 50 MB uploaded in 5 minutes, more than one MAC address for one IP in 5 minutes). An empty panel says "No activity above threshold". Tune the thresholds to your traffic before relying on them.
- Dashboards query the raw flows; there are no pre-aggregated tables, and nothing is kept beyond the 3 to 4 months of retention.

Most of these can be added to order, see the next section.

---

## Custom deployment and support

This repository is the free edition: a working stack that you can run and adapt yourself. If you would rather have it set up for your network, or you need something it does not do yet, I take that on as paid work, tailored to your environment.

Typical requests:

- **Deployment:** installation in your infrastructure, onboarding of your routers and switches (field mapping for each exporter), sizing and retention for your traffic volume, firewall and access setup.
- **Enrichment:** GeoIP and ASN, service names for ports, several exporters told apart, your own network zones and naming.
- **Dashboards and detection:** dashboards built around your questions, detection thresholds tuned to your traffic, alerting.
- **Performance and history:** pre-aggregated tables for fast dashboards and for statistics that outlive the raw-data retention.
- **Operation:** upgrades and ongoing maintenance.

### Contact for custom work

Write to me directly. Issues in this repository are public, so they are not the place for business enquiries.

- **Dan Hanuška**, based in Prague, Czech Republic (CET). I work in English and Czech.
- E-mail: [dan.hanuska.consulting@gmail.com](mailto:dan.hanuska.consulting@gmail.com)
- LinkedIn: [linkedin.com/in/dan-hanuška-669114242](https://www.linkedin.com/in/dan-hanuška-669114242)

A short description of your network is enough to start: which devices export flows, roughly how much traffic, and what you want to see.

### Bugs and questions about this repository

Found a bug, or something in this README does not work as described? Open an [issue](https://github.com/danhanuska/ipfix-monitoring-stack/issues). Issues are public: before you paste logs, query results or screenshots, remove real IP and MAC addresses and anything from your `.env`.

---

## Troubleshooting

### ClickHouse crashes with `Illegal instruction`
Newer ClickHouse images (24.x+) require an x86-64-v3 CPU (AVX2, BMI, FMA). On CPUs without AVX2, or VMs with a generic CPU type, they crash immediately on startup. The image is therefore pinned to `23.8`. Check with `grep -o avx2 /proc/cpuinfo | head -1`. In a VM, passing the host CPU type through (e.g. CPU type `host` in Proxmox) often exposes AVX2.

If your CPU has AVX2, you are free to use a newer ClickHouse LTS release instead: change the `clickhouse` image tag in `docker-compose.yml`. The stack itself is tested with `23.8`.

### ipfixcol2 logs `Insert failed` while the connection is fine
Almost always a permissions problem on `data/clickhouse`: ClickHouse runs as UID 101 and cannot write temporary insert files. The `permissions` service handles this; check `docker compose logs permissions`. It can also mean that `flows_raw` does not match the `<columns>` in `startup.xml.tpl`.

### `can't find '__main__' module in '/app/ipfix_generator.py'`
The bind-mounted file did not exist when the container was first created, so Docker created an empty **directory** in its place. Fix:
```bash
docker compose rm -sf ipfix-generator
rmdir scripts/ipfix-generator/ipfix_generator.py
# put the real file in place, check with: ls -la scripts/ipfix-generator/
docker compose --profile demo up -d
```

### Grafana: `mkdir: can't create directory '/var/lib/grafana/plugins': Permission denied`
`data/grafana` must be owned by UID 472. This is normally handled by the `permissions` service.

### Grafana login fails after changing `GRAFANA_ADMIN_PASSWORD`
The new value reaches Grafana only when the container is recreated: `docker compose up -d grafana`. After five failed login attempts Grafana locks the account for five minutes, so wait before trying again. To check the password without a browser:

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  -u "admin:$(grep '^GRAFANA_ADMIN_PASSWORD=' .env | cut -d= -f2)" \
  http://localhost:3000/api/org      # 200 = the password from .env is valid
```

Do not wipe `data/grafana` to reset a password. It also holds every dashboard change that has not been exported yet.

### Grafana restarts in a loop with `failed to install plugin … 404: Plugin not found`
With `GF_PLUGINS_PREINSTALL_SYNC`, Grafana does not start when the plugin cannot be installed. The plugin is downloaded from the Grafana plugin catalog on the first start and whenever the pinned version changes, so that start needs internet access. Later starts work offline. Check which versions the catalog offers:

```bash
docker run --rm --entrypoint grafana grafana/grafana:13.2.1 cli plugins list-versions grafana-clickhouse-datasource
```

If the pinned version is listed, the lookup failed temporarily: wait a few minutes and run `docker compose up -d grafana` again. If it is not listed, pin a version that is. To get Grafana running in the meantime, remove `@<version>` from the variable; a plugin that is already in `data/grafana/plugins` is then used as it is.

### A change seems to have no effect
- **`init_tables.sql`:** the script runs automatically only on an empty data directory. See [The init script runs only once](#the-init-script-runs-only-once).
- **A dashboard edited in the UI is gone after a restart:** the JSON file in the repository replaced it. See [Changing a dashboard](#changing-a-dashboard).

---

## Operations cheat sheet

```bash
docker compose up -d --build                 # (re)build and start
docker compose build ipfixcol2               # rebuild the collector only (after changing the pinned versions)
docker compose --profile demo up -d          # start including the demo generator
docker compose ps                            # status
docker compose logs -f <service>             # follow logs (Ctrl+C stops following only)
docker compose logs --tail 50 <service>      # last lines, no follow
docker compose stop ipfix-generator          # stop the demo generator
docker compose up -d --force-recreate        # apply .env changes (e.g. a new password)
docker compose up -d grafana                 # apply a changed GRAFANA_ADMIN_PASSWORD
docker compose restart grafana               # reload the datasource or dashboard provider YAML
docker compose down                          # stop and remove containers (data in ./data stays)
```

---

## License

MIT, see [LICENSE](LICENSE). 
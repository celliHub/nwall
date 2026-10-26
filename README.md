# nwall

Network sniffer for macOS with a web UI, real-time metrics, traffic blocking through the system firewall, and an HTTP/HTTPS inspection proxy to analyze and block the content of every request.

It uses only the Go standard library, cgo/C (BPF, ioctl, setsockopt) and SQLite (`libsqlite3` via cgo, no third-party driver). The UI is plain HTML5/CSS/JavaScript and is embedded in the binary.

## Getting the code

```sh
git clone https://github.com/celliHub/nwall.git
cd nwall
cp .env.example .env    # or: make env
```

Requires Go (see `go.mod`), a C compiler and `libsqlite3`.

## Running

```sh
make                 # builds and runs with sudo → http://127.0.0.1:8080
make proxy           # trusts the CA and runs with the inspection proxy on (macOS)
make trust           # only installs/trusts the CA (macOS)
make untrust         # removes the trusted CA
make PORT=9090       # one-off overrides: HOST, PORT, IFACE, DB
make geoip           # regenerates the map's IP→country database (downloads the RIR files)
make threatfeed      # regenerates the malicious-IP database (stamparm/ipsum feed, MIT)
make mcp             # builds nwall-mcp and nwall-agent
make mcp-http        # MCP over HTTP at 127.0.0.1:8090/mcp
make mcp-config CLIENT=lmstudio   # ready-made config for the client
make agent MODEL=qwen2.5:7b      # chat with Ollama/LM Studio operating nwall
make mode-central    # fleet central mode (agents connect on 8443/TLS)
make fleet-token     # on the central: enrollment token + ready-to-run agent command
make mode-agent CENTRAL=… FINGERPRINT=… ENROLL=…   # agent mode
make version         # prints the embedded version (make build VERSION=x.y.z overrides it)
make help            # lists the targets
make test
```

`sudo` is required to open `/dev/bpf*` and to use `pfctl`.

## Configuration (`.env`)

The binary reads `.env` from the current directory at startup. This works with `make`, `go run` and `sudo`, which drops shell variables. To use a different file: `NWALL_ENV_FILE=/path/to/file.env`. On the first run, `make` creates `.env` from `.env.example`. `.env` is kept out of git because it may contain the token.

Precedence: flags (`-listen`, `-db`, `-iface`, `-token`, `-debug`) > environment variables > `.env`.

| Variable | Default | Description |
|---|---|---|
| `NWALL_HOST` | `127.0.0.1` | UI/API address (`0.0.0.0` requires a token) |
| `NWALL_PORT` | `8080` | UI/API port |
| `NWALL_TOKEN` | | API Bearer token |
| `NWALL_IFACE` | | interface to analyze; if set, capture starts when the program opens |
| `NWALL_PROMISCUOUS` | `false` | promiscuous mode |
| `NWALL_DB` | `nwall.db` | SQLite file |
| `NWALL_DEBUG` | `false` | verbose logs |

The fine-tuning variables (`NWALL_PAYLOAD_BYTES`, `NWALL_MAX_STORED_PACKETS`, `NWALL_FIREWALL_ENABLED`, `NWALL_PORTSCAN_*` etc.) are commented out in `.env`. While commented out, whatever was saved in the Settings tab or via `PUT /api/config` applies. Uncommented, the `.env` value is applied on every program start. Invalid values prevent the program from starting, and the error names the variable.

## What is analyzed

- Link: Ethernet (VLAN/QinQ), `DLT_NULL` (`lo0`, VPN `utun*`), raw IP, ARP
- Network: IPv4, IPv6 (extension headers), TTL, fragments
- Transport: TCP (flags and connection state), UDP, ICMP/ICMPv6
- Application:
  - HTTP: method (GET/POST/PUT/PATCH/DELETE…), path, Host, User-Agent and response status
  - TLS/HTTPS: ClientHello with SNI, version and ALPN
  - SSH: banner
  - DNS/mDNS: query, response and returned IPs (used to name IPs)
  - QUIC
  - port-based identification for about 50 services
- Metrics: packets/bytes per protocol, packets/s, bandwidth, 120 s timeline, top hosts, domains and ports, connections (flows) and direction (inbound/outbound)
- Sessions (**Sessions** tab, proxy only): proxy traffic grouped as **site → page → child resources**. The parent→child link comes from the `Referer`, so a YouTube page shows up with the **video ID** being watched and, under it, the resources it pulled (JS/CSS/images and the streams on `*.googlevideo.com`). Cross-origin resources only send the origin in the `Referer` and are attributed to the most recent active page of the same site (heuristic). API: `GET /api/sessions`.
- Map (**Map** tab): where traffic is going **right now**, by country. Active flows (seen in the last 60 s) are geolocated and plotted on an SVG world map — each country is a dot sized by volume, with a side list sorted by bytes. Clicking a dot pins the country (highlights it and scrolls the list to it) and enables the **Block <country>** button, which sends the firewall one rule per active IP from that country; each host can also be blocked individually by IP. Geolocation is **country-level** (it plots the centroid), using an IP→country database embedded in the binary, generated from the public allocation files of the five RIRs (public domain) — no download, no key. Regenerate: `make geoip`. Private/local IPs are not shown. API: `GET /api/geo`.
- Alerts: port scan, plaintext credentials (HTTP Basic, FTP/POP3/IMAP/SMTP/Telnet), Telnet and "alert" rules
- Harmful traffic detection (inbound and outbound), all via `GET /api/alerts` and consolidated in `GET /api/threats`:
  - **Exfiltration/leakage** — abnormal outbound volume to a single destination (limits `NWALL_EXFIL_BYTES`/`_WINDOW_SEC`)
  - **Malware/C2** — communication with known-malicious IPs, from an embedded database (public stamparm/ipsum feed, MIT; regenerate with `make threatfeed`)
  - **DNS tunneling** — long/high-entropy query names or abnormal volume to one domain
  - **Suspicious ports/services** — C2, IRC, Tor, mining, exposed RDP/SMB (embedded curated list)
  - **Unusual country** — traffic to a never-seen country, after learning the baseline
  - **Unusual hours** — activity at historically rare hours
  - `GET /api/threats` scores each host and explains *why* it is suspicious (evidence types, reasons, direction), highlighting what to investigate first. The baseline (countries/hours) persists across runs.

## Blocking

Rules (`block` or `alert`) accept IP/CIDR, port and protocol, and are stored in SQLite. `block` rules are applied in **pf**, in a dedicated anchor (`com.apple/250.nwall`), without touching `/etc/pf.conf`:

- traffic is dropped in both directions and connections already open with the IP are killed (`pfctl -k`);
- the program enables pf with a reference token (`pfctl -E`) and, on exit, removes the anchor and releases the token (`pfctl -X`). Rules are reapplied on the next run.

To check: `sudo pfctl -a com.apple/250.nwall -s rules`.

BPF still sees the inbound packets pf drops, and they show up tagged as **BLOCKED** in the UI.

## HTTP/HTTPS inspection proxy

Capture shows network traffic, but HTTPS content is encrypted. To see each request in plain text — the page **and everything it fetches** (CSS, JS, images, fonts, APIs) — and block by keyword, nwall includes a local proxy, in the style of mitmproxy/Charles.

On macOS, inspecting only Chrome (recommended):

```sh
make proxy     # generates/installs the CA and starts the proxy, WITHOUT touching the system proxy
make chrome    # in another terminal: opens a dedicated Chrome pointed at the proxy
```

Only that Chrome is intercepted; the rest of the Mac (Claude Code, git, other apps) still goes direct. `make chrome` uses a separate profile (`~/.nwall-chrome`), so you log in to it separately.

> **Don't use the system proxy unless you need it.** `make proxy-system` (or `NWALL_PROXY_CONFIGURE_SYSTEM=true`) intercepts **all** Mac traffic. Programs that don't trust the CA or that pin certificates — Claude Code, git, brew, apps — start failing with certificate errors. If that happens, run **`make proxy-off`** to turn off the system proxy on all interfaces.

`make proxy` asks for your password (sudo) to install the CA and for capture. The CA stays installed until `make untrust`.

Manual steps, if you prefer:

1. **Proxy tab → Download CA certificate** (or `make ca`, which writes `nwall-ca.crt`) and install it as trusted. The CA key stays only on this machine, inside SQLite; the CA is generated on the first run.
2. Enable the proxy. Check "Configure the system proxy" so macOS starts using it, or manually set the HTTP/HTTPS proxy to `127.0.0.1:8081`.
3. Every request now shows up in the **Live** and **History** tabs (interface `proxy`), with method, URL, status, host and Content-Type.

### Block ads, trackers and banners

At the top of the **Rules** tab there is a **Block ads, trackers and banners** panel: turn it on per category (**Ads and banners**, **Trackers and analytics**, **Social buttons and widgets**) or all at once with the master switch. Each category is a curated domain list embedded in the binary; matching is by **domain suffix** against the request host (`doubleclick.net` covers `ad.doubleclick.net`, but doesn't take down the site you're visiting). The panel shows how many requests each category blocked. The choice is saved in the config (`adblock_categories`) and applies to all traffic going through the proxy. API: `GET /api/adblock` and `PUT /api/adblock {"categories":["ads","trackers","social"]}`.

### Blocking by keyword/expression

For anything else, a rule with a **keyword or expression** rejects (HTTP 403) every request whose URL, host or headers (User-Agent, Referer) match — across all traffic going through the proxy, without blocking the whole IP. Example: `pattern:"youtube"` blocks `www.youtube.com`, `m.youtube.com` and the fonts/videos those pages fetch. Rules with an IP/port still go to the firewall; content-only rules are enforced by the proxy.

```sh
curl -s -X POST localhost:8080/api/rules -H 'Content-Type: application/json' -d '{"action":"block","pattern":"youtube"}'
curl -s -X POST localhost:8080/api/rules -H 'Content-Type: application/json' -d '{"action":"block","pattern":"youtube|googlevideo","is_regex":true}'
curl -s -X POST localhost:8080/api/proxy/start
```

Limitations: apps that pin the server certificate (banks, Apple apps) fail under interception — add the domain to the "no inspection" list, which passes them through a blind tunnel. Only traffic from clients using the proxy is inspected; everything else remains visible only through capture. Installing the CA lets you inspect HTTPS **on this machine**, so protect the SQLite file (it contains the CA key).

## Plugins

The **Plugins** tab gathers extensions that broaden the analysis. Each plugin declares a manifest: name, version, typed configuration fields and actions. The UI builds the form from that manifest. The lifecycle is **install → configure → enable/disable → uninstall** (uninstalling deletes the plugin's configuration and data). Everything lives in SQLite and can also be controlled via `/api/plugins` and the MCP tools `list_plugins`, `install_plugin`, `configure_plugin`, `uninstall_plugin` and `run_plugin_action`.

Plugins are compiled together with nwall: no third-party code is downloaded. To create a new one, implement `plugin.Plugin` (`internal/plugin`) in a package under `internal/plugins/<name>`, register it with `plugin.Register` in `init()` and add an import in `internal/plugins/all`. Optional hooks:
- `Inspector`: receives each packet/proxy request in real time (must be fast: it runs in the capture loop);
- `AlertListener`: receives each recorded alert, from any source (cannot block);
- `Host.Report`: emits alerts that show up in `/api/alerts` and `/api/threats`;
- `Host.Observed`: returns active traffic or history for scans;
- `Host.LoadState`/`SaveState`: persistent state isolated per plugin.

Fields with `Secret: true` (tokens, URLs with keys) come back masked (`********`) in the API, the UI and MCP; sending the mask back keeps the saved value.

Built-in plugins:

| Plugin | What it does | External data |
|---|---|---|
| `threatintel` | compares traffic against public malicious IP/domain lists | yes (free) |
| `domainwatch` | risky new domains and algorithmically generated names (DGA) | no |
| `beacon` | clockwork-like connections (C2 beaconing) | no |
| `notify` | sends alerts via webhook (JSON, Discord, Slack, ntfy) and Telegram | — |

### Threat intelligence (`threatintel`)

Downloads free public lists (no API key) of malicious traffic and compares them with your traffic:

| List | Category | Default |
|---|---|---|
| Feodo Tracker (abuse.ch) | botnet C2 | ✔ |
| Spamhaus DROP | hijacked/criminal network | ✔ |
| Emerging Threats – compromised | attacker | ✔ |
| IPsum level 3+ | attacker (on 3+ lists) | ✔ |
| CINS Army | attacker | ✔ |
| URLhaus – domains (malware-filter) | malware distribution | ✔ |
| OpenPhish (community) | phishing | ✔ |
| FireHOL Level 1 | attacker (aggregate) | |
| blocklist.de (48 h) | attacker | |
| Phishing Army (~150k domains) | phishing | |
| Tor – exit nodes | anonymization | |

- **Custom lists**: any `https` URL, with the format detected automatically (IPs, CIDRs, domains, URLs, hosts file, `||domain^`, extra columns). Local/private hosts are rejected.
- **Real-time analysis**: checks source/destination IPs, DNS queries, SNI, HTTP Host and proxy requests. Matches become `threat-intel` alerts: critical severity for C2, malware and hijacked networks, warning for phishing and attackers, and informational for Tor. They feed into the threat assessment, with 10 min deduplication.
- **Actions**: `update` (re-downloads in the background), `lookup` (which lists an IP/domain/URL appears on) and `scan` (scans active connections or stored packets; with `report=true` it records matches as alerts). In the UI, each match has a **Block** button: IPs go to the firewall, domains to the proxy.
- **False positives**: private/reserved ranges are ignored, as are blocks larger than /8. Phishing URLs only match the exact host. The "Never flag" list (with Google, Microsoft, GitHub, CDNs etc. by default) protects shared platforms.
- **Cache and updates**: the cache lives in SQLite and the plugin comes back without downloading anything on restart. The default update interval is 12 h; if a list fails, the previous index stays in effect and the retry comes in 15 min. Limits: 48 MB and 600k indicators per list.
- Via MCP: `threat_intel_lookup`, `threat_intel_scan` and `threat_intel_update`.

Respect each list's license (described in the UI). Some, such as OpenPhish and Phishing Army, are for non-commercial use only.

### Suspicious domains (`domainwatch`)

Learns the domains the network accesses and flags them, without relying on external data:
- **DGA** (`dga-domain`): malware generates names like `bkcxhcfuyhcmzqqx.com` to find its command server. The score (0–100) combines unlikely letter pairs (bigrams rare in English/Portuguese), few vowels, consonant runs, mixed letters and digits, hash-like shape, entropy and length, plus risky TLDs and dynamic DNS. The default threshold is 55; calibrated against ~350 real domains (Brazil and worldwide, CDNs and adtech) with no false positives. Critical severity from 80 up, warning below that.
- **New domain** (`new-domain`): first access to a registrable domain (`uol.com.br`, `evil.duckdns.org`). In the default mode it only warns when there is a risk signal: cheap TLD (`.top`, `.xyz`, `.zip`…), dynamic DNS/tunnel (duckdns, no-ip, ngrok…), punycode or an odd name. During the first 24 h (configurable) it only learns.
- Ignores local network names (`.lan`, `.local`, `.home.arpa`, reverse zones) and the "Never flag" list (CDNs and system services by default).
- **Actions**: `analyze` (a domain's score and reasons, and whether it has been seen), `recent` (new domains in the last hours) and `scan` (scores active connections or history; with `report=true` it becomes an alert).
- Known domains are stored in SQLite (up to 100k, saved every 5 min).

### Beaconing (`beacon`)

Malware often "phones home" at fixed intervals (e.g. every 60 s ± 2 s); people browsing don't have that rhythm. The plugin records each new TCP connection (SYN) from capture and each proxy request per source → destination:port pair. Parallel connections at the same instant (within 2 s) count as one. Over the last 48 it computes the median interval and the median absolute deviation, and raises a `beaconing` alert when:
- there are at least 8 connections;
- the interval is between 10 s and 1 h;
- the variation is below 10% (all configurable).

By default it ignores local network destinations and services with a legitimate rhythm (Apple push, Windows Update, NTP etc.). The `candidates` action lists every pair with repeated connections, from most to least regular, for investigation. The analysis is in-memory only: UDP/QUIC is not covered yet.

### Notifications (`notify`)

Sends alerts outside the dashboard:
- **Channels**: webhook with generic JSON format, Discord, Slack/Mattermost or ntfy (priority and title in the header), and Telegram (token from @BotFather + chat ID). At least one channel is required.
- **Filters**: minimum severity (default: critical only), "only these types" and "never send" (default: `proxy-block`).
- **Anti-spam**: the same type + source + destination is not repeated for 10 min, and there are at most 6 sends per minute. The excess becomes a summary ("N alerts not sent"). Sending is asynchronous, through a queue that never blocks capture, with one retry on network failure, 429 or 5xx.
- **Action** `test`: sends a test message to each channel and shows the result. Errors never reveal the URL/token.

## Modes: single, agent and central (fleet)

By default nwall runs in **single** mode: it analyzes and protects only the machine it runs on. For multiple machines there are two more modes, following the design of products in this space (EDR, Wazuh, Elastic Fleet, Zeek/Corelight):

| Mode | What it does |
|---|---|
| `single` | As always: captures, analyzes, blocks and shows everything locally. |
| `agent` | Everything single does **and** sends summaries to the central and applies its policy. |
| `central` | Receives agents on its own TLS listener (port 8443), stores, correlates across machines and distributes the policy. It can also capture its own traffic. |

**Principles**

- **Traffic never goes through the central.** Each agent captures and blocks locally. If the central goes down, the network carries on normally and the agent keeps the last policy.
- **The agent sends summaries, not packets.** Every 10 s it sends a compressed batch with the conversations (machine ↔ destination:port, bytes, connections, name, app), DNS resolutions and alerts. Packets stay in the machine's own SQLite. A conversation is ~200 bytes, versus thousands of packets.
- **The agent opens the connection**, which works through NAT, home offices and 4G. Policy arrives via long-poll and is applied within seconds.
- **Per-machine identity.** The enrollment token is reusable until it expires. Each machine gets its own key, and the central stores only the hash. DHCP can change the IP without losing history.
- **Pinned TLS.** The central uses its own fleet CA, separate from the inspection CA. Agents check the SHA-256 fingerprint and reject any other certificate.
- **Local queue.** Without a connection, batches wait in the agent's SQLite (up to 24 h) and are sent in order when the central comes back.

**Setting up a fleet**

```sh
# 1. On the central (a VM, for example):
make mode-central                    # agents on 0.0.0.0:8443; UI on 127.0.0.1:8080
make fleet-token TTL=168h            # in another terminal: token + ready-to-run command

# 2. On each machine (paste the command printed in step 1):
make mode-agent CENTRAL=https://192.168.0.10:8443 FINGERPRINT=AA:BB:…:FF ENROLL=nwl_… IFACE=en0
```

The token is also available in the **Fleet** tab → "Connect a machine", which shows the command with a copy button. After the first enrollment, `ENROLL` is no longer needed. Everything can live in `.env` (`NWALL_MODE`, `NWALL_CENTRAL_URL`, `NWALL_CENTRAL_FINGERPRINT`, `NWALL_ENROLL_TOKEN`, `NWALL_AGENT_NAME`), and then plain `make` is enough.

**Fleet tab (central)**

- **Machines**: online/offline, IPs, OS, capture, queue, policy version, 24 h alerts and "Revoke". A revoked machine stops sending and does not re-enroll on its own.
- **Fleet policy**: block/alert rules (IP/CIDR, port, keyword) and, optionally, the Adblock categories. On agents, these rules appear in the Rules tab tagged "central" and cannot be edited locally. Local rules remain free to change.
- **Correlation**, which only the central can see:
  - alerts repeated across several machines (the same beacon or the same malicious IP);
  - destinations seen by a single machine (long tail);
  - most common destinations.

  Each row has "Block on fleet".
- **Fleet alerts** per machine, and **"Who in the fleet talked to…"**, which answers who talked to an IP or domain, or resolved it, in the last 7 days.
- Agent alerts also go to the central's plugins, with the machine name in the message. Configuring `notify` on the central alone is enough.

**Fleet tab (agent)**: central, enrollment, connection, queue, batches sent, policy version and errors.

Retention on the central: `NWALL_FLEET_RETENTION_DAYS` (default 7). If agents need a different address for the central (DNS, NAT), use `make mode-central FLEET_URL=https://central.company:8443`, which changes the generated command.

## MCP (assistant control: Claude Code etc.)

`nwall-mcp` exposes **every** API endpoint as an MCP tool (stdio, JSON-RPC 2.0), plus shortcuts that used to exist only in the UI. It captures nothing on its own: it talks to the API of a running nwall, so the token, loopback and validations still apply and the assistant doesn't need `sudo`.

```sh
make            # or make proxy — nwall must be running
```

### Local integration per client

`make mcp` builds `nwall-mcp` and `nwall-agent`. `make mcp-config CLIENT=<client>` prints a ready-made configuration, with an absolute path and an explicit `-url`, because Claude Desktop and LM Studio start the server outside this directory and don't read the `.env` here.

| Client | MCP support | How to connect |
|---|---|---|
| **Claude Code** | native (stdio) | In this directory it already works via `.mcp.json` (approve it the first time). Global: `make mcp-config CLIENT=claude-code` and run the printed command. |
| **Claude Desktop** | native (stdio) | `make mcp-config CLIENT=claude-desktop` → paste into `~/Library/Application Support/Claude/claude_desktop_config.json` and restart the app. |
| **LM Studio** | native (stdio or URL) | `make mcp-config CLIENT=lmstudio` → paste into `~/.lmstudio/mcp.json` (app: *Program → Install → Edit mcp.json*). Or `make mcp-http` + `make mcp-config CLIENT=http`. Use a model with *tool use*. |
| **Cursor** | native (stdio) | `make mcp-config CLIENT=cursor` → `~/.cursor/mcp.json`. |
| **Ollama** | **no MCP** (only *tool calling*) | Use `nwall-agent`, which bridges the gap: `make agent MODEL=qwen2.5:7b`. |

**HTTP transport**: `make mcp-http` serves at `http://127.0.0.1:8090/mcp` (Streamable HTTP, JSON responses). A single server handles several clients. It rejects external `Origin` (anti DNS-rebinding) and, outside loopback, requires `-http-token`/`NWALL_MCP_TOKEN`, sent as `Authorization: Bearer`.

### nwall-agent (Ollama, LM Studio or any OpenAI-compatible API)

Terminal chat in which the local model operates nwall through the same 31 tools, via *function calling*:

```sh
ollama pull qwen2.5:7b
make agent MODEL=qwen2.5:7b                                     # Ollama (127.0.0.1:11434)
make agent PROVIDER=lmstudio MODEL=qwen2.5-7b-instruct          # LM Studio (server on 127.0.0.1:1234)
./nwall-agent -model qwen2.5:7b -read-only -q "are there signs of data leakage?"
./nwall-agent -provider ollama -list-models
```

- Actions that change state (block, delete, change config) **ask for confirmation** `[y/N]`. Without an answer, the action is refused and the model is told not to insist.
- `-read-only` exposes only read tools (recommended for small models). `-tools get_threats,list_alerts` restricts the list. `-yes` approves everything without asking; use with care.
- Large results are truncated (12k characters by default) to fit in the context. The `<think>` reasoning from qwen3 and deepseek-r1 is stripped from the answer.
- The model must support tools: qwen2.5, qwen3, llama3.1/3.2 and mistral-nemo, for example. If it doesn't, the error says so.
- Variables: `NWALL_AGENT_PROVIDER`, `NWALL_AGENT_MODEL`, `NWALL_AGENT_LLM_URL`, `NWALL_AGENT_LLM_KEY` (see `.env.example`).

API address: `-url`, `NWALL_MCP_URL` or `http://NWALL_HOST:NWALL_PORT`. Token: `-token` or `NWALL_TOKEN`. The binaries look for `.env` in the current directory and then next to the executable.

| Area | Tools |
|---|---|
| Status/capture | `get_status`, `list_interfaces`, `capture_start`, `capture_stop` |
| Metrics/traffic | `get_stats`, `reset_stats`, `query_packets`, `get_packet`, `clear_packets`, `list_flows`, `list_hosts`, `get_sessions`, `get_geo` |
| Threats | `get_threats`, `list_alerts`, `clear_alerts` |
| Rules/blocking | `list_rules`, `get_rule`, `create_rule`, `update_rule`, `delete_rule`, `block_ip`, `block_country` |
| Adblock | `get_adblock`, `set_adblock` |
| Config/proxy | `get_config`, `update_config`, `proxy_start`, `proxy_stop`, `get_ca_cert` |
| Real time | `watch_events` (listens to the SSE stream for N seconds) |

Each tool carries *annotations* (`readOnlyHint`, `destructiveHint`) so the client can ask for confirmation on those that delete or block in bulk. A test (`TestEveryAPIRouteHasATool`) fails if any new API route is left without a tool.

## API

Full documentation is in the UI's **API** tab and at the top of `internal/api/api.go`. Examples:

```sh
curl -s localhost:8080/api/interfaces
curl -s -X POST localhost:8080/api/capture/start -H 'Content-Type: application/json' -d '{"interface":"en0"}'
curl -s 'localhost:8080/api/packets?app=HTTP&method=POST'
curl -s -X POST localhost:8080/api/rules -H 'Content-Type: application/json' -d '{"action":"block","ip":"203.0.113.7"}'
curl -s -X PUT localhost:8080/api/config -H 'Content-Type: application/json' -d '{"payload_bytes":1024}'
curl -N localhost:8080/api/events     # SSE: packets, stats, alert, rules, status, fleet
curl -s localhost:8080/api/fleet      # mode (single/agent/central) and fleet state
```

State-changing requests require `Content-Type: application/json` and are rejected when they come from another origin. The `Host` must be loopback unless `-token` is set. This prevents a website open in the browser from using the API.

## Layout

```
main.go                 flags, .env, startup and shutdown
internal/envfile        .env reader (stdlib)
internal/capture        BPF (macOS, cgo) and AF_PACKET (Linux, for development)
internal/decode         parsers: Ethernet → IP → TCP/UDP/ICMP → HTTP/TLS/SSH/DNS
internal/engine         pipeline, rules, metrics, flows, alerts, SSE hub, configuration
internal/firewall       pf (macOS) and iptables (Linux)
internal/proxy          HTTP/HTTPS inspection proxy: own CA + content blocking
internal/store          persistence (packets, rules, configuration)
internal/sqlite         minimal cgo wrapper for libsqlite3
internal/api            REST + SSE + access protections (fleet routes in fleet.go)
internal/fleet          agent/central modes: conversation collector, queue, enrollment, pinned TLS, policy, correlation
web/static              index.html, app.css, app.js, world.json (map basemap)
tools/geoipgen          generator for the embedded IP→country database (make geoip)
tools/threatgen         generator for the embedded malicious-IP database (make threatfeed)
internal/plugin         plugin contract (manifest, validation, hooks, catalog)
internal/plugins        built-in plugins (threatintel, domainwatch, beacon, notify) and the registry (all)
internal/mcp            MCP server: JSON-RPC/stdio protocol + one tool per endpoint
cmd/nwall-mcp        MCP server binary: stdio, HTTP and -print-config (make mcp)
internal/agent          MCP host for OpenAI-compatible LLMs (Ollama, LM Studio)
cmd/nwall-agent      terminal chat with a local LLM operating nwall (make agent)
internal/version        release version shared by the binaries and the fleet protocol
```

## Tests

```sh
go test -race ./...
```

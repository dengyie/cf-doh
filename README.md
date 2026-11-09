<div align="center">

# CfDoH

**High-Performance DNS-over-HTTPS & DNS-over-TLS Gateway on Cloudflare Workers**

[![License](https://img.shields.io/badge/license-MIT-green.svg?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Cloudflare%20Workers-F38020.svg?style=flat-square&logo=cloudflare&logoColor=white)](https://workers.cloudflare.com/)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-5FA04E.svg?style=flat-square&logo=node.js&logoColor=white)](https://nodejs.org/)
[![Protocols](https://img.shields.io/badge/Protocols-RFC%208484%20%7C%20RFC%207858-0052CC.svg?style=flat-square)](https://datatracker.ietf.org/doc/html/rfc8484)
[![DNSSEC](https://img.shields.io/badge/DNSSEC-AD%20Pass--Through-brightgreen.svg?style=flat-square)](#security--anti-poisoning)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg?style=flat-square)]()

[English](./README.md) · [简体中文](./README.zh-CN.md) · [Core Features](#core-features) · [Deployment](#quick-deployment) · [Architecture](#architecture) · [Client Setup](#client-configuration)

</div>

---

## Overview

**CfDoH** is an open-source, pure ESM, zero-dependency DNS-over-HTTPS (DoH, RFC 8484) gateway running on Cloudflare Workers, accompanied by a standalone DNS-over-TLS (DoT, RFC 7858) endpoint designed for Android system-level Private DNS.

It resolves common routing pitfalls when using international public DoH resolvers (such as 1.1.1.1 or 8.8.8.8) in East Asia, where queries frequently lack localized EDNS Client Subnet (ECS) hints and cause CDN traffic to drift across oceans. CfDoH routes domestic and global domain lookups across concurrent upstream racing pools while enforcing EDNS0 client subnet preservation, DNSSEC authentication pass-through, and zero-runtime dependency cold starts.

---

## Public Live Demo

| Endpoint Type | Address / Link | Description |
| :--- | :--- | :--- |
| **Web Dashboard & Debug Console** | [https://doh-demo.mangoqwq.com/](https://doh-demo.mangoqwq.com/) | Real-time query workbench, upstream latency, and win-rate charts |
| **Standard DoH Endpoint** | `https://doh-demo.mangoqwq.com/doh` | Standard RFC 8484 wire format interface (GET / POST) |
| **Google JSON API** | [`https://doh-demo.mangoqwq.com/json?name=github.com&type=A`](https://doh-demo.mangoqwq.com/json?name=github.com&type=A) | Browser-navigable JSON response for instant diagnostics |
| **Health Probe** | [`https://doh-demo.mangoqwq.com/healthz`](https://doh-demo.mangoqwq.com/healthz) | Process uptime, upstream configurations, and metrics counters |

> **Notice on Public Demo Fair Use**:
> - The demo instance is intended strictly for developer testing and connectivity validation. Do not configure it as an authoritative gateway for routers or production fleets.
> - Protected by Cloudflare WAF rate limiting (30 requests per 10s per IP). Exceeding limits triggers standard HTTP 429 backoff.
> - For personal or team workloads, deploy your own instance for free in minutes to take advantage of 100,000 daily queries.

---

## Core Features

### Key Advantages Over Conventional Resolvers

| Feature Matrix | Public Resolvers (1.1.1.1) | Generic CF DoH Scripts | CfDoH |
| :--- | :---: | :---: | :---: |
| **Dynamic Geolocation Routing** | Global only | Single upstream / static | Dynamic rule sets (Loyalsoldier / Custom / Overrides) |
| **Upstream Racing & High Availability** | Blackbox | Sequential failover (3s timeout) | Concurrent multi-upstream racing (fastest wins) |
| **EDNS Client Subnet (ECS)** | Stripped or unsupported | Trusts raw client XFF | Edge-verified client IP truncation (/24 and /56) |
| **Rule Failure Resilience** | N/A | Remote failure causes crashes | Single-flight fetch + KV snapshot + fallback rules |
| **DNSSEC Authentication** | Supported | Stripped or mocked AD bits | RFC-compliant DNSSEC AD bit pass-through |
| **Web Management Console** | None | Plain text error page | Interactive single-page dashboard with real-time stats |
| **Telemetry & Metrics** | Aggregated only | None | Cloudflare Analytics Engine + P95 / win-rate telemetry |
| **Zero-Downtime Rule Updates** | N/A | Requires recompilation | GitHub Actions automated sync + Webhook KV push |
| **Interface Compatibility** | Standard DoH only | Standard DoH only | RFC 8484 + RFC 7858 DoT + Google JSON API + CORS |
| **Ad / Malware Filtering** | IP-dependent | None | Optional Blocklist rules (NXDOMAIN / 0.0.0.0 sinkhole) |
| **Runtime Footprint** | N/A | Heavy NPM dependencies | Zero runtime dependencies, instant cold starts |

---

## Domain Routing Model

CfDoH complies with RFC 8484 and resolves any valid domain globally. It implements a 4-tier routing hierarchy balancing localized CDN optimization with anti-poisoning resolution:

```text
                                [ Client DNS Query ]
                                         │
                 ┌───────────────────────┴───────────────────────┐
                 ▼                                               ▼
      [ Domestic Optimized Pool ]                     [ Global Upstream Pool ]
(AliDNS & DNSPod Concurrent Racing)             (Google DNS & Cloudflare Concurrent Racing)
   + Client Subnet (ECS /24 mask)                    + Anycast Routing + DNSSEC AD Pass-through
                 │                                               │
   ├─ 1. Core Guaranteed (linux.do / github)       ├─ 3. AI Services (OpenAI / Claude / HF)
   ├─ 2. 60,000+ Regional Domains                  ├─ 3. Global Ecosystems (Docker / NPM / PyPI)
   └─ 4. Custom Private Overrides                  └─ 3. Streaming & Social (Google / YouTube / X)
```

1. **Guaranteed Fast-Path**: Hardcoded into the Worker runtime (e.g. `linux.do`, `github.com`). Always routes through optimized domestic resolvers even if remote rule sync is unreachable.
2. **Regional Direct List**: Sourced from community-verified direct lists (60,000+ records) to route domestic infrastructure, cloud providers, and media streams to regional CDN POPs.
3. **Global Upstream Pool**: All domains outside direct rules are dispatched to Google DNS and Cloudflare concurrently, delivering pure Anycast answers without regional tampering.
4. **Dynamic Private Overrides**: Push custom hostnames (DDNS, personal homelabs) via Webhooks or GitHub Actions without redeploying the Worker.

---

## Architecture

```text
Client (Browser / Clash / Surge / Mobile OS)
   │
   ▼  RFC 8484 (POST application/dns-message or GET ?dns=) / Google JSON API
Cloudflare Edge (Cloudflare Workers)
   │
   ├─ [Web Console] Root request `/` serves reactive management dashboard
   ├─ [Token Auth]  Optional ?token= or x-doh-token request authorization
   ├─ [Blocklist]   Ad/malware sinkhole (NXDOMAIN or 0.0.0.0)
   ├─ [Router]      Evaluates query against builtin overrides and synced rule sets
   ├─ [ECS Inject]  Encodes client /24 or /56 subnet into EDNS0 OPT record
   └─ [Racing Resolver (HA Engine)]
        ├─ Regional Pool → AliDNS (dns.alidns.com) vs DNSPod (doh.pub)
        └─ Global Pool   → Google DNS (dns.google) vs Cloudflare (cloudflare-dns.com)
            │
            ▼
     Selects fastest valid reply (non-truncated, non-SERVFAIL, ID matched)
            │
            ▼
     DNSSEC AD Bit Validation ──> In-Memory Cache ──> Response
```

---

## Quick Deployment

### Option A: Command-Line Deployment (Recommended)

Requires Node.js 18+ and a Cloudflare account:

```bash
# 1. Clone repository and install dependencies
git clone https://github.com/dengyie/cf-doh.git
cd cf-doh
npm install

# 2. Run unit tests and bundle production assets
npm test
npm run build

# 3. Create persistent KV namespace for rule sets (optional)
npx wrangler kv namespace create RULES_KV
# Paste generated namespace ID into wrangler.jsonc under RULES_KV

# 4. Deploy to Cloudflare Workers
npx wrangler deploy
```

### Option B: Cloudflare Web Dashboard

No local CLI tools required:

1. Log in to [Cloudflare Dashboard](https://dash.cloudflare.com/), navigate to **Workers & Pages** -> **Create application** -> **Create Worker**.
2. Assign a worker name (e.g. `cf-doh`) and click **Deploy**.
3. Select **Edit code** in the Worker management view.
4. Copy the complete contents of [`dists/worker-single.js`](dists/worker-single.js) into the online editor.
5. Click **Deploy**.

> **Custom Domain Notice**:  
> Default `*.workers.dev` subdomains frequently experience connection resets in multiple geographies. Bind a custom subdomain under **Settings -> Triggers -> Custom Domains** (e.g. `doh.yourdomain.com`).

---

## Client Configuration

Standard query endpoint: `https://doh.yourdomain.com/doh`.

### 1. Clash Verge / Mihomo / Clash Meta
```yaml
dns:
  enable: true
  listen: 0.0.0.0:1053
  ipv6: false
  enhanced-mode: fake-ip
  nameserver:
    - "https://doh.yourdomain.com/doh"
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
```

### 2. Surge
```ini
[General]
dns-server = 223.5.5.5, 119.29.29.29
doh-server = https://doh.yourdomain.com/doh
doh-format = wire
```

### 3. Apple iOS / macOS Native Encrypted DNS
Install a configuration profile specifying:
- ServerURL: `https://doh.yourdomain.com/doh`

### 4. Command-Line Verification
```bash
# Health check
curl -s "https://doh.yourdomain.com/healthz"

# Google JSON API query
curl -s "https://doh.yourdomain.com/json?name=linux.do&type=A"

# RFC 8484 test via kdig
kdig -d @doh.yourdomain.com +https=/doh linux.do A
```

---

## DoT Support (Android Private DNS)

Android native Private DNS requires RFC 7858 (DNS-over-TLS on port 853 with valid public CA certificates) and does not support DoH directly. CfDoH includes a lightweight, zero-dependency Node daemon (`src/dot.js`) that shares the exact same routing and racing engine.

```text
                ┌─────────────────────────────┐
 DoH (443) ───▶ │  Cloudflare Workers         │──┐
 RFC 8484       │  src/worker.js              │  │
                └─────────────────────────────┘  │    Rules / Blocklist / ECS Subnets
                                                 ├──▶ Concurrent Racing / Caching / DNSSEC
                ┌─────────────────────────────┐  │    (src/core.js, runtime agnostic)
 DoT (853) ───▶ │  VPS / Host Node 18+        │──┘
 RFC 7858       │  src/dot.js (node:tls)      │
                └─────────────────────────────┘
```

### Host Deployment

```bash
git clone https://github.com/dengyie/cf-doh.git
cd cf-doh

# Issue certificate using Certbot
sudo certbot certonly --standalone -d dns.example.com

# Start daemon
node src/dot.js \
  --cert /etc/letsencrypt/live/dns.example.com/fullchain.pem \
  --key /etc/letsencrypt/live/dns.example.com/privkey.pem
```

Configure Android Settings -> **Network & internet** -> **Private DNS** -> **Private DNS provider hostname**: `dns.example.com`.

---

## Environment Variables

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `DOH_PATH` | `/doh` | RFC 8484 wire format path |
| `JSON_PATH` | `/json` | Google-compatible JSON API endpoint |
| `DOMESTIC_DOH_URL` | `https://dns.alidns.com/dns-query` | Primary domestic upstream |
| `DOMESTIC_FALLBACK_DOH_URL` | `https://doh.pub/dns-query` | Concurrent secondary domestic upstream (DNSPod) |
| `GLOBAL_DOH_URL` | `https://dns.google/dns-query` | Primary global upstream |
| `GLOBAL_FALLBACK_DOH_URL` | `https://cloudflare-dns.com/dns-query` | Concurrent secondary global upstream |
| `ECS_IPV4_PREFIX` | `24` | Client IPv4 subnet bitmask |
| `ECS_IPV6_PREFIX` | `56` | Client IPv6 subnet bitmask |
| `UPSTREAM_TIMEOUT_MS` | `3000` | Upstream query timeout threshold |
| `CACHE_TTL_SECONDS` | `300` | In-memory edge cache duration (0 disables caching) |
| `DNSSEC` | `1` | Enforce DNSSEC AD bit verification pass-through |
| `DOH_TOKEN` | *(empty)* | Optional authentication token (`?token=` or `x-doh-token`) |
| `RULES_URL` | *(default list)* | URL for external routing rules |
| `BLOCK_URL` | *(empty)* | Blocklist URL for domain filtering |
| `BLOCK_ACTION` | `nxdomain` | Action on block match: `nxdomain` or `zero` (0.0.0.0 sinkhole) |
| `RULES_SYNC_SECRET` | *(empty)* | Secret key protecting `/api/rules/sync` |

---

## Local Development & Testing

All test suites execute natively in Node.js without requiring external Cloudflare mock runtimes:

```bash
npm test
npm run build
```

---

## License

Released under the [MIT License](LICENSE).

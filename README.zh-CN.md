<div align="center">

# CfDoH

**基于 Cloudflare Workers 的自研高性能 DNS-over-HTTPS 与 DNS-over-TLS 智能分流网关**

[![License](https://img.shields.io/badge/license-MIT-green.svg?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Cloudflare%20Workers-F38020.svg?style=flat-square&logo=cloudflare&logoColor=white)](https://workers.cloudflare.com/)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-5FA04E.svg?style=flat-square&logo=node.js&logoColor=white)](https://nodejs.org/)
[![Protocols](https://img.shields.io/badge/Protocols-RFC%208484%20%7C%20RFC%207858-0052CC.svg?style=flat-square)](https://datatracker.ietf.org/doc/html/rfc8484)
[![DNSSEC](https://img.shields.io/badge/DNSSEC-AD%20Pass--Through-brightgreen.svg?style=flat-square)](#安全与防污染最佳实践)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg?style=flat-square)]()

[English](./README.md) · [简体中文](./README.zh-CN.md) · [核心特性](#痛点与核心特性) · [支持网站](#支持的网站范围与分流模型) · [架构原理](#架构图解) · [快速部署](#快速部署) · [客户端配置](#客户端接入配置指南)

</div>

---

## 项目概述

**CfDoH** 是一套开源、原生 JavaScript ESM、零第三方运行时依赖的 Cloudflare Workers DNS-over-HTTPS (DoH, RFC 8484) 智能网关，并附带一个共享同一套解析核心的 DoT (DNS-over-TLS, RFC 7858) 独立入口，可直接用于 Android 系统级「私人 DNS」。

系统解决了海外公共 DoH（如 1.1.1.1、8.8.8.8）在中国大陆环境下使用时导致的 CDN 节点漂移至海外、访问变慢、部分站点连接超时的痛点，同时弥补了主流开源 Cloudflare DoH 脚本串行重试慢、盲目信任 XFF 导致投毒风险、缺乏现代 Web 运维交互等缺陷。

---

## 在线体验 Demo

| 端点类型 | 地址 / 演示链接 | 说明 |
| :--- | :--- | :--- |
| **Web 仪表盘 / 调试台** | [https://doh-demo.mangoqwq.com/](https://doh-demo.mangoqwq.com/) | 内置响应式 Web 控制台，支持实时查询调试、上游竞速延迟与胜出率看板 |
| **标准 DoH 解析端点** | `https://doh-demo.mangoqwq.com/doh` | 标准 RFC 8484 协议接口（支持 GET / POST） |
| **Google JSON API** | [`https://doh-demo.mangoqwq.com/json?name=github.com&type=A`](https://doh-demo.mangoqwq.com/json?name=github.com&type=A) | 浏览器点击即可快速测试，免命令行工具 |
| **服务探针 / 状态** | [`https://doh-demo.mangoqwq.com/healthz`](https://doh-demo.mangoqwq.com/healthz) | 查看在线运行状态与上游配置 |

> **关于公用 Demo 的安全与配额防护说明**：
> - **仅供测试与体验**：该 Demo 仅用于开发者体验、验证解析效果及连通性测试。请勿将其配置为路由器、局域网或多台生产设备的主力 DNS。
> - **已配置 Cloudflare WAF 速率限制**：为防止公用接口被恶意刷量耗尽配额，Demo 域名配置了 IP 速率限制（单 IP 限制 30 req / 10s，超速触发 HTTP 429 自动阻断）。
> - **生产环境推荐自建**：借助 Cloudflare Workers，免费自建仅需数分钟（详见下方快速部署），独享每日 100,000 次查询配额。

---

## 痛点与核心特性

### 1. 为什么不直接用 1.1.1.1 或 8.8.8.8？
- **CDN 调度漂移**：海外公共 DoH 没有境内 ECS（EDNS Client Subnet），国内大型站点（如 Bilibili、阿里云、腾讯云、各大高校镜像站）会被解析到欧美节点，网速严重受限。
- **直连站点断流**：像 `github.com`、`linux.do` 等在国内原本能够直连的站点，如果使用了海外 DNS 解析出不可达的海外 IP，就会导致无法打开。

### 2. 方案对比

| 特性对比 | 传统公共 DoH (1.1.1.1) | 传统开源 CF DoH 脚本 | CfDoH (本项目) |
| :--- | :---: | :---: | :---: |
| **国内外智能分流** | 纯全球节点 | 单一上游 / 静态分流 | 规则库动态匹配 (Loyalsoldier / 自定义 / 内置直连) |
| **上游容灾与调度** | 官方黑盒 | 串行依次重试（主上游超时等待 3s） | 全并发竞价（所有上游同时发起，取最快响应） |
| **ECS 子网注入** | 不支持或丢弃 | 信任客户端伪造的 XFF（存在投毒风险） | 仅信任 Cloudflare 边缘真实客户端 IP 掩码截断 |
| **规则库容错防护** | 无 | 远程列表损坏直接导致整个解析宕机 | 内存单飞 + KV 镜像 + 格式校验 + 失败回退 |
| **DNSSEC 支持** | 支持 | 大多数剥离或伪造 AD 位 | RFC 兼容的 DNSSEC AD 智能透传 |
| **交互式 Web 控制台** | 404 或无界面 | 简陋纯文本或 400 | 内置现代化响应式 Web 仪表盘 + 在线实时调试台 |
| **性能度量与可视化** | 仅全局统计 | 无 | Cloudflare Analytics Engine + P95 / 胜出率实时看板 |
| **规则热更新 (免部署)** | 无 | 需重新打包部署 | GitHub Action 自动同步 + Webhook 秒级推送写入 KV |
| **API 兼容性** | 仅标准 DoH | 仅标准 DoH | RFC 8484 + RFC 7858 DoT + Google JSON API + 完整 CORS |
| **广告 / 恶意拦截** | 依赖特定 IP | 无 | 可选 Blocklist 规则拦截（NXDOMAIN / 0.0.0.0） |
| **运行时依赖** | 无 | 部分依赖庞大 npm 包 | 零外部运行时依赖，秒级冷启动 |

---

## 支持的网站范围与分流模型

CfDoH 遵循标准 RFC 8484 协议规范，支持全网任意合法域名的解析。通过四层梯队分流模型，实现「境内直连精准就近调度」与「海外站点原生防污染」的统一：

```text
                              [ 用户 DNS 查询 ]
                                      │
               ┌──────────────────────┴──────────────────────┐
               ▼                                             ▼
       【境内直连加速组】                             【全球海外原生组】
 (阿里云 DNS 与 腾讯 DNSPod 并发竞速)             (Google DNS 与 Cloudflare 并发竞速)
  + 注入客户端真实 IP (ECS /24 掩码)               + 原生 Anycast IP + DNSSEC 校验
               │                                             │
   ├─ 1. 内置核心保障 (linux.do / github)         ├─ 3. 前沿 AI 基础设施 (OpenAI / Claude)
   ├─ 2. 60,000+ 境内生态 (微信/B站/淘宝/大厂云)   ├─ 3. 全球开发生态 (Docker / NPM / PyPI)
   └─ 4. 自定义热扩展 (自建私有域名/DDNS)          └─ 3. 海外社交流媒体 (YouTube / Google / X)
```

### 1. 第一梯队：内置核心保障（免配置 · 零依赖冷启动）
固化在 Worker 运行时层，即便在远端规则源宕机或无法连通的极端情况下，仍享受国内竞速组永久保底解析：
- **Linux.do 全站及子域 (`*.linux.do`)**：双路上游毫秒竞速，解决主站论坛与 CDN 资源在部分地区的超时或连接中断。
- **GitHub 生态核心 (`github.com`, `*.githubusercontent.com`, `*.githubassets.com`)**：通过国内出口并携带客户端 ECS 解析，获取最优直连 CDN IP，改善 `git clone` 速度及资源加载。

### 2. 第二梯队：60,000+ 境内主流互联网生态（本地 CDN 最优命中）
默认接入权威的 `Loyalsoldier direct-list.txt`（包含 6~8 万条全量中国大陆直连域名），经由阿里 DNS 与腾讯 DNSPod 毫秒级竞价：
- **国民社交与电商支付**：微信 (`qq.com`, `weixin.qq.com`)、淘宝、天猫、支付宝 (`alipay.com`)、京东、拼多多、美团、饿了么、滴滴出行等。
- **音视频与内容流媒体**：哔哩哔哩 (`bilibili.com`)、抖音 (`douyin.com`)、快手、爱奇艺、优酷、网易云音乐、QQ 音乐、知乎、小红书、微博等。
- **大厂云与开发者基础设施**：阿里云、腾讯云、百度智能云、华为云、火山引擎、七牛云、开源中国 (`gitee.com`)、各类国内镜像源。
- **金融政企与教育机构**：国有各大银行网银、高校教育网 (`.edu.cn`)、政务公共服务网 (`.gov.cn`)。

### 3. 第三梯队：全球海外站点与前沿 AI 服务（抗污染 + 原生 Anycast IP）
所有不在境内直连列表中的全球域名，自动进入全球组（Google DNS vs Cloudflare DNS 并发竞速）：
- **前沿 AI 服务**：OpenAI (`chatgpt.com`, `api.openai.com`)、Claude (`claude.ai`)、Hugging Face、Midjourney、Copilot 等。
- **全球开发者生态**：Docker Hub、NPM、PyPI、Rust crates.io、StackOverflow、Vercel、Supabase 等。
- **海外主流流媒体与社交**：Google、YouTube、Twitter/X、Telegram、Netflix、Spotify、Wikipedia、Reddit、Discord 等。

### 4. 第四梯队：自定义私有站点与穿透域名即时扩展
支持通过专属 Webhook 或 GitHub Actions 向 `/api/rules/sync` 推送自定义域名列表（如个人博客、NAS 穿透域名、DDNS 动态域名）。写入 KV 并在内存中秒级热生效，无需重新打包或重新部署 Worker。

---

## 架构图解

```text
Client (浏览器 / Clash / Surge / 手机系统)
   │
   ▼  RFC 8484 (POST application/dns-message 或 GET ?dns=) / Google JSON API
Cloudflare Edge (Cloudflare Workers)
   │
   ├─ [Web Console] 浏览器访问根路径 `/` → 呈现响应式交互调试仪表盘
   ├─ [Token 鉴权]  可选验证 ?token= 或 x-doh-token 鉴权防滥用
   ├─ [Blocklist]   恶意域名 / 广告拦截过滤 → 快速阻断 (NXDOMAIN / 0.0.0.0)
   ├─ [规则分流]    解析 qname → 匹配内置 override (linux.do / github) + 远程规则库
   ├─ [ECS 注入]    提取 Cloudflare 可信边缘客户端 IP (/24 或 /56) 编码 EDNS0 OPT
   └─ [并发竞价 Resolver (HA Engine)]
        ├─ 国内组并发 → 阿里云 DNS (dns.alidns.com) 与 DNSPod (doh.pub)
        └─ 全球组并发 → Google DNS (dns.google) 与 Cloudflare (cloudflare-dns.com)
            │
            ▼
    取首个有效应答 (非截断、非 SERVFAIL、ID 匹配) 
            │
            ▼
     DNSSEC AD 校验透传 ──> 内存缓存 ──> 返回客户端
```

---

## 快速部署

### 方案 A：命令行一键部署（推荐）

适合有 Node.js 与 Cloudflare 账号的开发者：

```bash
# 1. 克隆代码仓库并安装依赖
git clone https://github.com/dengyie/cf-doh.git
cd cf-doh
npm install

# 2. 本地测试与打包验证
npm test
npm run build

# 3. 创建持久化 KV 命名空间（可选，增强规则离线留存能力）
npx wrangler kv namespace create RULES_KV
# 将输出的 id 写入 wrangler.jsonc 里的 RULES_KV 中（若不填会自动降级为纯内存模式运行）

# 4. 部署至 Cloudflare Workers
npx wrangler deploy
```

### 方案 B：纯网页 Dashboard 部署

无需安装任何本地环境，只要有浏览器即可：

1. 打开 [Cloudflare Dashboard](https://dash.cloudflare.com/)，点击 **Workers & Pages** -> **Create application** -> **Create Worker**；
2. 填写服务名称（如 `cf-doh`），点击 **Deploy**；
3. 进入该 Worker 的管理页面，点击 **Edit code**；
4. 复制本仓库根目录 [`dists/worker-single.js`](dists/worker-single.js) 的全部内容，覆盖粘贴到编辑器中；
5. 点击右上角 **Deploy** 即可上线。

> **核心建议：绑定自定义域名**  
> `*.workers.dev` 官方分配的二级域名在大面积网络环境下受到干扰阻断。强烈推荐在 Worker 管理页的 **Settings -> Triggers -> Custom Domains** 绑定自己的二级域名（例如 `doh.yourdomain.com`），Cloudflare 会自动签发证书并配置好全局路由。

---

## 客户端接入配置指南

部署完成后，标准 DoH 接口为：`https://doh.yourdomain.com/doh`。

### 1. Clash Verge / Mihomo / Clash Meta
在配置文件的 `dns` 节点下配置：
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
在 `[General]` 配置段中追加：
```ini
[General]
dns-server = 223.5.5.5, 119.29.29.29
doh-server = https://doh.yourdomain.com/doh
doh-format = wire
```

### 3. Shadowrocket / Loon / Quantumult X
- **Shadowrocket**：设置 -> DNS -> 添加自定义 DNS-over-HTTPS -> 填入 `https://doh.yourdomain.com/doh`。
- **Loon**：`[General]` -> `doh-server = https://doh.yourdomain.com/doh`。

### 4. Apple iOS 14+ / macOS 11+ 原生加密 DNS
通过 Safari 打开您的域名首页，或者通过 Apple Configurator 制作包含 `dns-over-https` 描述文件：
- ServerURL: `https://doh.yourdomain.com/doh`

### 5. Android 13+ / 浏览器安全 DNS
- **Chrome / Edge / Firefox**：进入浏览器设置 -> 隐私和安全性 -> 使用安全 DNS -> 选择「自定义」-> 填入 `https://doh.yourdomain.com/doh`。
- **Android 系统级「私人 DNS (Private DNS)」**：该设置在协议上只支持 DoT（RFC 7858），不支持 DoH。请先按下一节在 VPS 上启动 `src/dot.js`，再填入持有 853 端口 TLS 证书的域名。

### 6. 命令行调试 (cURL / dig / kdig)
```bash
# 1. 服务健康检查
curl -s "https://doh.yourdomain.com/healthz"

# 2. 通过内置 Google JSON API 快速解析
curl -s "https://doh.yourdomain.com/json?name=linux.do&type=A"

# 3. 使用 kdig 测试 RFC 8484 协议
kdig -d @doh.yourdomain.com +https=/doh linux.do A
```

---

## DoT 支持（Android 私人 DNS）

除 DoH 外，CfDoH 还提供 RFC 7858 **DoT (DNS-over-TLS)** 服务端，让 Android 系统级「私人 DNS」也能用上同一套分流解析核心。

### 架构设计与原理

- **Android 私人 DNS 仅实现 RFC 7858（TLS + TCP 853）**：不接受 DoH，要求证书由系统信任的公网 CA 签发（RFC 8310 严格校验）。
- **Cloudflare Workers 仅暴露 443 上的 HTTPS**：无法监听 TCP 853，也无法承载 `node:tls` 服务。
- 因此 DoT 以独立入口 `src/dot.js` 部署在 VPS 或家庭服务器（Node 18+，`node:tls` 监听 853），零第三方运行时依赖。

```text
                ┌─────────────────────────────┐
 DoH (443) ───> │  Cloudflare Workers         │──┐
 RFC 8484       │  src/worker.js              │  │
                └─────────────────────────────┘  │    规则分流 / Blocklist / ECS 注入
                                                 ├──> 并发竞价 / 缓存 / DNSSEC 透传
                ┌─────────────────────────────┐  │    （src/core.js，运行时无关）
 DoT (853) ───> │  任意 VPS · Node 18+        │──┘
 RFC 7858       │  src/dot.js (node:tls)      │
                └─────────────────────────────┘
```

两个入口共享 `src/core.js` 的完整管线：国内/全球规则分流、Blocklist 拦截、ECS 注入、上游并发竞价、内存缓存、DNSSEC AD 透传。

### VPS 部署步骤

前提：一台 VPS，一个解析到它的主机名（如 `dns.example.com`），Node.js 18+。

```bash
# 1. 获取代码
git clone https://github.com/dengyie/cf-doh.git && cd cf-doh

# 2. 签发公网 CA 证书（Let's Encrypt）
sudo certbot certonly --standalone -d dns.example.com

# 3. 启动 DoT 服务
node src/dot.js --cert /etc/letsencrypt/live/dns.example.com/fullchain.pem \
  --key /etc/letsencrypt/live/dns.example.com/privkey.pem
```

生产环境建议使用 systemd 守护运行（`/etc/systemd/system/cf-doh-dot.service`）：

```ini
[Unit]
Description=cf-doh DoT (DNS-over-TLS, RFC 7858) server
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=/opt/cf-doh
ExecStart=/usr/bin/node src/dot.js --cert /etc/letsencrypt/live/dns.example.com/fullchain.pem --key /etc/letsencrypt/live/dns.example.com/privkey.pem
Restart=always
RestartSec=3
User=cfdoh
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ReadOnlyPaths=/etc/letsencrypt

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now cf-doh-dot

# 证书自动续期后重启服务
echo '#!/bin/sh' | sudo tee /etc/letsencrypt/renewal-hooks/deploy/cf-doh-dot.sh
echo 'systemctl try-restart cf-doh-dot' | sudo tee -a /etc/letsencrypt/renewal-hooks/deploy/cf-doh-dot.sh
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/cf-doh-dot.sh
```

---

## 生产环境最佳实践

### 1. 必备自定义二级域名
避免使用默认分配的 `*.workers.dev` 域名。Cloudflare 默认的 `workers.dev` 二级域名在较多运营商网络环境下存在连接干扰，推荐在 Worker 后台绑定自己的二级域名。

### 2. 代理客户端协同最佳实践 (Clash / Mihomo / Surge)
- **避免 DNS 解析死循环**：在客户端的 `hosts` 节点中将 `doh.yourdomain.com` 静态绑定，或在 `nameserver-policy` 中指定使用基础直连 DNS 解析该 DoH 域名本身。
- **Mihomo / Clash Verge 最佳参数**：搭配 `enhanced-mode: fake-ip` 使用。将 `cf-doh` 作为主 `nameserver`，配合国内公共 DNS（如 `223.5.5.5`）作为 `default-nameserver`。

### 3. ECS 隐私与地域调度最佳平衡：保持 /24 与 /56 掩码
- 默认设置 `ECS_IPV4_PREFIX = 24` 与 `ECS_IPV6_PREFIX = 56`。
- `/24` 会自动把 IP 的最后一段置 0（如 `1.2.3.4` → `1.2.3.0/24`），既精确告知了上游用户所在的运营商与省市级网段，又保护了终端个人隐私。

### 4. 规则自动化更新：启用 GitHub Actions 每日同步
项目自带的 `.github/workflows/sync-rules.yml` 会在每天 UTC 04:00 自动抓取社区最新直连库，与 `sample-rules/direct-personal.txt` 合并后通过 Webhook 推送至 Worker KV，实现全自动免维护更新。

### 5. 广告拦截与黑名单联动
在 Worker 环境变量中配置 `BLOCK_URL`（指向反广告规则源），并将 `BLOCK_ACTION` 设为 `zero`。命中黑名单的域名将在 Cloudflare 边缘瞬间返回 `0.0.0.0` 黑洞地址。

---

## 环境变量与进阶配置

所有参数均可在 `wrangler.jsonc` 的 `vars` 或 Cloudflare 控制台环境变量中配置：

| 环境变量 | 默认值 | 作用与说明 |
| :--- | :--- | :--- |
| `DOH_PATH` | `/doh` | RFC 8484 查询路径 |
| `JSON_PATH` | `/json` | Google 风格 JSON API 路径 |
| `DOMESTIC_DOH_URL` | `https://dns.alidns.com/dns-query` | 国内组主上游 |
| `DOMESTIC_FALLBACK_DOH_URL` | `https://doh.pub/dns-query` | 国内组并发备用上游（腾讯 DNSPod） |
| `GLOBAL_DOH_URL` | `https://dns.google/dns-query` | 全球组主上游 |
| `GLOBAL_FALLBACK_DOH_URL` | `https://cloudflare-dns.com/dns-query` | 全球组并发备用上游 |
| `ECS_IPV4_PREFIX` | `24` | IPv4 注入掩码 |
| `ECS_IPV6_PREFIX` | `56` | IPv6 注入掩码 |
| `UPSTREAM_TIMEOUT_MS` | `3000` | 单个上游超时熔断时间（毫秒） |
| `CACHE_TTL_SECONDS` | `300` | 边缘内存热缓存最大时间（秒）；为 `0` 则停用缓存 |
| `DNSSEC` | `1` | 启用 DNSSEC AD 位透传（`1` 开启，`0` 关闭） |
| `DOH_TOKEN` | 空 | 可选访问令牌。设置后请求须带 `?token=xxx` 或标头 `x-doh-token` |
| `RULES_URL` | 默认国内列表 | 外部规则源 URL（每行一个域名，支持 `full:` 及 `regexp:`） |
| `BLOCK_URL` | 空 | 拦截黑名单 URL。设置后命中域名直接拦截 |
| `BLOCK_ACTION` | `nxdomain` | 拦截行为：`nxdomain`（不存在）或 `zero`（黑洞 0.0.0.0/::） |
| `RULES_SYNC_SECRET` | 空 | 规则同步 Webhook 密钥。用于 GitHub Actions 或第三方推送规则至 `/api/rules/sync` |

---

## 统计度量与可视化监控

### 1. 内置 Web 监控看板
访问 Worker 首页（如 `https://doh.yourdomain.com/`）即可使用可视化仪表盘：
- **本地 PoP 边缘 vs 全球多地域聚合**：支持查看单个边缘节点的低延迟内存采样，或通过 Analytics Engine SQL API 聚合全球所有 PoP 节点的汇总度量。
- **国内组竞速 (AliDNS vs DNSPod)**：实时展示两者的胜出次数与比例，以及 P50 / P95 / Avg 解析延迟。
- **全球组竞速 (Google vs Cloudflare)**：实时对比两大全球 DNS 的胜出份额与链路时延。
- **边缘缓存指标**：直观反映缓存命中率（Cache Hit Rate）、服务运行时间及请求总量。

### 2. 结构化度量接口
- `GET /api/stats`：当前 Worker 实例的内存采样统计。
- `GET /api/stats?scope=global`：聚合全球所有边缘节点指标。
- `GET /healthz`：包含系统运行时间、计数器指标及最新配置。

---

## 本地开发与测试

本项目测试完全脱离外部云环境，直接在本地 Node.js 运行：

```bash
# 运行全套单元测试与集成测试
npm test

# 重新构建单文件生产包
npm run build
```

---

## 参与贡献与许可证

欢迎提交 Issue 和 Pull Request！在贡献代码前，请参阅 [CONTRIBUTING.md](CONTRIBUTING.md)。

本项目基于 [MIT License](LICENSE) 协议发布。

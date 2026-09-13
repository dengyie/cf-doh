<div align="center">

# ⚡ cf-doh

### High-Performance Self-Hosted DNS-over-HTTPS Resolver on Cloudflare Workers
**专为国内直连加速与防污染定制的自研高性能 DoH 解析网关**

[![CI Status](https://github.com/dengyie/cf-doh/actions/workflows/ci.yml/badge.svg)](https://github.com/dengyie/cf-doh/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Cloudflare Workers](https://img.shields.io/badge/Platform-Cloudflare%20Workers-F38020?logo=cloudflare)](https://workers.cloudflare.com/)
[![RFC 8484 Compliant](https://img.shields.io/badge/RFC-8484-success.svg)](https://tools.ietf.org/html/rfc8484)
[![DNSSEC Ready](https://img.shields.io/badge/DNSSEC-AD%20Pass--through-brightgreen.svg)](#-安全与防污染)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0%20(Pure%20ESM)-orange.svg)](#-设计哲学)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/dengyie/cf-doh/pulls)

<p align="center">
  <a href="#-痛点与核心特性">核心特性</a> •
  <a href="#-架构图解">架构原理</a> •
  <a href="#-极速部署">极速部署</a> •
  <a href="#-客户端接入配置指南">客户端配置</a> •
  <a href="#-进阶玩法">进阶玩法</a> •
  <a href="#-本地开发与测试">本地测试</a> •
  <a href="#-license">开源许可</a>
</p>

</div>

---

## 📖 项目简介

`cf-doh` 是一套**开源、纯原生 JavaScript ESM、零第三方运行时依赖**的 Cloudflare Workers DNS-over-HTTPS (DoH, RFC 8484) 智能网关。

它彻底解决了普通海外公共 DoH（如 1.1.1.1、8.8.8.8）在中国大陆环境下使用时导致的 **CDN 节点漂移至海外、访问变慢、部分站点连接超时** 的致命痛点，同时弥补了主流开源 Cloudflare DoH 脚本**串行重试慢、盲目信任 XFF 导致投毒风险、缺乏现代 Web 运维交互**等缺陷。

---

## 🔥 痛点与核心特性

### 1. 为什么不直接用 1.1.1.1 或 8.8.8.8？
- **CDN 乱飘**：海外公共 DoH 没有境内 ECS（EDNS Client Subnet），国内大型站点（如 Bilibili、阿里云、腾讯云、各大高校镜像站）会被解析到欧美节点，网速从百兆直降到几百 KB。
- **直连站点断流**：像 `github.com`、`linux.do` 等在国内原本能够直连的站点，如果使用了海外 DNS 解析出被污染或不可达的海外 IP，就会导致无法打开。

### 2. 为什么写 cf-doh？（与主流开源方案对比）

| 特性对比 | 传统公共 DoH (1.1.1.1) | 传统开源 CF DoH 脚本 | **cf-doh (本项目)** |
| :--- | :---: | :---: | :---: |
| **国内外智能分流** | ❌ 纯全球节点 | ⚠️ 单一上游 / 静态分流 | **✅ 规则库动态匹配 (Loyalsoldier / 自定义 / 内置直连)** |
| **上游容灾与调度** | ❌ 官方黑盒 | ❌ 串行依次重试（主上游超时白等 3s） | **🚀 全并发竞价（所有上游同时发起，取最快响应）** |
| **ECS 子网注入** | ❌ 不支持或丢弃 | ⚠️ 信任客户端伪造的 `XFF`（易被投毒） | **🛡️ 仅信任 Cloudflare 边缘 `cf-connecting-ip` 掩码截断** |
| **规则库容错防护** | ❌ 无 | ❌ 远程列表损坏直接导致整个解析宕机 | **🔒 内存单飞 + KV 镜像 + 格式强校验 + 失败回退** |
| **DNSSEC 支持** | ✅ 支持 | ❌ 大多数剥离或伪造 AD 位 | **✅ RFC 兼容的 DNSSEC AD 智能透传** |
| **交互式 Web 控制台** | ❌ 404 或无界面 | ❌ 简陋纯文本或 400 | **✨ 内置现代化响应式 Web 仪表盘 + 在线实时调试台** |
| **性能度量与可视化** | ❌ 仅全局统计 | ❌ 无 | **📊 Cloudflare Analytics Engine + P95 / 胜出率实时可视化看板** |
| **规则热更新 (免部署)** | - | ❌ 需重新打包部署 | **⚡ GitHub Action 自动同步 + Webhook 秒级推送写入 KV** |
| **API 兼容性** | 仅标准 DoH | 仅标准 DoH | **✅ RFC 8484 + Google 风格 JSON API + 完整 CORS** |
| **广告 / 恶意拦截** | 依赖特定 IP | ❌ 无 | **🛡️ 可选 Blocklist 规则拦截（NXDOMAIN / 0.0.0.0）** |
| **运行时依赖** | - | 部分依赖庞大 npm 包 | **🌱 0 外部运行时依赖，秒级冷启动** |

---

## 🏗️ 架构图解

```
Client (浏览器 / Clash / Surge / 手机系统)
   │
   ▼  RFC 8484 (POST application/dns-message 或 GET ?dns=) / Google JSON API
Cloudflare Edge (Cloudflare Workers)
   │
   ├─ [Web Console] 浏览器访问根路径 `/` → 呈现响应式交互调试仪表盘
   ├─ [Token 鉴权]  可选验证 ?token= 或 x-doh-token 防白嫖
   ├─ [Blocklist]   恶意域名 / 广告拦截过滤 → 快速阻断 (NXDOMAIN / 0.0.0.0)
   ├─ [规则分流]    解析 qname → 匹配内置 override (linux.do / github) + 远程规则库
   ├─ [ECS 注入]    提取 Cloudflare 可信边缘客户端 IP (/24 或 /56) 编码 EDNS0 OPT
   └─ [并发竞价 Resolver (HA Engine)]
        ├─ 🇨🇳 国内组并发 → 阿里云 DNS (dns.alidns.com) ⚔️ DNSPod (doh.pub)
        └─ 🌐 全球组并发 → Google DNS (dns.google) ⚔️ Cloudflare (cloudflare-dns.com)
            │
            ▼
    取首个有效应答 (非截断、非 SERVFAIL、ID 匹配) 
            │
            ▼
     DNSSEC AD 校验透传 ──> 内存缓存 ──> 返回客户端
```

---

## ⚡ 极速部署

### 方案 A：命令行一键部署（推荐）

适合有 Node.js 与 Cloudflare 账号的开发者：

```bash
# 1. 克隆仓库并安装依赖
git clone https://github.com/dengyie/cf-doh.git
cd cf-doh
npm install

# 2. 本地测试与打包验证
npm test
npm run build

# 3. 创建持久化 KV 命名空间（可选，增强规则离线留存能力）
npx wrangler kv namespace create RULES_KV
# 将输出的 id 复制填入 wrangler.jsonc 里的 RULES_KV 中（若不填会自动降级为纯内存模式运行）

# 4. 部署至 Cloudflare Workers
npx wrangler deploy
```

### 方案 B：纯网页 Dashboard 0 命令行部署

无需安装任何本地环境，只要有浏览器即可：

1. 打开 [Cloudflare Dashboard](https://dash.cloudflare.com/)，点击 **Workers & Pages** -> **Create application** -> **Create Worker**；
2. 填写服务名称（如 `cf-doh`），点击 **Deploy**；
3. 进入该 Worker 的管理页面，点击 **Edit code**（编辑代码）；
4. 复制本仓库根目录 [`dists/worker-single.js`](dists/worker-single.js) 的全部内容，完整覆盖粘贴到左侧编辑器中；
5. 点击右上角 **Deploy** 即可上线！

> 💡 **核心建议：绑定自定义域名**  
> `*.workers.dev` 官方分配的二级域名在大面积网络环境下受到干扰阻断。强烈推荐在 Worker 管理页的 **Settings -> Triggers -> Custom Domains** 绑定您自己的二级域名（例如 `doh.yourdomain.com`），Cloudflare 会自动签发证书并配置好全局路由。

---

## 📱 客户端接入配置指南

一旦部署完成，您的标准 DoH 接口为：`https://doh.yourdomain.com/doh`。

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
- **Loon**：[General] -> `doh-server = https://doh.yourdomain.com/doh`。

### 4. Apple iOS 14+ / macOS 11+ 原生加密 DNS
通过 Safari 打开您的域名首页，或者通过 Apple Configurator 制作包含 `dns-over-https` 描述文件：
- ServerURL: `https://doh.yourdomain.com/doh`

### 5. Android 13+ / 浏览器安全 DNS
- **Chrome / Edge / Firefox**：进入浏览器设置 -> 隐私和安全性 -> 使用安全 DNS -> 选择「自定义」-> 填入 `https://doh.yourdomain.com/doh`。

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

## 🎛️ 环境变量与进阶配置

所有参数均可在 `wrangler.jsonc` 的 `vars` 或 Cloudflare 控制台环境变量中自由定制：

| 环境变量 | 默认值 | 作用与说明 |
| :--- | :--- | :--- |
| `DOH_PATH` | `/doh` | RFC 8484 查询路径 |
| `JSON_PATH` | `/json` | Google 风格 JSON API 路径（如 `?name=...&type=A`） |
| `DOMESTIC_DOH_URL` | `https://dns.alidns.com/dns-query` | 国内组主上游 |
| `DOMESTIC_FALLBACK_DOH_URL` | `https://doh.pub/dns-query` | 国内组并发备用上游（腾讯 DNSPod） |
| `GLOBAL_DOH_URL` | `https://dns.google/dns-query` | 全球组主上游 |
| `GLOBAL_FALLBACK_DOH_URL` | `https://cloudflare-dns.com/dns-query` | 全球组并发备用上游 |
| `ECS_IPV4_PREFIX` | `24` | IPv4 注入掩码（/24 既能精准识别地域又保护隐私） |
| `ECS_IPV6_PREFIX` | `56` | IPv6 注入掩码 |
| `UPSTREAM_TIMEOUT_MS` | `3000` | 单个上游超时熔断时间（毫秒） |
| `CACHE_TTL_SECONDS` | `300` | 边缘内存热缓存最大时间（秒）；为 `0` 则停用缓存 |
| `DNSSEC` | `1` | 启用 DNSSEC AD 位透传（`1` 开启，`0` 关闭） |
| `DOH_TOKEN` | *(空)* | 可选访问令牌。设置后请求须带 `?token=xxx` 或标头 `x-doh-token` |
| `RULES_URL` | *(默认国内列表)* | 外部规则源 URL（每行一个域名，支持 `full:` 及 `regexp:`） |
| `BLOCK_URL` | *(空)* | 拦截黑名单 URL。设置后命中域名直接拦截 |
| `BLOCK_ACTION` | `nxdomain` | 拦截行为：`nxdomain`（不存在）或 `zero`（黑洞 0.0.0.0/::） |
| `RULES_SYNC_SECRET` | *(空)* | 规则同步 Webhook 密钥。用于 GitHub Actions 或第三方推送规则至 `/api/rules/sync` |

---

## 📊 统计度量与可视化监控 (Analytics Engine)

本项目实现了低开销的边缘性能监控与胜出率实时度量：

### 1. 内置 Web 监控看板
访问您的 Worker 首页（如 `https://doh.yourdomain.com/`），即可看到可视化的监控看板：
- **📍 本地 PoP 边缘 vs 🌐 全球多地域聚合**：控制台内置无缝切换开关，支持查看单个 Cloudflare 边缘节点的低延迟内存采样，或通过 Analytics Engine SQL API 聚合全球所有 PoP 节点的汇总度量！
- **🇨🇳 国内组竞速 (AliDNS vs DNSPod)**：实时展示两者的胜出次数与比例进度条，以及 P50 / P95 / Avg 解析延迟。
- **🌐 全球组竞速 (Google vs Cloudflare)**：实时对比两大全球 DNS 的胜出份额与链路时延。
- **📦 边缘缓存与请求指标**：直观反映缓存命中率（Cache Hit Rate）、服务运行时间及请求总量。

### 2. 结构化度量接口
- **本地 PoP 竞速统计**：`GET /api/stats`（秒级输出当前 Worker 实例的内存采样统计）。
- **全球跨 PoP 聚合统计**：`GET /api/stats?scope=global` 或 `GET /api/stats/global`（执行 Cloudflare Analytics Engine SQL API 聚合全球所有边缘节点指标）。
- **节点健康检查**：`GET /healthz`（包含系统运行时间、各计数器指标及最新配置）。

### 3. Cloudflare Workers Analytics Engine 接入与全球聚合配置
在 `wrangler.jsonc` 中已预置配置：
```jsonc
"analytics_engine_datasets": [
  { "binding": "DOH_ANALYTICS", "dataset": "cf_doh_metrics" }
]
```
每次解析请求完成后，Worker 会自动异步打点上报至 Cloudflare Analytics Engine：
- **Blobs**：`[winningUpstream, group, qtype, rcode, cacheStatus]`
- **Doubles**：`[durationMs]`
- **Indexes**：`[winningUpstream]`

**开启全球多地域 SQL 聚合（可选）**：
1. 在 Cloudflare Dashboard 的 **Workers & Pages -> Analytics Engine** 点击 **Enable**（免费功能）；
2. 在 Worker 环境变量或 `wrangler.jsonc` 的 `vars` 中配置：
   - `CF_ACCOUNT_ID`: 您的 Cloudflare 账户 ID
   - `CF_ANALYTICS_READ_TOKEN`: 具备 `Account Analytics Read` 权限的 API Token
3. 前端控制台点击「🌐 全球多地域聚合」或请求 `/api/stats?scope=global` 即可自动执行聚合分析！如果未配置凭据，系统会自动平滑降级至本地 PoP 实时指标。

---

## ⚡ 规则自动热更新 (GitHub Actions & Webhook)

无需重新打包或部署 Worker，即可实现国内直连规则的每日自动更新与 KV 持久化！

### 1. 自动化流水线 (`.github/workflows/sync-rules.yml`)
仓库内置了生产级 GitHub Actions 定时同步工作流：
1. **定时触发**：每天 UTC 04:00 自动从上游（如 Loyalsoldier release）抓取最新直连域名。
2. **个人保障**：自动合并本地 [`sample-rules/direct-personal.txt`](sample-rules/direct-personal.txt)，确保 `linux.do`、`github.com` 直连绝对不丢失。
3. **格式强校验**：过滤空行与脏注释，校验关键域名存在性，拦截 HTML 异常响应。
4. **一键推送**：通过 Worker 专属 Webhook 接口将规则推送到 Cloudflare KV 并热加载到内存。

### 2. 配置 GitHub 仓库 Secrets
在您 Fork 或私有的本仓库中进入 **Settings -> Secrets and variables -> Actions**，添加以下密钥：
- `DOH_ENDPOINT`：您的 Worker 完整域名（例如 `https://doh.yourdomain.com`）。
- `RULES_SYNC_SECRET`：在 Worker 环境变量中配置的同步密钥。
- *(可选)* `CLOUDFLARE_API_TOKEN` 与 `CLOUDFLARE_ACCOUNT_ID`：若需要 Action 直接调用 Wrangler 写入 KV 时提供。

### 3. 手动或第三方 Webhook 触发
```bash
# Push 模式：直接推送自定义规则文本
curl -X POST "https://doh.yourdomain.com/api/rules/sync" \
  -H "Authorization: Bearer YOUR_SYNC_SECRET" \
  -H "Content-Type: text/plain" \
  --data-binary @my-rules.txt

# Pull 模式：触发 Worker 立即重新拉取远程 RULES_URL
curl -X POST "https://doh.yourdomain.com/api/rules/sync" \
  -H "Authorization: Bearer YOUR_SYNC_SECRET"
```

---

## 🎯 进阶玩法

### 1. 强制特定站点国内直连 (如 linux.do / 自建私有域名)
`src/rules.js` 中内置了 `BUILTIN_OVERRIDE` 核心名单（`linux.do`, `github.com` 等），即便外部网络波动无法拉取外部列表，这些域名也**绝对保底直连**，始终通过阿里云获取带国内 ECS 的最优 IP。  
如需追加个人专属规则，只需在环境变量中设置 `RULES_URL` 指向您自己的 GitHub Gist 或 CDN 文件（可参考 [`sample-rules/direct-personal.txt`](sample-rules/direct-personal.txt)）。

### 2. 广告过滤与恶意域名黑洞
在环境变量中配置 `BLOCK_URL`（指向去广告规则列表）并设置 `BLOCK_ACTION="zero"`：  
所有广告域名将在 Workers 边缘被瞬间拦截并直接返回 `0.0.0.0`，毫秒响应且不消耗任何上游流量！

---

## 🧪 本地开发与测试

本项目保持极度纯粹的技术底座，测试**完全脱离外部云环境**，直接在本地 Node.js 原生运行：

```bash
# 运行全套单元测试与集成测试
npm test

# 重新构建单文件生产包
npm run build
```

**测试套件包含**：
- `dns.test.mjs`：DNS 二进制 Wire-format 解码、打包与边界溢出校验
- `cache.test.mjs`：基于 ECS 隔离与 TTL 淘汰的内存缓存机制
- `routing.mjs`：境内外域名规则分流与内置重载测试
- `ecs.forward.mjs`：EDNS0 OPT 客户端子网精准注入测试
- `filter-json-dnssec.mjs`：DNSSEC AD 透传、Google JSON API、Blocklist 黑名单拦截验证
- `landing.cors.mjs`：跨域预检与 Web 仪表盘交互测试
- `bundle.smoke.mjs`：esbuild 单文件打包冒烟测试

---

## 🤝 参与贡献

欢迎提交 Issue 和 Pull Request！在贡献代码前，请参阅 [CONTRIBUTING.md](CONTRIBUTING.md)。

---

## 📄 License

本项目采用 [MIT License](LICENSE) 开源许可。自由使用、修改与分发，欢迎 Star 🌟 支持！

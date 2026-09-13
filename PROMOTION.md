# 📢 cf-doh 全平台推广发布文案集锦

本项目针对常见公共 DoH 在中国大陆地区导致的「CDN 乱飘海外、github/linux.do 直连站点降速、开源脚本串行超时」等顽疾进行了彻底优化。以下针对各社区风格定制了推广文案，方便一键复制发布。

---

## 1. Linux.do 论坛专用贴（推荐板块：开发调优 / 搞七拧八 / 资源荟萃）

**帖子标题**：  
【开源自研】受够了 DoH 导致 CDN 乱飘？搞了个跑在 CF Workers 上的智能 DoH 网关，并发竞价+可信 ECS，linux.do/github 绝对直连！

**帖子正文**：

各位佬友好！

相信不少自建 DoH 或者用公共 DoH（比如 1.1.1.1、8.8.8.8）的佬友都遇到过这几个抓狂的痛点：
1. **国内网站 CDN 乱飘**：用了海外 DoH，B站、腾讯、阿里甚至高校镜像站被解析到了美国或欧洲节点，千兆宽带瞬间变成几百 K。
2. **直连站点断流**：像我们心爱的 `linux.do` 以及 `github.com`，本来国内能直连，一旦解析出污染或者被阻断的海外 IP，直接连接超时。
3. **现有的开源 Workers 脚本太拉胯**：我看过 GitHub 上几个主流方案（如 CF-Workers-DoH 等），遇到上游故障居然是**逐个串行重试**，主上游超时得白等 3 秒；而且盲目转发客户端伪造的 `X-Forwarded-For`，极其容易被投毒。

忍不住自己动手写了一个完全符合 RFC 8484 标准的自研方案：**cf-doh**。

### ✨ 核心特性：
- 🏎️ **全上游并发竞价 (Zero Penalty)**：国内组（阿里 ⚔️ 腾讯 DNSPod）与全球组（Google ⚔️ Cloudflare）各上游同时并发请求，延迟取最小值！单个上游抖动完全无感。
- 🛡️ **绝对可信的 ECS 注入**：严格从 Cloudflare 边缘提取真实 `cf-connecting-ip` 截断子网，过滤伪造的 XFF，让 CDN 精准调度到离你最近的国内机房。
- 🔒 **linux.do / github 专属硬核守护**：内置绝对直连保护层，就算外部网络波动、规则源挂掉，`linux.do` 依然 100% 走国内高速直连解析！
- 🖥️ **内置 Web 交互式测试台**：浏览器直接打开域名即可进入高颜值控制台，在线输入域名实时测试分流、延迟与 IP，还能一键生成 Clash / Surge / iOS / Android 配置代码！
- 🚀 **零外部运行时依赖**：纯原生 JavaScript ESM，秒级冷启动，支持 Workers 免费版，支持网页端直接复制代码一键部署。
- 🛡️ **DNSSEC AD 智能透传 + Google JSON API 兼容 + 广告拦截黑名单**。

项目已全部开源并配置了全套测试与 CI，欢迎各位佬友 Star ⭐️ 体验或提 PR 交流！

👉 **GitHub 仓库**：https://github.com/dengyie/cf-doh  
👉 **在线部署教程与客户端接入**：详见仓库 README，支持 2 分钟无代码网页端部署！

---

## 2. V2EX 社区（推荐节点：/go/programmer 或 /go/dns）

**帖子标题**：  
[分享] 自研开源 cf-doh：基于 Cloudflare Workers 的高性能 DNS-over-HTTPS 解析网关（并发竞价 / 可信 ECS / 纯 ESM 零依赖）

**帖子正文**：

各位 V 友大家好，

在日常开发与网络优化中，DNS 解析质量直接决定了首包延迟与 CDN 命中率。市面上现有的 DoH 方案在处理「境内直连加速 + 境外防污染」时，普遍存在以下不足：
- 海外公共 DoH 缺乏境内 ECS，导致国内各大站点 CDN 调度漂移；
- 社区现有 Cloudflare Workers 脚本大多采用串行 Fallback，遇上游单点抖动会有明显的 2~3 秒等待惩罚；
- 部分脚本简单粗暴透传客户端的 `X-Forwarded-For`，存在被构造请求投毒解析结果的安全隐患。

为此我用原生 JavaScript 开发了 **cf-doh**，并在本地实现了完整的 RFC 8484 报文编解码与自动化测试套件。

### 核心设计点：
1. **并发竞价调度引擎（Resolver Race Group）**：
   分组内（国内组：AliDNS + DNSPod；全球组：Google + Cloudflare）所有上游全并发查询，选取首个「ID 匹配、非截断、非 SERVFAIL」的有效响应，延迟由最快上游决定。
2. **边缘可信 ECS 注入**：
   抛弃非可信客户端请求头，严格提取 Cloudflare 边缘环境校验过的 `cf-connecting-ip`，按照 IPv4 /24、IPv6 /56 进行掩码截断并拼接 EDNS0 OPT 报文。
3. **多层规则容灾机制**：
   内存热缓存 + KV 持久化 + 外部列表强校验（防止 HTML 错误页毒化）+ 核心域名内置保底规则。
4. **全套 API 与交互支持**：
   除标准 RFC 8484 wire-format 外，内置 Google 风格 JSON API (`/json?name=...&type=A`) 与全跨域 CORS 支持，根路径自适应响应 Web 诊断控制台。

项目采用 MIT 协议开源，无任何运行时 npm 依赖，在 GitHub Actions 上保持自动化多版本 Node 测试覆盖。欢迎大家试用与交流建议！

- 仓库地址：https://github.com/dengyie/cf-doh
- 详细文档与接入指南：详见 README

---

## 3. Telegram 频道 / 极客群分享文案

⚡ **【开源推荐】cf-doh — 自研 Cloudflare Workers 高性能 DoH 解析网关**

告别传统 DoH 国内 CDN 乱飘海外与串行重试卡顿！

🎯 **三大杀手锏**：
1. **全上游并发竞价**：阿里、腾讯、Google、CF 同时竞速，取最快返回，上游抽风零感知；
2. **边缘可信 ECS 注入**：基于 CF 真实客户端 IP 截断子网，国内直连站点秒开，精准调度最优 CDN；
3. **高颜值 Web 控制台**：自带浏览器在线测试台与 Clash / Surge / iOS / Windows 客户端一键配置生成器！

💡 纯原生 JS 实现，零运行时依赖，Cloudflare 免费版即开即用，支持网页端一键粘贴部署。

🔗 **项目地址**：https://github.com/dengyie/cf-doh

---

## 4. X (Twitter) 推文（中英双语推）

Tired of slow CDN routing when using overseas DoH in China? 🚀

I open-sourced **cf-doh** — a high-performance, self-hosted DNS-over-HTTPS (RFC 8484) gateway on Cloudflare Workers!

🔥 Highlights:
- 🏎️ Concurrent upstream racing (Zero failover latency penalty)
- 🛡️ Trusted ECS subnet injection from Cloudflare edge IP
- 🇨🇳 Domain-based split-routing (AliDNS/DNSPod vs Google/CF)
- ✨ Built-in interactive web console & config generator
- 🌱 Zero runtime dependencies (Pure ESM)

Check it out: https://github.com/dengyie/cf-doh

#DNS #DoH #Cloudflare #OpenSource #Networking #WebDev

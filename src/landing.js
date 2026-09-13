/**
 * Built-in Interactive Web Console & Landing Page for cf-doh.
 *
 * Provides:
 *  - Modern, responsive Dark/Light UI (Tailwind-like aesthetics with zero external dependencies)
 *  - Live DNS Playground: test domain queries directly in browser against /json API
 *  - Split-routing & ECS visualizer (Domestic/Global indicator, latency, records)
 *  - One-click configuration generator for Mihomo, Clash, Surge, Shadowrocket, iOS, Android, Windows
 *  - Quick metrics & node health preview
 */

export function renderLandingHtml(origin, config) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>cf-doh — 高性能自研 Cloudflare Workers DoH 解析网关</title>
  <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>⚡</text></svg>">
  <style>
    :root {
      --bg: #0b0f19;
      --card-bg: rgba(23, 32, 54, 0.7);
      --card-border: rgba(255, 255, 255, 0.08);
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --primary: #3b82f6;
      --primary-hover: #2563eb;
      --accent: #10b981;
      --accent-orange: #f59e0b;
      --code-bg: #060911;
    }
    @media (prefers-color-scheme: light) {
      :root {
        --bg: #f8fafc;
        --card-bg: rgba(255, 255, 255, 0.9);
        --card-border: rgba(0, 0, 0, 0.08);
        --text: #0f172a;
        --text-muted: #64748b;
        --primary: #2563eb;
        --primary-hover: #1d4ed8;
        --accent: #059669;
        --accent-orange: #d97706;
        --code-bg: #f1f5f9;
      }
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding: 0;
      overflow-x: hidden;
    }
    .container {
      max-width: 1080px;
      margin: 0 auto;
      padding: 40px 20px 80px 20px;
    }
    header {
      text-align: center;
      margin-bottom: 48px;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 12px;
      border-radius: 9999px;
      font-size: 0.85rem;
      font-weight: 500;
      background: rgba(59, 130, 246, 0.15);
      color: #60a5fa;
      border: 1px solid rgba(59, 130, 246, 0.3);
      margin-bottom: 16px;
    }
    h1 {
      font-size: 2.75rem;
      font-weight: 800;
      letter-spacing: -0.025em;
      margin-bottom: 12px;
      background: linear-gradient(135deg, #60a5fa 0%, #3b82f6 50%, #93c5fd 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .subtitle {
      font-size: 1.15rem;
      color: var(--text-muted);
      max-width: 680px;
      margin: 0 auto 24px auto;
    }
    .tags {
      display: flex;
      flex-wrap: wrap;
      justify-content: center;
      gap: 8px;
    }
    .tag {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 0.8rem;
      color: var(--text-muted);
    }
    .grid {
      display: grid;
      grid-template-columns: 1fr;
      gap: 24px;
      margin-bottom: 32px;
    }
    @media (min-width: 768px) {
      .grid-2 { grid-template-columns: 1fr 1fr; }
    }
    .card {
      background: var(--card-bg);
      backdrop-filter: blur(12px);
      border: 1px solid var(--card-border);
      border-radius: 16px;
      padding: 24px;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.1);
    }
    .card-title {
      display: flex;
      align-items: center;
      gap: 10px;
      font-size: 1.25rem;
      font-weight: 600;
      margin-bottom: 16px;
    }
    .input-group {
      display: flex;
      gap: 8px;
      margin-bottom: 16px;
    }
    input[type="text"] {
      flex: 1;
      padding: 10px 14px;
      border-radius: 8px;
      border: 1px solid var(--card-border);
      background: var(--code-bg);
      color: var(--text);
      font-size: 0.95rem;
      outline: none;
      transition: border-color 0.2s;
    }
    input[type="text"]:focus {
      border-color: var(--primary);
    }
    select {
      padding: 10px 12px;
      border-radius: 8px;
      border: 1px solid var(--card-border);
      background: var(--code-bg);
      color: var(--text);
      font-size: 0.95rem;
      outline: none;
      cursor: pointer;
    }
    button.btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      padding: 10px 18px;
      background: var(--primary);
      color: #fff;
      border: none;
      border-radius: 8px;
      font-weight: 600;
      font-size: 0.95rem;
      cursor: pointer;
      transition: all 0.2s;
    }
    button.btn:hover { background: var(--primary-hover); transform: translateY(-1px); }
    .quick-chips {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-bottom: 16px;
    }
    .chip {
      background: var(--code-bg);
      border: 1px solid var(--card-border);
      padding: 3px 8px;
      border-radius: 6px;
      font-size: 0.8rem;
      color: var(--text-muted);
      cursor: pointer;
      transition: all 0.2s;
    }
    .chip:hover { color: var(--primary); border-color: var(--primary); }
    .result-box {
      background: var(--code-bg);
      border-radius: 10px;
      padding: 16px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.88rem;
      border: 1px solid var(--card-border);
      min-height: 120px;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
    }
    .tabs {
      display: flex;
      gap: 6px;
      border-bottom: 1px solid var(--card-border);
      margin-bottom: 16px;
      overflow-x: auto;
      padding-bottom: 6px;
    }
    .tab-btn {
      padding: 6px 14px;
      border-radius: 6px;
      font-size: 0.88rem;
      background: transparent;
      border: none;
      color: var(--text-muted);
      cursor: pointer;
      font-weight: 500;
      white-space: nowrap;
    }
    .tab-btn.active {
      background: rgba(59, 130, 246, 0.15);
      color: #60a5fa;
      font-weight: 600;
    }
    .scope-btn {
      background: transparent;
      border: none;
      color: var(--text-muted);
      padding: 4px 10px;
      font-size: 0.78rem;
      border-radius: 6px;
      cursor: pointer;
      font-weight: 500;
      transition: all 0.2s;
    }
    .scope-btn.active {
      background: var(--primary);
      color: #fff;
    }
    .scope-btn:hover:not(.active) {
      color: var(--text);
    }
    .code-block {
      position: relative;
      background: var(--code-bg);
      border-radius: 10px;
      padding: 16px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.85rem;
      border: 1px solid var(--card-border);
      overflow-x: auto;
    }
    .copy-btn {
      position: absolute;
      top: 10px;
      right: 10px;
      background: rgba(255, 255, 255, 0.1);
      border: 1px solid rgba(255, 255, 255, 0.15);
      color: var(--text);
      border-radius: 6px;
      padding: 4px 8px;
      font-size: 0.75rem;
      cursor: pointer;
      transition: background 0.2s;
    }
    .copy-btn:hover { background: rgba(255, 255, 255, 0.2); }
    .feature-list {
      list-style: none;
      display: grid;
      grid-template-columns: 1fr;
      gap: 12px;
    }
    @media (min-width: 640px) {
      .feature-list { grid-template-columns: 1fr 1fr; }
    }
    .feature-item {
      display: flex;
      gap: 12px;
      align-items: flex-start;
    }
    .feature-icon {
      font-size: 1.25rem;
      background: rgba(59, 130, 246, 0.1);
      padding: 8px;
      border-radius: 8px;
      line-height: 1;
    }
    .footer {
      text-align: center;
      color: var(--text-muted);
      font-size: 0.9rem;
      margin-top: 48px;
      border-top: 1px solid var(--card-border);
      padding-top: 24px;
    }
    .footer a {
      color: var(--primary);
      text-decoration: none;
    }
    .footer a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="badge">🚀 Cloudflare Workers • RFC 8484 • 纯自研</div>
      <h1>cf-doh 解析网关</h1>
      <p class="subtitle">专为国内直连加速定制的自研 DNS-over-HTTPS 解析服务。内置国内外智能分流、真实可信 ECS 注入与全上游并发竞速。</p>
      <div class="tags">
        <span class="tag">⚡ 并发竞价 (Zero Wait)</span>
        <span class="tag">🛡️ 可信出口 ECS</span>
        <span class="tag">🇨🇳 阿里云 / 腾讯云 直连</span>
        <span class="tag">🌐 Google / CF 全球兜底</span>
        <span class="tag">🔒 DNSSEC 透传</span>
        <span class="tag">📊 JSON API 兼容</span>
      </div>
    </header>

    <div class="grid grid-2">
      <!-- 实时 DNS 调试卡片 -->
      <div class="card">
        <div class="card-title">
          <span>🧪</span>
          <span>在线解析测试台 (Live Playground)</span>
        </div>
        <p style="font-size:0.88rem; color:var(--text-muted); margin-bottom:12px;">
          实时测试域名在当前节点的分流策略、解析 IP 与响应耗时：
        </p>
        <div class="quick-chips">
          <span class="chip" onclick="setQuery('linux.do')">linux.do (国内组)</span>
          <span class="chip" onclick="setQuery('github.com')">github.com (国内组)</span>
          <span class="chip" onclick="setQuery('bilibili.com')">bilibili.com (国内组)</span>
          <span class="chip" onclick="setQuery('google.com')">google.com (全球组)</span>
          <span class="chip" onclick="setQuery('cloudflare.com')">cloudflare.com (全球组)</span>
        </div>
        <div class="input-group">
          <input type="text" id="domainInput" placeholder="输入待解析域名 (如 linux.do)" value="linux.do">
          <select id="typeSelect">
            <option value="A">A</option>
            <option value="AAAA">AAAA</option>
            <option value="TXT">TXT</option>
            <option value="HTTPS">HTTPS</option>
          </select>
          <button class="btn" id="queryBtn" onclick="runQuery()">查询</button>
        </div>
        <div class="result-box" id="resultBox">点击「查询」查看真实解析结果与链路时延...</div>
      </div>

      <!-- 端点信息与状态卡片 -->
      <div class="card">
        <div class="card-title">
          <span>📡</span>
          <span>服务接入端点</span>
        </div>
        <div style="margin-bottom: 16px;">
          <div style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 4px;">RFC 8484 标准 DoH URL</div>
          <div class="code-block" style="padding: 10px 14px;">
            <code>${origin}${config.path}</code>
            <button class="copy-btn" onclick="copyText('${origin}${config.path}')">复制</button>
          </div>
        </div>
        <div style="margin-bottom: 16px;">
          <div style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 4px;">Google 风格 JSON API 端点</div>
          <div class="code-block" style="padding: 10px 14px;">
            <code>${origin}${config.jsonPath}?name=linux.do&type=A</code>
            <button class="copy-btn" onclick="copyText('${origin}${config.jsonPath}?name=linux.do&type=A')">复制</button>
          </div>
        </div>
        <div style="margin-bottom: 16px;">
          <div style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 4px;">健康检查与统计指标</div>
          <div class="code-block" style="padding: 10px 14px;">
            <code>${origin}/healthz</code>
            <button class="copy-btn" onclick="copyText('${origin}/healthz')">复制</button>
          </div>
        </div>
        <div style="margin-bottom: 16px;">
          <div style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 4px;">竞速统计 API (JSON)</div>
          <div class="code-block" style="padding: 10px 14px;">
            <code>${origin}/api/stats</code>
            <button class="copy-btn" onclick="copyText('${origin}/api/stats')">复制</button>
          </div>
        </div>
      </div>
    </div>

    <!-- 📊 上游竞速与度量监控卡片 -->
    <div class="card" style="margin-bottom: 32px;">
      <div class="card-title" style="justify-content: space-between; flex-wrap: wrap; gap: 10px;">
        <div style="display: flex; align-items: center; gap: 10px;">
          <span>📊</span>
          <span>上游并发竞速与延迟监控 (Racing & P95 Metrics)</span>
        </div>
        <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
          <div style="display:inline-flex; background:rgba(255,255,255,0.06); border:1px solid var(--card-border); border-radius:8px; padding:2px; gap:2px;">
            <button id="scopeLocalBtn" class="scope-btn active" onclick="setStatsScope('local')">📍 本地 PoP 边缘</button>
            <button id="scopeGlobalBtn" class="scope-btn" onclick="setStatsScope('global')">🌐 全球多地域聚合</button>
          </div>
          <button class="btn" style="padding: 5px 12px; font-size: 0.8rem;" onclick="loadStats()">
            <span>🔄</span><span>刷新指标</span>
          </button>
        </div>
      </div>
      <div id="scopeNotice" style="font-size:0.82rem; color:var(--text-muted); margin-bottom:12px; padding:6px 12px; background:rgba(255,255,255,0.03); border-radius:6px; border-left:3px solid var(--primary);">
        📍 统计范围：当前 Cloudflare 边缘节点内存实时采样 (单实例)
      </div>
      <p style="font-size:0.88rem; color:var(--text-muted); margin-bottom:16px;">
        所有上游并发同时发起请求，延迟由最快节点决定。实时统计各上游的胜出比例、P50 / P95 解析延迟及边缘缓存效率。
      </p>

      <div class="grid grid-2" style="margin-bottom: 16px;">
        <!-- 国内组对比 -->
        <div style="background:var(--code-bg); padding:16px; border-radius:10px; border:1px solid var(--card-border);">
          <div style="display:flex; justify-content:space-between; margin-bottom:8px; font-weight:600; font-size:0.9rem;">
            <span>🇨🇳 国内组竞速 (AliDNS vs DNSPod)</span>
            <span id="domesticTotalWins" style="color:var(--text-muted); font-size:0.8rem;">0 胜出</span>
          </div>
          <div style="display:flex; height:10px; border-radius:9999px; overflow:hidden; background:rgba(255,255,255,0.1); margin-bottom:8px;">
            <div id="barAlidns" style="width:50%; background:#3b82f6; transition:width 0.4s;"></div>
            <div id="barDohpub" style="width:50%; background:#10b981; transition:width 0.4s;"></div>
          </div>
          <div style="display:flex; justify-content:space-between; font-size:0.8rem; color:var(--text-muted);">
            <span><span style="color:#3b82f6;">●</span> 阿里 DNS: <b id="winAlidns">0 (0.0%)</b></span>
            <span><span style="color:#10b981;">●</span> 腾讯 DNSPod: <b id="winDohpub">0 (0.0%)</b></span>
          </div>
          <div style="margin-top:12px; padding-top:8px; border-top:1px dashed var(--card-border); font-size:0.8rem; display:flex; justify-content:space-between;">
            <span>P50: <b id="p50Domestic">- ms</b></span>
            <span>P95: <b id="p95Domestic" style="color:#f59e0b;">- ms</b></span>
            <span>Avg: <b id="avgDomestic">- ms</b></span>
          </div>
        </div>

        <!-- 全球组对比 -->
        <div style="background:var(--code-bg); padding:16px; border-radius:10px; border:1px solid var(--card-border);">
          <div style="display:flex; justify-content:space-between; margin-bottom:8px; font-weight:600; font-size:0.9rem;">
            <span>🌐 全球组竞速 (Google vs Cloudflare)</span>
            <span id="globalTotalWins" style="color:var(--text-muted); font-size:0.8rem;">0 胜出</span>
          </div>
          <div style="display:flex; height:10px; border-radius:9999px; overflow:hidden; background:rgba(255,255,255,0.1); margin-bottom:8px;">
            <div id="barGoogle" style="width:50%; background:#8b5cf6; transition:width 0.4s;"></div>
            <div id="barCf" style="width:50%; background:#f97316; transition:width 0.4s;"></div>
          </div>
          <div style="display:flex; justify-content:space-between; font-size:0.8rem; color:var(--text-muted);">
            <span><span style="color:#8b5cf6;">●</span> Google DNS: <b id="winGoogle">0 (0.0%)</b></span>
            <span><span style="color:#f97316;">●</span> Cloudflare: <b id="winCf">0 (0.0%)</b></span>
          </div>
          <div style="margin-top:12px; padding-top:8px; border-top:1px dashed var(--card-border); font-size:0.8rem; display:flex; justify-content:space-between;">
            <span>P50: <b id="p50Global">- ms</b></span>
            <span>P95: <b id="p95Global" style="color:#f59e0b;">- ms</b></span>
            <span>Avg: <b id="avgGlobal">- ms</b></span>
          </div>
        </div>
      </div>

      <div style="display:flex; flex-wrap:wrap; gap:16px; font-size:0.82rem; color:var(--text-muted);">
        <span>📦 边缘缓存命中率: <b id="cacheHitRate" style="color:var(--accent);">0.0%</b></span>
        <span>📈 累计服务请求: <b id="totalRequests" style="color:var(--text);">0</b></span>
        <span id="uptimeWrap">⏱️ 节点运行时间: <b id="nodeUptime" style="color:var(--text);">0s</b></span>
        <span>☁️ Analytics Engine: <b id="analyticsStatus" style="color:var(--primary);">已接入 (Worker 点位写入)</b></span>
      </div>
    </div>

    <!-- 客户端一键配置卡片 -->
    <div class="card" style="margin-bottom: 32px;">
      <div class="card-title">
        <span>⚙️</span>
        <span>全平台客户端接入指南</span>
      </div>
      <div class="tabs">
        <button class="tab-btn active" onclick="switchTab('clash')">Clash / Mihomo</button>
        <button class="tab-btn" onclick="switchTab('surge')">Surge</button>
        <button class="tab-btn" onclick="switchTab('shadowrocket')">Shadowrocket</button>
        <button class="tab-btn" onclick="switchTab('apple')">iOS / macOS</button>
        <button class="tab-btn" onclick="switchTab('android')">Android / Windows</button>
        <button class="tab-btn" onclick="switchTab('cli')">cURL / dig 调试</button>
      </div>

      <div id="tab-clash" class="tab-content">
        <div class="code-block">
          <button class="copy-btn" onclick="copyElement('code-clash')">复制代码</button>
          <pre id="code-clash"><code>dns:
  enable: true
  listen: 0.0.0.0:1053
  enhanced-mode: fake-ip
  nameserver:
    - "${origin}${config.path}"
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29</code></pre>
        </div>
      </div>

      <div id="tab-surge" class="tab-content" style="display:none;">
        <div class="code-block">
          <button class="copy-btn" onclick="copyElement('code-surge')">复制代码</button>
          <pre id="code-surge"><code>[General]
dns-server = 223.5.5.5, 119.29.29.29
doh-server = ${origin}${config.path}
doh-format = wire</code></pre>
        </div>
      </div>

      <div id="tab-shadowrocket" class="tab-content" style="display:none;">
        <div class="code-block">
          <button class="copy-btn" onclick="copyElement('code-shadowrocket')">复制代码</button>
          <pre id="code-shadowrocket"><code># 进入 Shadowrocket -> 设置 -> DNS -> 启用 DNS-over-HTTPS
DNS 服务器 URL:
${origin}${config.path}</code></pre>
        </div>
      </div>

      <div id="tab-apple" class="tab-content" style="display:none;">
        <div class="code-block">
          <button class="copy-btn" onclick="copyElement('code-apple')">复制代码</button>
          <pre id="code-apple"><code># iOS 14+ / macOS 11+ 原生支持 DoH 描述文件 (.mobileconfig)
# 对应 DoH 服务器地址:
${origin}${config.path}

# 可以在 Safari 打开，或使用 Apple Configurator 生成描述文件。</code></pre>
        </div>
      </div>

      <div id="tab-android" class="tab-content" style="display:none;">
        <div class="code-block">
          <button class="copy-btn" onclick="copyElement('code-android')">复制代码</button>
          <pre id="code-android"><code># Android 13+ (Private DNS / 现代浏览器设置)
# Chrome / Edge: 设置 -> 隐私和安全性 -> 使用安全 DNS -> 选择提供商 -> 自定义:
${origin}${config.path}

# Windows 11: 设置 -> 网络和 Internet -> 以太网/WLAN -> 硬件属性 -> DNS 服务器分配:
# 选择手动 -> IPv4/IPv6 开 -> 填写 DNS 并开启「仅加密 (通过 HTTPS 的 DNS)」
模板 URL: ${origin}${config.path}</code></pre>
        </div>
      </div>

      <div id="tab-cli" class="tab-content" style="display:none;">
        <div class="code-block">
          <button class="copy-btn" onclick="copyElement('code-cli')">复制代码</button>
          <pre id="code-cli"><code># 1. 快速健康检查
curl -s "${origin}/healthz"

# 2. 通过 JSON API 快速解析
curl -s "${origin}${config.jsonPath}?name=linux.do&type=A"

# 3. 使用 kdig (knot-dnsutils) 测试标准 DoH
kdig -d @${new URL(origin).hostname} +https=${config.path} linux.do A</code></pre>
        </div>
      </div>
    </div>

    <!-- 核心优势 -->
    <div class="card">
      <div class="card-title">
        <span>💡</span>
        <span>为什么选择 cf-doh？</span>
      </div>
      <div class="feature-list">
        <div class="feature-item">
          <div class="feature-icon">🏎️</div>
          <div>
            <strong>全并发竞价 (Zero Penalty)</strong>
            <p style="font-size:0.85rem; color:var(--text-muted);">
              国内组与全球组内所有上游同时并发请求，延迟取最小值。彻底终结传统方案串行超时卡顿。
            </p>
          </div>
        </div>
        <div class="feature-item">
          <div class="feature-icon">🎯</div>
          <div>
            <strong>真实可信 ECS 注入</strong>
            <p style="font-size:0.85rem; color:var(--text-muted);">
              严格信任 Cloudflare 边缘提取的 client IP（/24 或 /56），过滤可伪造的 XFF，让 CDN 调度精准锁定最近节点。
            </p>
          </div>
        </div>
        <div class="feature-item">
          <div class="feature-icon">🛡️</div>
          <div>
            <strong>规则防毒化与硬隔离</strong>
            <p style="font-size:0.85rem; color:var(--text-muted);">
              内置 linux.do / github.com 绝对直连硬编码防护，外部规则失效或格式异常平滑回退，保障服务永远可用。
            </p>
          </div>
        </div>
        <div class="feature-item">
          <div class="feature-icon">📦</div>
          <div>
            <strong>零运行时依赖 & 开箱即用</strong>
            <p style="font-size:0.85rem; color:var(--text-muted);">
              纯原生 JavaScript ESM 实现，无论免费版还是企业版 Cloudflare Workers，单文件或 Wrangler 均可秒级启动。
            </p>
          </div>
        </div>
      </div>
    </div>

    <footer class="footer">
      <p>开源项目：<a href="https://github.com/dengyie/cf-doh" target="_blank" rel="noopener">github.com/dengyie/cf-doh</a> • 基于 MIT License 开源</p>
      <p style="margin-top: 6px; font-size: 0.8rem;">Powered by Cloudflare Workers & Serverless Edge Computing</p>
    </footer>
  </div>

  <script>
    function escapeHtml(str) {
      if (str === null || str === undefined) return '';
      return String(str).replace(/[&<>"']/g, function(m) {
        switch (m) {
          case '&': return '&amp;';
          case '<': return '&lt;';
          case '>': return '&gt;';
          case '"': return '&quot;';
          case "'": return '&#39;';
          default: return m;
        }
      });
    }

    function setQuery(domain) {
      document.getElementById('domainInput').value = domain;
      runQuery();
    }

    async function runQuery() {
      const domain = document.getElementById('domainInput').value.trim();
      const type = document.getElementById('typeSelect').value;
      const box = document.getElementById('resultBox');
      const btn = document.getElementById('queryBtn');
      if (!domain) return;

      btn.disabled = true;
      btn.innerText = '查询中...';
      box.textContent = '正在发起 DoH 查询...';

      const start = performance.now();
      try {
        const resp = await fetch('${config.jsonPath}?name=' + encodeURIComponent(domain) + '&type=' + encodeURIComponent(type));
        const data = await resp.json();
        const duration = Math.round(performance.now() - start);

        let html = '';
        html += '⏱️ 解析耗时: ' + duration + ' ms\\n';
        const statusNum = Number(data.Status);
        html += '🎯 响应状态: ' + (statusNum === 0 ? '<span style="color:#10b981">NOERROR (成功)</span>' : '<span style="color:#ef4444">Status ' + statusNum + '</span>') + '\\n';
        html += '🔒 DNSSEC: ' + (data.AD ? '已验证 (AD=1)' : '未开启/普通 (AD=0)') + '\\n\\n';

        if (Array.isArray(data.Answer) && data.Answer.length > 0) {
          html += '📋 答案记录 (Answers):\\n';
          data.Answer.forEach(ans => {
            const safeName = escapeHtml(ans.name);
            const safeType = escapeHtml(ans.type);
            const safeData = escapeHtml(ans.data);
            const safeTtl = Number(ans.TTL) || 0;
            html += '  • ' + safeName + '  ' + safeType + '  ' + safeData + ' (TTL: ' + safeTtl + 's)\\n';
          });
        } else {
          html += '⚠️ 未查询到对应记录。\\n';
        }

        if (Array.isArray(data.Authority) && data.Authority.length > 0) {
          html += '\\n🏛️ 权威记录 (Authority):\\n';
          data.Authority.forEach(auth => {
            const safeName = escapeHtml(auth.name);
            const safeType = escapeHtml(auth.type);
            const safeData = escapeHtml(auth.data);
            html += '  • ' + safeName + '  ' + safeType + '  ' + safeData + '\\n';
          });
        }

        box.innerHTML = html;
        loadStats();
      } catch (err) {
        box.innerHTML = '<span style="color:#ef4444">查询失败: ' + escapeHtml(err.message) + '</span>';
      } finally {
        btn.disabled = false;
        btn.innerText = '查询';
      }
    }

    let currentScope = 'local';

    function setStatsScope(scope) {
      currentScope = scope;
      const localBtn = document.getElementById('scopeLocalBtn');
      const globalBtn = document.getElementById('scopeGlobalBtn');
      if (scope === 'global') {
        localBtn.classList.remove('active');
        globalBtn.classList.add('active');
      } else {
        globalBtn.classList.remove('active');
        localBtn.classList.add('active');
      }
      loadStats(scope);
    }

    async function loadStats(scope = currentScope) {
      try {
        const url = scope === 'global' ? '/api/stats?scope=global' : '/api/stats';
        const resp = await fetch(url);
        if (!resp.ok) return;
        const rawData = await resp.json();
        const isGlobal = scope === 'global';
        const noticeEl = document.getElementById('scopeNotice');

        let data = rawData;
        if (isGlobal) {
          if (rawData.available) {
            noticeEl.innerHTML = '🌐 <b>全球多地域聚合数据 (Cloudflare Analytics Engine)</b> • 最近 24 小时跨所有 PoP 边缘节点总计';
            noticeEl.style.borderLeftColor = '#10b981';
            document.getElementById('analyticsStatus').innerText = '全局 SQL 查询已激活';
            document.getElementById('analyticsStatus').style.color = '#10b981';
            document.getElementById('uptimeWrap').style.display = 'none';
          } else {
            noticeEl.innerHTML = '⚠️ <b>全球聚合未开启或未配置读取凭据</b>：' + escapeHtml(rawData.message || '回退展示当前本地 PoP 数据') + '。可至 Cloudflare 控制台激活 Analytics Engine。';
            noticeEl.style.borderLeftColor = '#f59e0b';
            document.getElementById('analyticsStatus').innerText = '未激活全局读取 (展示本地)';
            document.getElementById('analyticsStatus').style.color = '#f59e0b';
            document.getElementById('uptimeWrap').style.display = 'inline';
            if (rawData.fallback) data = rawData.fallback;
          }
        } else {
          noticeEl.innerHTML = '📍 统计范围：当前 Cloudflare 边缘节点内存实时采样 (单实例)';
          noticeEl.style.borderLeftColor = 'var(--primary)';
          document.getElementById('analyticsStatus').innerText = '已接入 (Worker 点位写入)';
          document.getElementById('analyticsStatus').style.color = 'var(--primary)';
          document.getElementById('uptimeWrap').style.display = 'inline';
        }

        // Domestic
        const dom = (data.upstreams && data.upstreams.domestic) ? data.upstreams.domestic : { upstreams: {}, totalWins: 0 };
        const ali = dom.upstreams['dns.alidns.com'] || { wins: 0, winRate: '0.0%' };
        const pod = dom.upstreams['doh.pub'] || { wins: 0, winRate: '0.0%' };
        document.getElementById('domesticTotalWins').innerText = dom.totalWins + ' 次胜出';
        document.getElementById('winAlidns').innerText = ali.wins + ' (' + ali.winRate + ')';
        document.getElementById('winDohpub').innerText = pod.wins + ' (' + pod.winRate + ')';
        const domTotal = ali.wins + pod.wins;
        const aliPct = domTotal > 0 ? (ali.wins / domTotal) * 100 : 50;
        document.getElementById('barAlidns').style.width = aliPct + '%';
        document.getElementById('barDohpub').style.width = (100 - aliPct) + '%';

        if (data.latency && data.latency.domestic) {
          document.getElementById('p50Domestic').innerText = (data.latency.domestic.p50Ms || 0) + ' ms';
          document.getElementById('p95Domestic').innerText = (data.latency.domestic.p95Ms || 0) + ' ms';
          document.getElementById('avgDomestic').innerText = (data.latency.domestic.avgMs || 0) + ' ms';
        }

        // Global
        const glob = (data.upstreams && data.upstreams.global) ? data.upstreams.global : { upstreams: {}, totalWins: 0 };
        const ggl = glob.upstreams['dns.google'] || { wins: 0, winRate: '0.0%' };
        const cf = glob.upstreams['cloudflare-dns.com'] || { wins: 0, winRate: '0.0%' };
        document.getElementById('globalTotalWins').innerText = glob.totalWins + ' 次胜出';
        document.getElementById('winGoogle').innerText = ggl.wins + ' (' + ggl.winRate + ')';
        document.getElementById('winCf').innerText = cf.wins + ' (' + cf.winRate + ')';
        const globTotal = ggl.wins + cf.wins;
        const gglPct = globTotal > 0 ? (ggl.wins / globTotal) * 100 : 50;
        document.getElementById('barGoogle').style.width = gglPct + '%';
        document.getElementById('barCf').style.width = (100 - gglPct) + '%';

        if (data.latency && data.latency.global) {
          document.getElementById('p50Global').innerText = (data.latency.global.p50Ms || 0) + ' ms';
          document.getElementById('p95Global').innerText = (data.latency.global.p95Ms || 0) + ' ms';
          document.getElementById('avgGlobal').innerText = (data.latency.global.avgMs || 0) + ' ms';
        }

        if (data.cache) {
          document.getElementById('cacheHitRate').innerText = data.cache.hitRate || '0.0%';
        }
        if (typeof data.totalRequests !== 'undefined') {
          document.getElementById('totalRequests').innerText = data.totalRequests;
        }
        if (typeof data.uptimeSec !== 'undefined') {
          document.getElementById('nodeUptime').innerText = data.uptimeSec + 's';
        }
      } catch (err) {
        console.warn('Failed to load stats:', err);
      }
    }

    window.addEventListener('DOMContentLoaded', () => {
      loadStats();
    });

    function switchTab(name) {
      const contents = document.querySelectorAll('.tab-content');
      contents.forEach(c => c.style.display = 'none');
      const btns = document.querySelectorAll('.tab-btn');
      btns.forEach(b => b.classList.remove('active'));

      const target = document.getElementById('tab-' + name);
      if (target) target.style.display = 'block';
      event.target.classList.add('active');
    }

    function copyText(txt) {
      navigator.clipboard.writeText(txt).then(() => {
        alert('已复制到剪贴板: ' + txt);
      });
    }

    function copyElement(id) {
      const el = document.getElementById(id);
      if (el) {
        copyText(el.innerText);
      }
    }
  </script>
</body>
</html>`;
}

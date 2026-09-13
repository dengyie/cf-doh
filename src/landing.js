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
      box.innerHTML = '正在发起 DoH 查询...';

      const start = performance.now();
      try {
        const resp = await fetch('${config.jsonPath}?name=' + encodeURIComponent(domain) + '&type=' + type);
        const data = await resp.json();
        const duration = Math.round(performance.now() - start);

        let html = '';
        html += '⏱️ 解析耗时: ' + duration + ' ms\\n';
        html += '🎯 响应状态: ' + (data.Status === 0 ? '<span style="color:#10b981">NOERROR (成功)</span>' : '<span style="color:#ef4444">Status ' + data.Status + '</span>') + '\\n';
        html += '🔒 DNSSEC: ' + (data.AD ? '已验证 (AD=1)' : '未开启/普通 (AD=0)') + '\\n\\n';

        if (data.Answer && data.Answer.length > 0) {
          html += '📋 答案记录 (Answers):\\n';
          data.Answer.forEach(ans => {
            html += '  • ' + ans.name + '  ' + ans.type + '  ' + ans.data + ' (TTL: ' + ans.TTL + 's)\\n';
          });
        } else {
          html += '⚠️ 未查询到对应记录。\\n';
        }

        if (data.Authority && data.Authority.length > 0) {
          html += '\\n🏛️ 权威记录 (Authority):\\n';
          data.Authority.forEach(auth => {
            html += '  • ' + auth.name + '  ' + auth.type + '  ' + auth.data + '\\n';
          });
        }

        box.innerHTML = html;
      } catch (err) {
        box.innerHTML = '<span style="color:#ef4444">查询失败: ' + err.message + '</span>';
      } finally {
        btn.disabled = false;
        btn.innerText = '查询';
      }
    }

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

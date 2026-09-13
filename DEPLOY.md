# 🚀 Cloudflare Workers 部署指引 (Deployment Guide)

本项目已完成全套单元测试与集成测试，并已在 Cloudflare Workers 生产环境验证通过。

## 方案一：自动化脚本一键上线（推荐）

```bash
# 1. 设置您的 Cloudflare API Token（需具备 Workers 与 KV 读写权限）
export CLOUDFLARE_API_TOKEN="your_cloudflare_api_token"

# 2. 执行自动化部署脚本
./scripts/deploy.sh
```

脚本将自动执行：
1. 运行本地全套 DNS 与路由测试；
2. 构建生产级单文件 Bundle (`dists/worker-single.js`)；
3. 自动检测并创建 `RULES_KV` 命名空间并回填 `wrangler.jsonc`；
4. 通过 `wrangler deploy` 推送上线。

---

## 方案二：手动分步部署

```bash
# 1. 安装开发依赖
npm install

# 2. 创建 RULES_KV 命名空间（可选）
npx wrangler kv namespace create RULES_KV
# 复制输出的 id，替换 wrangler.jsonc 中的 REPLACE_WITH_YOUR_KV_NAMESPACE_ID

# 3. 执行部署
npx wrangler deploy
```

---

## 方案三：Cloudflare Dashboard 网页端一键粘贴

适合不习惯使用命令行的用户：
1. 打开 [Cloudflare Dashboard](https://dash.cloudflare.com/)，创建全新的 Worker（如 `cf-doh`）；
2. 点击 **Edit Code**，将本仓库生成的 [`dists/worker-single.js`](dists/worker-single.js) 全文复制并粘贴进去；
3. 点击 **Deploy** 即刻生效。

---

## 环境变量与可选绑定

在 Cloudflare 控制台的 **Settings -> Variables and Secrets** 中可按需添加：
- `RULES_SYNC_SECRET`：用于自动同步规则的 Webhook 密钥（与 GitHub Actions 配合使用）。
- `DOH_ANALYTICS`：可在 **Settings -> Bindings -> Add -> Workers Analytics Engine** 添加名为 `DOH_ANALYTICS` 的绑定（Dataset 名为 `cf_doh_metrics`），即可开启云端海量指标监控。

---

## 绑定自定义域名（重要）

由于 `*.workers.dev` 二级域名在大陆网络受限，部署后请务必绑定自定义域名：
1. 在 Worker 管理页进入 **Settings** -> **Triggers** -> **Custom Domains**；
2. 添加您的二级域名（如 `doh.example.com`）；
3. Cloudflare 会自动配置 DNS 记录并申请权威 SSL 证书；
4. 客户端填入 `https://doh.example.com/doh` 即可畅享极速解析！

---

## 生产环境最佳实践总结

1. **必须使用自定义域名**：严禁直接将 `*.workers.dev` 作为客户端长期端点，以防运营商 SNI 拦截。
2. **避免 DNS 死循环**：代理客户端（Mihomo / Clash / Surge）需在 `hosts` 或 `nameserver-policy` 中静态解析 DoH 域名本身。
3. **保持默认 ECS /24 掩码**：兼顾客户端隐私保护与国内 CDN 就近调度精准度。
4. **接入 GitHub Actions 每日同步**：配置 `DOH_ENDPOINT` 与 `RULES_SYNC_SECRET` Secrets，享受全自动免维护规则热更新。
5. **开启 Analytics Engine 监控**：在 Cloudflare Dashboard 点击一次开启，即可跨全球 PoP 观察 P95 延迟与上游健康度。

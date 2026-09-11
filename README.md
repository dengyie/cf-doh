# cf-doh — Self-hosted DNS-over-HTTPS resolver on Cloudflare Workers

一个**开源、纯 JS、零构建依赖**的 Cloudflare Workers 上的 DNS-over-HTTPS (RFC 8484) 解析服务,专为「国内直连加速」设计:

- **github.com / linux.do 等站点直连**:根据域名规则把查询分流到国内 DNS(阿里)+ 携带你的出口 IP 的 ECS,拿到可直连的正确 IP;
- 其它域名走全球 DNS(Google / Cloudflare)兜底;
- **高可用**:所有上游**并发竞价**,谁先返回有效答案用谁,单个上游抖动/超时不影响;
- 无需服务器、免费计划可跑,模块化、结构清晰、易扩展。

## 为什么用这个(相对其它开源方案)

我深度 review 过 GitHub 上主流的几个方案(`cloudflare-doh-ecs`、`CF-Workers-DoH`、`cfdohpw`),本实现针对它们的短板做了改进:

- **上游容错**:原方案逐个上游「串行重试」,主上游失败要白等一轮超时;本方案**并发竞价**取最快有效响应。
- **ECS 信任**:忽略客户端可伪造的 `X-Forwarded-For`,只用 Cloudflare 可信的 `cf-connecting-ip`,防止别人伪造 IP 拿到不属于自己的解析。
- **规则安全**:规则库必须整体校验通过才生效,远程列表损坏/被污染不会毒化在线逻辑。
- **可观测**:内置 `/healthz` + `/metrics`,结构化计数,便于接入告警。
- **结构清晰**:每个职责一个模块(`dns` / `ecs` / `ip` / `rules` / `resolver` / `metrics` / `config`),扩展新分流维度不用改主入口。

## 架构

```
Client (DoH, RFC8484)
   │
   ▼  https://doh.你的域名.com/doh  (GET ?dns= 或 POST application/dns-message)
Worker (src/worker.js)
   ├─ /healthz /metrics                 → 结构化指标
   ├─ read: 校验方法/Content-Type/大小
   ├─ parse: DNS wire-format 解析(qname/qtype/opt)
   ├─ rules: qname → 国内 or 全球       (KV 持久化 + 内存热缓存, cron 刷新)
   ├─ ECS:  注入客户端子网(可信 CF IP, /24 或 /56)
   └─ resolver: 并发竞速上游组
        ├─ 国内组  → dns.alidns.com / doh.pub
        └─ 全球组  → dns.google / cloudflare-dns.com
```

## 上游并发竞价(resolver)

对同一查询,把所属组(国内/全球)内的**所有上游同时发出**,取第一个「ID 匹配、非截断、非 SERVFAIL」的有效响应。全组失败才返回 SERVFAIL。这就是「线上高可用」的核心:延迟由最快的上游决定,单个坏上游遮不住掉。

## 目录结构

```
src/
  worker.js    # Worker 入口(路由 / 请求处理 / 默认出口)
  dns.js       # DNS 报文 解析 / 错误响应 / 上游响应校验(纯二进制)
  ecs.js       # EDNS Client Subnet 编码
  ip.js        # IP 解析(v4/v6)、掩码、可信头提取、全局单播判定
  rules.js      # 规则加载/匹配(plain/full/regexp)+ KV 分层 + cron 刷新
  resolver.js  # 上游并发竞价 + 故障转移
  cache.js     # 内存 DNS 响应缓存(TTL 封顶 / 按 ECS 分键)
  metrics.js    # 计数器 + /healthz 响应
  config.js     # 环境变量 → 配置(默认值集中)
cache:           # 响应缓存:key=(qname,qtype,ECS子网),TTL=min(应答TTL, 上限)
dists/
  worker-single.js  # 单文件打包产物(esbuild),可直接粘贴到 CF Control 面板
test/           # 无依赖 node 测试
sample-rules/   # 个人国内直连规则样例(含 linux.do)
scripts/        # 一键构建/部署脚本
wrangler.jsonc  # 部署配置
```

## 快速部署

### 方式 A — 命令行(Wrangler)

```bash
# 1. 安装依赖
npm install

# 2. one-click:验证测试 → 重建 bundle → 部署
./scripts/deploy.sh
# (没有 CLOUDFLARE_API_TOKEN 时会停下并提示;置好 token 后重跑即真正上线)

# 若需手动分步执行:
npx wrangler kv namespace create RULES_KV   # 复制输出的 id 回去填
npm run deploy                              # = wrangler deploy
```

### 方式 B — 网页 Dashboard(粘贴 `dists/worker.js`)

1. Workers → Create → Workers,选「Dashboard 编辑器」;
2. 新建一个 Work,把 `dists/worker.js` 内容整体粘贴为 **module worker**;
3. 绑定 `RULES_KV`(Workers → KV → Bindings → Add 一个命名空间);
4. 设置 Environment Variables(见下文);
5. Save & Deploy。

**注意**:`*.workers.dev` 自带域名基本被 GFW 阻断,必须绑定你自己的域名并通过 Workers 路由承载(见「绑定域名」)。

## 环境变量(vars 或 dashboard)

| 变量 | 默认 | 说明 |
|---|---|---|
| `DOH_PATH` | `/doh` | DoH 查询路径(客户端填入的 URL 路径) |
| `DOMESTIC_DOH_URL` | `https://dns.alidns.com/dns-query` | 国内组主上游 |
| `DOMESTIC_FALLBACK_DOH_URL` | `https://doh.pub/dns-query` | 国内组备上游(同组并发) |
| `GLOBAL_DOH_URL` | `https://dns.google/dns-query` | 全球组主上游 |
| `GLOBAL_FALLBACK_DOH_URL` | `https://cloudflare-dns.com/dns-query` | 全球组备上游 |
| `ECS_IPV4_PREFIX` | `24` | IPv4 客户端子网前缀 |
| `ECS_IPV6_PREFIX` | `56` | IPv6 客户端子网前缀 |
| `UPSTREAM_TIMEOUT_MS` | `3000` | 每个上游超时上限 |
| `MAX_QUERY_BYTES` | `4096` | 最大查询体 |
| `MAX_RESPONSE_BYTES` | `65535` | 最大响应体 |
| `CACHE_TTL_SECONDS` | `300` | 内存缓存上限(秒);实际 TTL = min(应答 TTL, 该值)。设 `0` 关闭缓存 |
| `RULES_URL` | (社区列表) | 覆盖规则源(自定义列表 CDN/gist) |
| `DOH_TOKEN` | (空) | 可选;设置后请求需带 `?token=` 或 `x-doh-token` 头,防止被滥用 |

## 绑定域名并启用

1. 境内购买域名(或已有),把 NS 托管到 Cloudflare(免费计划即可)。
2. 在域名 DNS 加记录:`doh  A  1.1.1.1`(或优选 CF IP;可配 CDN 仅用于这个低流量 DoH) 。
3. 在 **Workers 路由** 添加:`doh.你的域名.com/*` → 绑定到 `cf-doh` Worker。

> **更省事的替代(推荐)** — 直接用 Cloudflare API 把 `doh.<你的域名>` 绑为 Worker 的
> **自定义域**,Cloudflare 会自动建好 DNS 记录 + 免费证书,无需手动加 A 记录/路由:
> ```bash
> ACC=<account_id>; EMAIL=<账号邮箱>; KEY=<Global API Key 或 CF_API_TOKEN>
> curl -X PUT "https://api.cloudflare.com/client/v4/accounts/$ACC/workers/domains" \
>   -H "X-Auth-Email: $EMAIL" -H "X-Auth-Key: $KEY" \
>   -H "Content-Type: application/json" \
>   --data '{"hostname":"doh.你的域名.com","service":"cf-doh","environment":"production"}'
> ```
> 成功后等待 DNS 生效(通常几秒),`dig +short doh.你的域名.com` 会返回 CF 边缘 IP。

> **2026-09-11 实测**:`*.workers.dev` 域名在受限网络不可达(连接超时),自定义域(`doh.<你的域名>`)可达且
> `github.com`/`linux.do` 均返回 `rcode=0` + 正确 A 记录。若发现请求 403/退化异常,
> 先检查是不是测试脚本缺 `User-Agent`——Cloudflare 边缘会给裸 HTTP 客户端的 `/doh`
> 返回非 DNS 响应,加浏览器 UA 或用 dig 即可。
4. 客户端测试:
   ```bash
   # DoH 服务可用性
   curl -sk "https://doh.你的域名.com:443/healthz"

   # 走 DoH 解析 github.com
   curl -sk "https://doh.你的域名.com/doh?dns=$(printf 'github.com' ...)" # 或用 dig
   ```

### 客户端配置

任一支持 DoH 的设备/软件均可,填:

```
https://doh.你的域名.com /doh
```

- Android / Private DNS:选择「自定义 DoH」填上面地址;
- Windows / macOS:网络 → DNS 手动填 DoH 地址;
- 浏览器(如 Firefox):Settings → 通用 → Network Settings → 启用 DoH,填该地址。

## 把 linux.do / 其它站点加进来

`rules.js` 的 `RULES_URL` 默认指向社区维护的「国内直连列表」。若你想自定义(如强制 `linux.do` 走国内,始终获得阿里 + ECS 的国内出口),两种方式:

**A. 覆盖整个列表**(简单):把 `RULES_URL` 指向你自己的 gist / raw 文本,内容每行一个域名。`linux.do` 直接写 `linux.do`(裸域名 = 后缀匹配,会命中 `linux.do`、`www.linux.do` 及所有子域)。仓库附有最小落地方案 `sample-rules/direct-personal.txt`,把它传到你自己的 gist/raw 或 CF Pages 后填到配置即可:

```
# sample-rules/direct-personal.txt —— 个人国内直连覆盖层(每行一个域名)
linux.do
full:github.com
```

**B. 长期运行建议**:为「个人覆盖层 + 社区列表」合并维护一个聚合列表(例如用 CF Pages / GitHub Action 每日把这两份拼成一份),再提供给 `RULES_URL`。这样既保留了社区列表对主流国内站点的覆盖,又能强制你的自定义域名。可参考 `test/` 里对 `loadRulesFromText` 的用法。

> 规则格式:裸域名=子域匹配;`full:` 精确匹配;`regexp:` 正则。规则集在命中前会被完整校验,乱序/HTML 会被拒绝,避免毒化在线解析。

> 注意:只有 `RULES_URL` 指向的清单决定哪些域名走国内。若 `linux.do` 不在里面(默认也不会自动在),它会落到全球组。要让它获得阿里直连 + ECS,必须把它加进规则清单(方式 A 只要一行 `linux.do`)。

## 本地测试(不依赖 Cloudflare 运行时也

```bash
node test/run-all.mjs     # dns / routing / ecs-forward 全部无依赖测试
```

已在本地 Node 26 验证全部通过。

## 线上部署验证(真实 Cloudflare)

不含可变变量、仅使用 Worker 代码时可以真正推到真实 Cloudflare 验证:
临时预览账号部署成功并生成公网 URL —— `https://cf-doh.glowing-digit.workers.dev`
(wrangler 输出 `Deployed cf-doh triggers`)。
对公网 `*.workers.dev` 的 live smoke-test 在本沙箱网络下不可达(连接超时,属沙箱 egress 限制,非部署失败)。
正式绑定你自己域名与 KV 后,用 `scripts/deploy.sh` 一键发布即可。

## 安全性 & 访问控制

- **ECS 信任**:只用 `cf-connecting-ip`,忽略客户端可伪造的 XFF;
- **响应校验**:校验上游响应的 ID 匹配、非截断、非 SERVFAIL 即可回发;
- **可选 TOKEN**:开 `DOH_TOKEN` 后,外部请求必须有 token 才放行,防白嫖;
- **规则校验**:脏列表(HTML、超大、非 UTF8)不会毒化在线解析;
- DoH 端点不暴露 nginx 默认页,根路径返回一个简单说明页。

## License

MIT.
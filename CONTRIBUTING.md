# Contributing to cf-doh

Thank you for your interest in improving `cf-doh`!

## Code Principles

1. **Zero Runtime Dependencies**: The worker runtime is written in standard ES Modules (ES2022) with pure JavaScript. Do not add external runtime npm packages.
2. **RFC 8484 Compliant**: Any changes to the DNS wire-format parser or DoH transport must adhere strictly to RFC 8484 and relevant DNS specifications (RFC 1035, RFC 7871).
3. **Fail-Safe & Resilient**: Upstream timeouts, corrupted remote rule lists, or KV downtime must NEVER bring down the query path. Default fallback to built-in overrides and memory cache.
4. **Tested**: All changes must be backed by automated tests.

## Development Workflow

1. Fork and clone the repository.
2. Install devDependencies:
   ```bash
   npm install
   ```
3. Run test suite:
   ```bash
   npm test
   ```
4. Build the standalone bundle:
   ```bash
   npm run build
   ```
5. Commit your changes and submit a Pull Request.

---

# 贡献指南

感谢关注并参与 `cf-doh` 的开源建设！

## 核心原则

1. **零运行时依赖**：Worker 核心逻辑必须保持纯原生 JavaScript ESM，不引入第三方运行时依赖，保持轻量高效与极速冷启动。
2. **严格符合标准**：DNS 解析、ECS 编码和 DoH 协议实现须严格遵守 RFC 8484 / RFC 7871 等标准。
3. **极高容错**：无论是上游超时、外部规则列表损坏还是 KV 异常，核心解析路径必须能自动降级并维持可用。
4. **测试覆盖**：所有新增功能与 bugfix 必须配有单元/集成测试（`npm test` 通过）。

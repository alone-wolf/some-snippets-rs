# T15 `axum` 静态托管与开发代理支持

## 状态

- 已完成（2026-03-29）

## 目标

让 `web-admin` 的构建产物由现有 `axum` 服务托管，并为前端本地开发提供稳定的代理与运行约束。

## 输入

- `docs_design/10-web-frontend-and-hosting.md`
- `docs_design/06-service-architecture-axum.md`

## 前置依赖

- `T14`

## 具体工作

1. 在 `axum` 中新增前端静态资源路由挂载。
2. 将 `web-admin/dist` 挂载到：
   - `/app`
   - `/app/*`
3. 使用 `ServeDir` / `ServeFile` 实现 SPA fallback：
   - 深链刷新回退到 `index.html`
   - 只在 `/app` 子树下生效
4. 避免影响现有 API 404：
   - API 路由优先
   - SPA fallback 不作为全局 fallback
5. 在 `web-admin/vite.config.ts` 中配置 dev server proxy：
   - `/healthz`
   - `/collections`
   - `/contents`
   - `/nodes`
   - `/node-lineages`
   - `/draft`
   - `/latest`
   - `/versions`
   - `/files`
6. 配置前端构建基路径：
   - `base = "/app/"`

## 建议产物

- `src/web/router.rs`
- `src/app/mod.rs`
- `web-admin/vite.config.ts`

## 验收标准

1. 前端构建后，访问 `/app` 能正确返回页面。
2. 刷新 `/app/...` 深链不会返回 404。
3. 访问后端 API 的 404 仍然返回 JSON 错误，而不是 HTML 页面。
4. 本地 Vite 开发时无需手动处理跨域。

## 不在本任务内

- 具体业务页面功能
- 资源缓存优化
- `.br` / `.gz` 预压缩

# T14 初始化 `web-admin` 工程骨架

## 状态

- 已完成（2026-03-29）

## 目标

创建一个可持续演进的 `web-admin` 前端子项目骨架，作为后台 SPA 的基础承载层。

## 输入

- `docs_design/10-web-frontend-and-hosting.md`
- `docs_dev/README.md`

## 前置依赖

- `T13`

## 具体工作

1. 在仓库根目录创建 `web-admin/` 子项目。
2. 使用 `Vue 3 + TypeScript + Vite` 初始化工程。
3. 接入基础依赖：
   - `vue-router`
   - `pinia`
   - `element-plus`
   - `axios`
   - `sass`
4. 建立首版目录结构：
   - `src/router`
   - `src/stores`
   - `src/api`
   - `src/layouts`
   - `src/views`
   - `src/components`
   - `src/composables`
   - `src/styles`
   - `src/types`
   - `src/utils`
5. 提供最小启动页面：
   - `App.vue`
   - 基础首页视图
   - Element Plus 可正常渲染
6. 建立基础 npm scripts：
   - `dev`
   - `build`
   - `preview`
   - `lint`
   - `test`

## 建议产物

- `web-admin/package.json`
- `web-admin/tsconfig.json`
- `web-admin/vite.config.ts`
- `web-admin/src/main.ts`
- `web-admin/src/App.vue`

## 验收标准

1. `cd web-admin && npm install && npm run dev` 可以正常启动。
2. `web-admin` 首屏页面可以渲染基础 Vue + Element Plus 内容。
3. 目录结构可支持后续页面与模块扩展。

## 不在本任务内

- 业务页面实现
- 与 `axum` 的静态托管联调
- API 请求封装细节

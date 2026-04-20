# T16 `web-admin` 应用壳、路由与 API 基础层

## 状态

- 已完成（2026-03-29）

## 目标

建立 `web-admin` 的可复用基础层，包括应用壳、路由系统、全局样式与 API 请求封装。

## 输入

- `docs_design/10-web-frontend-and-hosting.md`
- `docs_design/05-api-design.md`

## 前置依赖

- `T14`
- `T15`

## 具体工作

1. 建立 `AppLayout`：
   - 左侧导航
   - 顶部栏
   - 主内容区
2. 建立基础路由：
   - `/app`
   - `/app/collections`
   - `/app/contents/:contentId/settings`
   - `/app/contents/:contentId/editor`
   - `/app/contents/:contentId/versions`
   - `/app/contents/:contentId/versions/:version`
3. 统一页面 meta：
   - `title`
   - `layout`
4. 建立 API client：
   - `axios` 实例
   - 基础超时
   - 错误标准化
5. 按模块拆分 API 文件：
   - `content.ts`
   - `node.ts`
   - `version.ts`
   - `types.ts`
6. 建立基础全局状态：
   - 当前 Collection / Content 上下文
   - 页面级 loading / UI 状态
7. 引入基础全局样式与 Element Plus 主题覆写。

## 建议产物

- `web-admin/src/router/index.ts`
- `web-admin/src/layouts/AppLayout.vue`
- `web-admin/src/api/client.ts`
- `web-admin/src/api/content.ts`
- `web-admin/src/stores/app.ts`
- `web-admin/src/styles/index.scss`

## 验收标准

1. 应用具备统一 layout 与可切换路由。
2. API 请求不在页面组件内散落实现。
3. 页面切换、标题、基础 loading 能统一处理。
4. 当前阶段不包含任何登录与权限守卫逻辑。

## 不在本任务内

- 业务列表页细节
- 编辑工作台交互
- 版本流转交互

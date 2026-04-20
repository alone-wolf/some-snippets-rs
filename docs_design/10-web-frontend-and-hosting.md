# `web-admin` 前端子项目与托管架构设计

## 1. 目标

在当前 `Rust + axum` 后端项目内新增一个独立的 Web 子项目，名称为 `web-admin`，面向内容平台后台/编辑台场景，满足以下目标：

- 使用 `Node.js + TypeScript + Vue + Element Plus` 构建前端单页应用。
- 前端与后端同仓库开发，但保持工程边界清晰。
- 生产环境编译产物由现有 `axum` 服务托管，不额外引入 Nginx 作为必须前提。
- 开发环境支持前后端分离调试，提高页面开发效率。
- 为后续的内容管理、节点编辑、版本管理提供可扩展 UI 基础。
- 当前阶段不引入任何 auth 限制，默认作为受控环境下的后台应用使用。

## 2. 非目标

首版设计不包含：

- 登录页 / 登录流程
- 用户身份体系
- RBAC 前端权限控制
- SSR / 同构渲染
- 面向搜索引擎的 SEO 站点
- 独立 public 官网
- 微前端拆分
- 多主题设计系统自研

也就是说，本次新增的是**后台型 SPA 子项目**，不是面向外部访客的内容站点。

补充约束：

- 当前阶段 `web-admin` 无登录要求。
- 当前阶段 `web-admin` 无路由访问限制。
- 当前阶段 `web-admin` 无按钮级权限控制。
- 当前阶段默认所有页面在进入应用后都可直接访问。

## 3. 技术选型

## 3.1 运行时与包管理

建议：

- `Node.js 24 LTS`
- `npm`

选择理由：

- 截至 **2026-03-29**，Node.js 官方发布页显示 `v24` 处于 `Active LTS`，适合作为生产默认版本。
- `npm` 随 Node 自带，降低新成员环境准备成本。
- 当前仓库尚未形成多前端包/多 package workspace 诉求，首版无需额外引入 `pnpm workspace` 复杂度。

版本建议：

```text
Node.js >= 24
npm >= 10
```

## 3.2 前端框架

建议：

- `Vue 3`
- `TypeScript`
- `Vite`
- `Vue Router 4`
- `Pinia`
- `Element Plus`

选择理由：

- Vue 官方文档明确推荐用 `create-vue` 创建基于 `Vite` 的 TypeScript 工程。
- Vite 是 Vue 官方推荐构建路径，开发体验与构建速度都适合后台应用。
- Pinia 是 Vue 官方推荐状态管理方案，足够承接后台台账、编辑状态与局部会话态。
- Element Plus 对后台应用组件覆盖率高，能显著降低表单、表格、弹窗、布局的首版成本。

## 3.3 推荐辅助依赖

首版建议包含：

- `axios`：统一请求封装、超时、拦截器、上传场景支持
- `@vueuse/core`：常用组合式工具
- `sass`：样式变量与主题覆写
- `unplugin-auto-import`
- `unplugin-vue-components`

说明：

- Element Plus 官方文档对 `unplugin-auto-import` 与 `unplugin-vue-components` 提供了明确的 Vite 集成建议，适合减少手动 import 成本。
- 若后续需要更严格的运行时响应校验，可在第二阶段引入 `zod`，但首版不是必须项。

## 3.4 测试与工程质量

建议：

- `Vitest`：单元测试
- `Vue Test Utils`：组件测试
- `ESLint`：代码规范
- `Prettier`：格式统一

第二阶段可选：

- `Playwright`：关键页面 E2E

## 4. 总体架构

采用：

```text
前端 SPA + 后端 API + axum 托管静态资源
```

即：

1. 前端单独在 `web-admin/` 目录开发与构建。
2. 开发时由 Vite dev server 负责页面热更新。
3. 生产时 `web-admin/dist/` 编译结果由 `axum` 直接托管。
4. 业务 API 仍由现有 Rust 后端提供。

## 4.1 URL 规划

建议保留当前 API 路径，不强制重写现有后端接口：

- API：
  - `/collections/...`
  - `/contents/...`
  - `/nodes/...`
  - `/draft/...`
  - `/latest/...`
  - `/versions/...`
- 前端 SPA：
  - `/app`
  - `/app/...`

这样做的原因：

- 避免与现有 API 根路径冲突。
- 静态资源和 SPA fallback 只需要挂在 `/app` 子树，风险更可控。
- 后续如果需要对外开放 API 网关，再单独规划 `/api` 前缀迁移。

## 4.2 生产托管策略

生产环境建议：

- `Vite build` 产物输出到 `web-admin/dist/`
- `axum` 使用静态文件服务挂载：
  - `/app/assets/*` -> `web-admin/dist/assets/*`
  - `/app`、`/app/*` -> SPA shell

后端实现建议：

1. 业务 API router 先注册。
2. 再注册前端 router。
3. 前端静态目录使用 `tower_http::services::ServeDir`。
4. 对 `/app/*path` 的深链请求使用 `index.html` fallback。

具体建议：

- 静态资源使用 `ServeDir::new("web-admin/dist")`
- 目录请求保留 `append_index_html_on_directories(true)` 默认行为
- SPA fallback 使用 `fallback(ServeFile::new("web-admin/dist/index.html"))`
- 不要把 SPA fallback 设为全局 fallback，必须限制在 `/app` 子树

原因：

- 如果挂到全局 fallback，API 404 可能被误返回成前端页面。
- 如果 fallback 只挂在 `/app`，则 `/contents/999` 这类 API 404 仍然是后端 JSON 404。

## 4.3 静态资源缓存策略

建议：

- `index.html`：`Cache-Control: no-cache`
- `assets/*`：`Cache-Control: public, max-age=31536000, immutable`

理由：

- Vite 默认会生成带 hash 的静态资源文件名，适合长缓存。
- SPA 入口 HTML 不应该长缓存，否则部署新版本后浏览器可能继续引用旧资源索引。

## 4.4 预压缩策略

建议作为第二阶段优化：

- 构建阶段生成 `.gz` 与 `.br`
- `ServeDir` 启用 `precompressed_gzip()` / `precompressed_br()`

这能在不引入额外反向代理的情况下，降低大体积资源传输成本。

## 5. 开发模式

## 5.1 本地开发拓扑

建议：

```text
axum:  http://127.0.0.1:3000
vite:  http://127.0.0.1:5173
```

开发时：

- 浏览器访问 Vite dev server
- Vite 代理后端 API 到 axum

## 5.2 Vite 代理规则

由于当前后端 API 不是统一 `/api` 前缀，前端 dev proxy 需要覆盖现有接口前缀：

- `/healthz`
- `/collections`
- `/contents`
- `/nodes`
- `/node-lineages`
- `/draft`
- `/latest`
- `/versions`
- `/files`

这样可以：

- 避免本地浏览器跨域问题
- 保持前端请求路径与生产一致

## 5.3 环境变量建议

前端建议使用：

```text
VITE_APP_TITLE=Some Snippets Admin
VITE_API_BASE_URL=
VITE_APP_BASE=/app/
```

说明：

- 生产环境下 `VITE_API_BASE_URL` 可留空，表示同源。
- 若后续需要独立前端部署，再通过该变量切换 API 根地址。
- `VITE_APP_BASE` 与前端托管路径保持一致，默认为 `/app/`。

## 6. 目录结构建议

建议新增：

```text
web-admin/
  package.json
  package-lock.json
  tsconfig.json
  tsconfig.node.json
  vite.config.ts
  index.html
  public/
  src/
    main.ts
    App.vue
    router/
      index.ts
    stores/
      app.ts
      editor.ts
    api/
      client.ts
      content.ts
      node.ts
      version.ts
      types.ts
    layouts/
      AppLayout.vue
      EditorLayout.vue
    views/
      dashboard/
      collections/
      contents/
      editor/
      versions/
      not-found/
    components/
      common/
      content/
      node/
      version/
    composables/
      useDraft.ts
      useVersioning.ts
    styles/
      index.scss
      element.scss
      variables.scss
    types/
      content.ts
      node.ts
    utils/
      env.ts
      request.ts
      route.ts
  tests/
    unit/
```

## 7. 功能模块规划

## 7.1 App Shell

负责：

- 全局布局
- 左侧导航
- 顶部导航
- 面包屑
- 全局消息提示
- 404 / 异常页

建议优先级：最高  
原因：这是所有业务页面的承载骨架。

## 7.2 Collection 与 Content 管理

负责：

- Collection 列表/切换
- Content 列表
- Content 基础信息查看与编辑
- 从 Collection 创建 Content

建议页面：

- `/app/collections`
- `/app/collections/:collectionId/contents`
- `/app/contents/:contentId/settings`

## 7.3 内容编辑工作台

这是首版前端的核心模块。

负责：

- 展示当前 draft 节点顺序
- 新建 text 节点
- 新建 file 节点
- 编辑节点内容
- 调整顺序
- 删除/替换节点引用
- 展示节点生命周期状态

建议页面：

- `/app/contents/:contentId/editor`

建议布局：

```text
左侧：节点列表 / 大纲
中间：当前编辑区
右侧：属性面板 / 元数据 / 文件信息
```

## 7.4 版本管理

负责：

- commit latest
- create version
- 查看版本列表
- 查看指定 version 快照
- rollback 到指定 version

建议页面：

- `/app/contents/:contentId/versions`
- `/app/contents/:contentId/versions/:version`

关键交互：

- commit latest 前给出确认弹窗
- create version 时填写可选 `label`
- rollback 时明确提示“恢复为 draft，不直接覆盖 latest”

## 7.5 当前阶段访问模型

当前阶段约定：

- 不设置登录页
- 不设置用户中心
- 不设置权限不足页
- 不做菜单、路由、按钮级鉴权

说明：

- 当前目标是优先打通后台工作流，不把 auth 作为首版前置条件。
- 如后续需要接入 auth，应单独追加设计与开发任务，不在本阶段强绑定。

## 7.6 文件上传与预览

负责：

- 上传 file 节点文件
- 展示文件名、类型、大小、checksum
- 图片/文本类基础预览

说明：

- 若后端文件上传接口尚未最终稳定，可先以元数据录入模式占位。
- 真正的上传进度、失败重试、断点续传等高级能力放第二阶段。

## 8. 前端状态设计

建议把状态分为两类：

## 8.1 全局状态

使用 `Pinia` 承载：

- 当前 Collection/Content 上下文
- 页面级 UI 状态（侧边栏折叠、主题、全局 loading）

## 8.2 页面/模块局部状态

建议用 `composables + local state` 承载：

- 当前编辑中的表单值
- 节点面板展开状态
- 版本创建弹窗状态
- 暂时未提交的排序结果

原因：

- 并非所有状态都应该进入全局 store。
- 编辑中的临时 UI 态更适合靠近页面维护。

## 8.3 编辑器状态建议

`editor` 模块建议至少区分：

- `serverSnapshot`：最近一次从接口读取的真实数据
- `workingState`：用户当前页面操作态
- `dirty`：是否存在未落库的界面编辑结果
- `saving`：是否正在提交

这样有利于：

- 控制按钮禁用状态
- 提示用户离开页面前确认
- 后续支持更复杂的草稿冲突处理

## 9. API 集成设计

## 9.1 API 客户端分层

建议结构：

```text
api/client.ts      # axios 实例、拦截器、错误标准化
api/content.ts     # content 相关接口
api/node.ts        # node 相关接口
api/version.ts     # commit/version/rollback
api/types.ts       # DTO 类型
```

## 9.2 错误处理约定

前端统一把后端错误映射为：

- 业务错误提示
- 字段级错误提示
- 页面级错误态
- 网络错误提示

建议不要在组件里直接散落 `try/catch + ElMessage`，而是统一通过 API 层和页面层处理。

## 9.3 DTO 策略

建议：

- 先按当前后端 DTO 手工维护 TS 类型
- 等 API 稳定后，再评估是否引入 OpenAPI 生成

原因：

- 当前项目 API 仍在快速演进，过早绑定生成链会增加维护噪音。
- 首版先保证模块边界清晰比“自动生成”更重要。

## 10. 路由设计

建议：

```text
/app
/app/collections
/app/collections/:collectionId/contents
/app/contents/:contentId/settings
/app/contents/:contentId/editor
/app/contents/:contentId/versions
/app/contents/:contentId/versions/:version
```

路由 meta 建议包含：

- `title`
- `layout`

这样后续可以统一做：

- 页面标题更新
- 菜单高亮
- 多布局切换

## 11. 当前阶段鉴权结论

当前阶段明确采用：

- 无登录
- 无 token
- 无 session 依赖
- 无前端权限模型

也就是说：

- 路由层不做 auth guard
- store 中不维护用户与权限状态
- 页面按钮按功能需求直接展示
- 若后端未来返回 `401/403`，前端仅做通用错误提示

## 12. UI 与交互建议

## 12.1 视觉层面

建议：

- 以 Element Plus 默认设计语言为基础
- 通过自定义 token 覆盖主色、圆角、间距
- 不在首版自研完整 design system

## 12.2 交互优先级

首版应优先保证：

- 可理解
- 可回退
- 可确认

重点关注：

- 高风险操作必须二次确认
- 版本类操作要明确影响范围
- committed 节点编辑时要显式提示“将创建替代节点”

## 13. 构建与发布设计

## 13.1 构建输出

建议：

- `npm run build`
- 输出目录：`web-admin/dist`
- Vite 配置：
  - `base: "/app/"`
  - `build.manifest = true`

说明：

- `base: "/app/"` 保证静态资源路径与生产托管路径一致。
- `manifest: true` 虽然首版未必立即使用，但为后续后端读取构建映射预留扩展点。

## 13.2 CI 顺序建议

建议流水线：

1. `npm ci`
2. `npm run lint`
3. `npm run test`
4. `npm run build`
5. `cargo test`
6. 打包后端与 `web-admin/dist`

## 13.3 产物托管边界

建议最终部署包至少包含：

- Rust 可执行文件
- `web-admin/dist/`
- 运行时配置文件

这样可保持：

- 单进程部署
- 环境简单
- 回滚容易

## 14. 推荐实施顺序

建议拆成 4 个阶段：

## 阶段 A：工程初始化

- 创建 `web-admin/` 子项目
- 接入 Vite + Vue + TS + Element Plus
- 建立基础 layout / router / store
- 接入 axum 静态托管最小闭环

验收：

- `GET /app` 能打开首页
- 刷新 `/app/...` 深链不 404
- `cargo run` 与前端构建产物可协同运行

## 阶段 B：内容管理基础页

- Collection / Content 列表
- Content 基础信息查看/编辑
- 错误态、空态、loading 态统一

## 阶段 C：编辑工作台

- draft 加载
- 节点新增/编辑/替换
- committed copy-on-write 的交互提示

## 阶段 D：版本流转页

- commit latest
- create version
- version 列表与详情
- rollback

## 15. 风险与决策点

## 15.1 当前 API 无统一 `/api` 前缀

影响：

- Vite dev proxy 配置稍显冗长

当前建议：

- 首版不强改后端接口
- 前端代理按现有路径前缀配置

## 15.2 SPA 托管与 API 404 容易相互影响

影响：

- 如果静态 fallback 配错，会把 API 404 返回成 HTML

当前建议：

- SPA 仅挂在 `/app`
- API 与静态路由明确分层

## 15.3 DTO 仍处于演进期

影响：

- 前端类型可能跟着后端一起调整

当前建议：

- 首版手工维护类型
- 等接口稳定后再评估自动生成

## 16. 结论

建议本项目的前端子项目 `web-admin` 采用：

```text
Node.js 24 LTS
Vue 3
TypeScript
Vite
Vue Router
Pinia
Element Plus
```

并采用以下工程策略：

- 前端目录独立放在 `web-admin/`
- 开发环境由 Vite 独立运行
- 生产环境由 `axum` 托管 `web-admin/dist`
- SPA 路由统一挂在 `/app`
- API 保持当前路径体系不变
- 当前阶段不接入 auth / 登录 / RBAC

这是一个实现成本、维护复杂度、部署简洁性之间较均衡的方案，适合作为当前项目的首版前端架构。

## 17. 参考资料

- [Node.js Releases](https://nodejs.org/en/about/previous-releases)
- [Vue - Using Vue with TypeScript](https://vuejs.org/guide/typescript/overview)
- [Element Plus - Quick Start](https://element-plus.org/en-US/guide/quickstart)
- [Vite - Backend Integration](https://vite.dev/guide/backend-integration.html)
- [tower-http `ServeDir`](https://docs.rs/tower-http/latest/tower_http/services/fs/struct.ServeDir.html)

# Web Panel UI 开发文档（Draft v1）

## 1. 文档目标

在开始编码前，定义 `some-snippets` 项目的 Web Panel UI 方案，覆盖：

- 产品目标与范围（MVP）
- 前端技术选型与架构
- 页面与组件设计
- 与后端 API 的契约映射
- 开发计划、测试策略与风险

---

## 2. 项目背景

后端已提供 REST API（`/api/v1/*`），资源包括：

- `collections`
- `snippets`
- `histories`
- `nodes`
- `texts`
- `files`
- `tags`

通用能力：分页查询、创建、详情、更新、删除。  
额外规则：`nodes` 的 `kind/text_id/file_id` 组合有严格约束。

Collection 资源字段约定：

- `label`：显示名称
- `key`：唯一标识，并用于 `/api/v1/collections/:key` 路径段

---

## 3. UI 产品目标（MVP）

### 3.1 核心目标

- 提供一个可用的后台管理面板，完成所有资源的 CRUD。
- 支持关系字段可视化编辑（如下拉选择/联动）。
- 让用户在不懂 API 的情况下完成数据维护。

### 3.2 非目标（当前阶段不做）

- 富文本/代码编辑器高级能力（仅文本输入即可）
- 实时协同
- 复杂权限系统（默认单用户/内部工具）

---

## 4. 用户与场景

### 4.1 用户角色

- 开发者/维护者：管理 snippets 及其关联数据。

### 4.2 高频场景

1. 创建 `collection`，再创建 `snippet` 绑定到 collection。
2. 为 snippet 创建 `history` 与 `node`（文本节点/文件节点）。
3. 通过列表页快速查找、编辑、删除异常数据。
4. 在 `files` 页面上传文件，自动提取文件名/MIME/大小并入库。

---

## 5. 信息架构与页面结构

### 5.1 全局布局

- 左侧导航（资源分组）
- 顶部栏（环境标识、刷新按钮）
- 主区域（列表/详情/编辑）

### 5.2 路由建议

- `/` -> Dashboard（可选，先放快捷入口）
- `/collections`
- `/snippets`
- `/histories`
- `/nodes`
- `/texts`
- `/files`
- `/tags`

每个资源页面统一采用：

- 列表页（Table + 分页）
- 新建抽屉/弹窗
- 编辑抽屉/弹窗
- 删除确认弹窗

---

## 6. 功能需求细化

### 6.1 通用 CRUD 能力

- 列表：支持 `page/page_size`，默认 1/20
- 新建：表单校验后提交
- 编辑：拉取详情后回填表单
- 删除：二次确认，删除后刷新当前页

### 6.2 关系字段编辑体验

- `snippet.connection_id`：下拉选择 collection
- `snippet.current_history_id`：下拉选择 history（后续可限制为当前 snippet 的 history）
- `history.snippet_id`：下拉选择 snippet
- `node.snippet_id/text_id/file_id`：下拉选择对应资源
- collection 列表展示使用 `label`，详情路由使用 `key`
- `files` 支持上传：选择文件后自动 POST 到 `/api/v1/files/upload`，由后端写盘并回填元数据

### 6.3 Node 业务规则（必须实现）

- `kind` 必填：`text | file`
- `kind = text`：`text_id` 必填，`file_id` 必须为空
- `kind = file`：`file_id` 必填，`text_id` 必须为空

前端校验要在提交前拦截，并给出明确错误提示。

---

## 7. 技术选型建议（Vue3 + Element Plus）

- 框架：Vue 3 + TypeScript + Vite
- 路由：Vue Router 4
- 状态管理：Pinia
- UI 组件：Element Plus
- 表单：Element Plus Form + 自定义校验规则
- HTTP：Axios（统一拦截器与错误处理）

目录建议：

```text
web/
  src/
    layout/
    pages/
    components/
    services/
    stores/
    composables/
    types/
    utils/
```

---

## 8. API 契约与前端类型

### 8.1 基础约定

- Base URL：`http://127.0.0.1:3000`
- API Prefix：`/api/v1`
- 健康检查：`GET /ping`

### 8.2 响应包装（建议前端按该结构适配）

```ts
interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  request_id?: string;
  status_code?: number;
}
```

列表接口 `data` 结构：

```ts
interface ListData<T> {
  items: T[];
  page: number;
  page_size: number;
}
```

---

## 9. 交互与状态管理规范

- Store 规范（Pinia）：按资源拆分 `useCollectionStore/useSnippetStore/...`
- 列表与详情状态：优先页面内管理，必要时下沉到 store 复用
- 新增/编辑/删除成功后统一：
  - Toast 成功提示
  - 触发当前资源列表刷新，必要时刷新关联详情
- 错误处理：
  - `400`：展示字段错误或业务提示
  - `404`：提示记录不存在并刷新列表
  - `409`：提示“存在引用冲突，无法删除/更新”
  - `500`：通用系统错误提示

---

## 10. UI 设计规范（MVP）

- 统一 8px 间距体系
- 列表操作列：`查看 | 编辑 | 删除`
- 删除按钮使用危险色，必须二次确认
- 所有时间字段统一本地化展示（如 `YYYY-MM-DD HH:mm:ss`）
- 表单字段提供 placeholder 与校验文案

---

## 11. 开发里程碑

### Milestone 1：脚手架与基础设施（0.5~1 天）

- 初始化 Vite + Vue3 + TS
- 接入 Vue Router、Pinia、Element Plus
- 搭建 Layout 和导航

### Milestone 2：通用 CRUD 页面框架（1~2 天）

- 抽象 `ResourceTable` / `ResourceFormDialog`
- 完成 `collections/tags/texts/files` 页面

### Milestone 3：关联资源页面（1~2 天）

- 完成 `snippets/histories/nodes`
- 实现 Node 规则校验与联动

### Milestone 4：联调与质量完善（1 天）

- 错误态、空态、加载态
- 文案与交互打磨
- 冒烟测试与文档更新

---

## 12. 测试策略

- 单元测试：表单校验函数（尤其 Node 规则）
- 组件测试：列表渲染、弹窗提交、错误展示
- E2E 冒烟：创建 collection -> snippet -> history -> node 完整链路

---

## 13. 风险与待确认项

- `snippet.current_history_id` 是否必须属于同一 `snippet`（建议后端补强）
- `files` 上传机制未定义（当前仅维护元数据）
- 是否需要按 `label/name` 搜索过滤（当前 API 未提供）

---

## 14. 下一步（进入编码前）

1. 你确认 UI 技术栈（Vue3 + Element Plus + Vue Router + Pinia）。
2. 你确认页面优先级（建议先 `collections/snippets/histories/nodes`）。
3. 我基于本文件开始生成前端工程与第一版页面。

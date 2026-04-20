# T17 Collection 与 Content 管理页面

## 状态

- 已完成（2026-03-29）

## 目标

提供 `web-admin` 中最基础的内容管理入口，包括 Collection 选择、Content 列表以及内容基础信息查看/编辑。

## 输入

- `docs_design/10-web-frontend-and-hosting.md`
- `docs_design/05-api-design.md`

## 前置依赖

- `T16`

## 具体工作

1. 实现 Collection 列表/切换页。
2. 实现指定 Collection 下的 Content 列表页。
3. 实现 Content 基础信息页：
   - 标题
   - slug
   - status
   - schema_id
4. 实现创建 Content 入口。
5. 实现更新 Content 基础信息入口。
6. 补齐基础页面状态：
   - loading
   - empty
   - error
7. 打通从内容列表跳转到编辑页和版本页的入口。

## 建议产物

- `web-admin/src/views/collections/*`
- `web-admin/src/views/contents/*`
- `web-admin/src/components/content/*`

## 验收标准

1. 可以浏览 Collection 与 Content 列表。
2. 可以创建并编辑 Content 基础信息。
3. 页面状态完整，不只有“成功态”。
4. 页面不依赖 auth 才能访问。

## 不在本任务内

- 节点编辑
- 版本流转
- 文件上传高级交互

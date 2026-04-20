# Design Documents

本目录用于沉淀当前内容平台项目的设计文档，目标是把现有方向整理成可实现、可迭代、可评审的工程方案。

## 当前核心思路

本轮确认后的核心前提是：

- 数据库保存当前内容节点实体。
- `Node` 是统一节点表，通过 `kind` 区分 `text` / `file`。
- `Node.id` 是物理行标识，只用于数据库内部和 `draft` 编排引用。
- `Node.uuid` 是逻辑节点标识，`Node.version` 是该逻辑节点的代际版本号。
- `Node` 采用 `draft_only / committed` 生命周期。
- `draft_only` 节点允许原地修改，`committed` 节点禁止原地修改。
- 已提交节点后续修改必须走 copy-on-write，复用 `uuid`、递增 `version`、新建 Node 再更新 draft 引用。
- `FileMetadata` 只为 `Node.kind = file` 提供文件细节。
- `Content` 保存内容级 metadata。
- `content_versions` 表保存版本元数据索引，不再只依赖对象存储命名约定查版本。
- `version` 在 API 和 JSON 数据中一律使用纯整数。
- `content.<version>.json` 的文件名使用 6 位零填充数字，例如 `content.000123.json`。
- `label` 是用户可写的展示字段，与版本编号不绑定。
- `content.draft.json` 只保存 `Node.id` 引用和顺序。
- `content.latest.json` / `content.<version>.json` 保存完整节点快照，并冗余 `uuid + version`。
- 回滚不是直接用 version 文件覆盖 draft，而是把 version 快照解析为一组 `Node.id` 引用后重建 `content.draft.json`。

## 文档列表

1. `00-product-vision-and-scope.md`
2. `01-domain-model.md`
3. `02-permission-and-policy.md`
4. `03-versioning-and-publishing.md`
5. `04-storage-and-data-layout.md`
6. `05-api-design.md`
7. `06-service-architecture-axum.md`
8. `07-database-schema.md`
9. `08-evolution-roadmap.md`
10. `09-content-json-schema.md`
11. `10-web-frontend-and-hosting.md`

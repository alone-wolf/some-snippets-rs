# T10 Rollback 流程

## 状态

- 已完成（2026-03-29）

## 目标

实现从历史 version 快照恢复 draft 的流程，遵守“version 快照归一化为 ref-only draft”的规则。

## 输入

- `docs_design/03-versioning-and-publishing.md`
- `docs_design/05-api-design.md`
- `docs_design/09-content-json-schema.md`

## 前置依赖

- `T06`
- `T07`
- `T09`

## 具体工作

1. 根据整数 `version` 查询 `content_versions`。
2. 读取对应 `content.<version>.json`。
3. 逐个节点执行恢复策略：
   - 优先按 `nodeId` 查找
   - 其次按 `uuid + version` 查找
   - 不存在则按快照补建 Node
4. 补建 file 节点时同步补建 `FileMetadata`。
5. 重建 `content.draft.json`：
   - 只保存恢复后节点的 `Node.id`
6. 默认不覆盖 `content.latest.json`。

## 建议产物

- `src/modules/content/rollback_service.rs`
- `src/storage/snapshot/rollback.rs`

## 验收标准

1. rollback 后得到的是合法的 ref-only draft 文件。
2. 缺失节点可按快照补建并继续进入 draft。
3. rollback 不会直接覆盖 latest。

## 不在本任务内

- 自动把 rollback 结果再次 commit 为 latest

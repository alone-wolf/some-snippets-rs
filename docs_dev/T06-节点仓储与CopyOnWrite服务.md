# T06 节点仓储与 Copy-on-Write 服务

## 状态

- 已完成（2026-03-29）

## 目标

实现节点的核心读写规则，尤其是 `draft_only` 可原地编辑、`committed` 必须 copy-on-write 的行为。

## 输入

- `docs_design/01-domain-model.md`
- `docs_design/03-versioning-and-publishing.md`
- `docs_design/07-database-schema.md`

## 前置依赖

- `T04`

## 具体工作

1. 实现 `NodeRepository`：
   - 按 `id` 查找
   - 按 `uuid + version` 查找
   - 批量按 `id` 查找
2. 实现 `FileMetadataRepository`。
3. 实现文本节点编辑逻辑：
   - `draft_only` 原地更新
   - `committed` 复制新 Node，复用 `uuid`，`version + 1`
4. 实现文件节点编辑逻辑：
   - `draft_only` 更新 `FileMetadata`
   - `committed` 复制新 Node 和新 `FileMetadata`
5. 返回统一的节点编辑结果：
   - 老节点
   - 新节点
   - 是否发生 copy-on-write

## 建议产物

- `src/modules/node/repository.rs`
- `src/modules/node/service.rs`
- `src/modules/file/repository.rs`
- `src/modules/file/service.rs`

## 验收标准

1. `draft_only` 节点更新不会新建记录。
2. `committed` 节点更新会生成新节点，且复用 `uuid`、递增 `version`。
3. file 节点 copy-on-write 时，新的 `file_metadata` 也会正确创建。

## 不在本任务内

- draft 快照文件重写
- HTTP handler

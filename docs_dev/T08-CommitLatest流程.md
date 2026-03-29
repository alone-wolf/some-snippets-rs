# T08 Commit latest 流程

## 状态

- 已完成（2026-03-29）

## 目标

实现从当前 draft 生成 `content.latest.json` 的完整提交流程。

## 输入

- `docs_design/03-versioning-and-publishing.md`
- `docs_design/04-storage-and-data-layout.md`
- `docs_design/09-content-json-schema.md`

## 前置依赖

- `T05`
- `T06`
- `T07`

## 具体工作

1. 读取当前 draft 中的 `Node.id` 顺序。
2. 批量加载节点和可选 `FileMetadata`。
3. 组装 `content.latest.json`：
   - `state = latest`
   - `version = contents.latest_version`
   - 嵌入完整节点快照
4. 写入对象存储。
5. 更新 `contents.latest_snapshot_key`。
6. 将被 latest 引用到的节点批量标记为 `committed`。

## 建议产物

- `src/storage/snapshot/latest.rs`
- `src/modules/content/commit_service.rs`

## 验收标准

1. latest 文件包含完整节点快照。
2. latest 文件中的节点顺序与 draft 一致。
3. 被引用节点会转为 `committed`。

## 不在本任务内

- 人工 version 创建
- 回滚流程

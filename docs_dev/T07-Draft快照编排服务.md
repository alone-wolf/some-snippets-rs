# T07 Draft 快照编排服务

## 状态

- 已完成（2026-03-29）

## 目标

实现 `content.draft.json` 的读取、重建和持久化，使 draft 成为唯一的当前编排文件。

## 输入

- `docs_design/01-domain-model.md`
- `docs_design/03-versioning-and-publishing.md`
- `docs_design/09-content-json-schema.md`

## 前置依赖

- `T05`
- `T06`

## 具体工作

1. 定义 `content.draft.json` DTO。
2. 实现 draft 读取服务。
3. 实现 draft 重建服务：
   - 新增 node 引用
   - 删除 node 引用
   - 调整顺序
   - 替换旧 `nodeId` 为新 `nodeId`
4. 将 draft 写回对象存储。
5. 同步更新 `contents.draft_snapshot_key`。

## 建议产物

- `src/storage/snapshot/draft.rs`
- `src/modules/content/draft_service.rs`
- `src/web/dto/draft.rs`

## 验收标准

1. draft 文件只保存 `Node.id` 引用顺序。
2. 节点编辑后，draft 可正确替换为新 `nodeId`。
3. draft 文件满足 `docs_design/09-content-json-schema.md` 的约束。

## 不在本任务内

- latest/version 快照
- 回滚流程

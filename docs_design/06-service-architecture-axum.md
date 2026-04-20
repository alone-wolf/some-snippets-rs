# Rust + axum 服务架构设计

## 1. 模块边界建议

### content 模块

负责：

- `Content` CRUD
- draft/latest/version 快照管理
- `content_versions` 元数据管理
- 从数据库节点生成 `content.*.json`
- rollback 时把完整快照归一化为 ref-only draft

### node 模块

负责：

- `Node` 创建、更新、删除
- `Node.kind` 分支逻辑
- `uuid + version` 版本链维护
- `draft_only / committed` 生命周期判断
- committed 节点的 copy-on-write
- 节点更新后的 draft 重建

### file 模块

负责：

- 文件上传下载
- `FileMetadata` 管理
- bucket / object key 管理

## 2. 请求流示例

以“更新一个 file 节点”为例：

1. handler 接收请求
2. service 加载 `Node`
3. 校验 `Node.kind = file`
4. 判断 `Node.lifecycle_state`
5. 若为 `draft_only`，直接更新 `Node` 和 `FileMetadata`
6. 若为 `committed`，创建新 Node 和新 `FileMetadata`，复用旧 `uuid`，并令 `version = old.version + 1`
7. 更新 draft 中的节点引用
8. 重新生成 `content.draft.json`
9. 返回新的节点状态

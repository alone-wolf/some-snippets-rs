# 存储与数据布局设计

## 1. 存储分层

推荐采用：

- 关系数据库：存储 `Content`、`ContentVersion`、`Node`、`FileMetadata`
- 对象存储：存储文件二进制和 `content.*.json`

## 2. 数据分类

### 进入数据库

- `contents`
- `content_versions`
- `nodes`
- `file_metadata`
- `collections`
- 权限与审计相关表

### 进入对象存储

- 文件二进制
- `content.draft.json`
- `content.latest.json`
- `content.<version>.json`

## 3. 一致性要求

需要保证：

- `content.draft.json` 中的 `Node.id` 引用始终有效
- `nodes(uuid, version)` 组合始终唯一
- `content_versions(content_id, version)` 组合始终唯一
- `FileMetadata.node_id` 始终指向 `Node.kind = file`
- `Content.draft_snapshot_key` 和 `latest_snapshot_key` 始终有效
- `Node.prev_node_id` 不形成非法断链

## 4. 写入路径

### 文本编辑

1. 读取目标 Node
2. 若 `lifecycle_state = draft_only`，直接更新 `Node.text_content`
3. 若 `lifecycle_state = committed`，创建新 Node，并复用 `uuid`、设置 `version = old.version + 1`、设置 `prev_node_id`
4. 更新 draft 中对应的 `Node.id` 引用
5. 重新生成 `content.draft.json`

### 文件更新

1. 上传文件到对象存储
2. 读取目标 Node
3. 若 `lifecycle_state = draft_only`，直接更新 `FileMetadata`
4. 若 `lifecycle_state = committed`，创建新 Node 和新 `FileMetadata`，并复用 `uuid`、设置 `version = old.version + 1`
5. 更新 draft 中对应的 `Node.id` 引用
6. 重新生成 `content.draft.json`

### latest 提交

1. 从 draft 中读取 `Node.id` 编排
2. 加载对应 Node 内容并生成 `content.latest.json`
3. 更新 `Content.latest_snapshot_key`
4. 将 latest 中引用到的节点批量标记为 `committed`

### version 创建

1. 从 `content.latest.json` 读取 latest 快照
2. 重写 `state=version` 和整数 `version`
3. 以 6 位零填充版本号写入 `content.<version>.json`
4. 写入 `content_versions`

### rollback

1. 读取目标 `content.<version>.json`
2. 逐个节点按 `nodeId` 或 `uuid + version` 解析数据库实体
3. 若找不到对应实体，则按快照内容补建 `Node` 和可选 `FileMetadata`
4. 以解析出的 `Node.id` 顺序重建 `content.draft.json`

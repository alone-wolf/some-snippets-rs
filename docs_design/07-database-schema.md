# 数据库 Schema 设计

## 1. 核心表

基于当前模型，核心表建议为：

- `collections`
- `contents`
- `content_versions`
- `nodes`
- `file_metadata`

## 2. contents

```text
id
collection_id
slug
title
status
schema_id
draft_snapshot_key
latest_snapshot_key
latest_version
created_by
updated_by
created_at
updated_at
archived_at
```

补充说明：

- `latest_version` 是缓存字段，不作为版本查询主来源。
- 版本查询、列表、校验和标签等信息应以 `content_versions` 为准。
- `latest_version` 建议使用整数类型。
- `latest_version` 建议默认值为 `0`。

## 3. content_versions

```text
id
content_id
version
label
snapshot_key
snapshot_checksum
created_by
created_at
meta_json
```

约束建议：

- `(content_id, version)` 唯一
- `version` 必须为整数
- `snapshot_key` 必须指向一个 6 位零填充版本号的 `content.<version>.json`
- `snapshot_checksum` 建议保存为不可变校验值

## 4. nodes

```text
id
content_id
uuid
version
kind
lifecycle_state
text_content
prev_node_id
meta_json
created_by
updated_by
created_at
updated_at
deleted_at
```

约束建议：

- `(uuid, version)` 唯一
- `version >= 0`
- `kind = text` 时，`text_content` 非空
- `kind = file` 时，`text_content` 为空
- `lifecycle_state` 建议取值为 `draft_only` / `committed`
- `prev_node_id` 自引用 `nodes.id`

补充说明：

- `id` 是物理主键，用于 draft 内部引用。
- `uuid` 是逻辑节点标识。
- `version` 是该逻辑节点的代际版本号。
- `version` 不表示草稿态保存次数，而表示 copy-on-write 代际。
- `draft_only` 节点原地修改时，不强制递增 `version`。
- 对 `committed` 节点做 copy-on-write 时，必须复用 `uuid` 并令 `version = old.version + 1`。
- `content.draft.json` 对节点的引用应使用 `nodes.id`
- `content.latest.json` / `content.<version>.json` 可冗余 `nodeId + uuid + version + 快照内容`

## 5. file_metadata

```text
id
node_id
file_uuid
bucket
object_key
filename
mime_type
size_bytes
checksum
meta_json
created_at
updated_at
```

约束建议：

- `node_id` 唯一
- `node_id` 必须指向 `nodes.kind = file`

## 6. 关键索引

- `nodes(content_id, kind)`
- `nodes(content_id, lifecycle_state)`
- `nodes(uuid, version)`
- `content_versions(content_id, version)`
- `nodes(prev_node_id)`
- `file_metadata(node_id)`
- `file_metadata(file_uuid)`

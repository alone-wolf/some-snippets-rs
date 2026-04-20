# API 设计

## 1. 核心资源

```http
POST   /collections/{collection_id}/contents
GET    /contents/{content_id}
PATCH  /contents/{content_id}

POST   /contents/{content_id}/nodes
PATCH  /nodes/{node_id}
DELETE /nodes/{node_id}

GET    /nodes/{node_id}
GET    /node-lineages/{uuid}/versions/{version}
GET    /nodes/{node_id}/file-metadata

POST   /contents/{content_id}/commit
POST   /contents/{content_id}/versions
POST   /contents/{content_id}/rollback

GET    /draft/contents/{content_id}
GET    /latest/contents/{content_id}
GET    /contents/{content_id}/versions
GET    /versions/contents/{content_id}/{version}

POST   /files/upload
```

## 2. 关键语义

### 创建节点

`POST /contents/{content_id}/nodes`

请求体示例：

```json
{
  "kind": "text",
  "text": "hello"
}
```

或：

```json
{
  "kind": "file",
  "file": {
    "filename": "demo.png",
    "bucket": "content-assets"
  }
}
```

语义：

- 创建 `Node`
- 服务端生成新的逻辑 `uuid`
- 新节点默认 `version = 0`
- 如为 file，则创建 `FileMetadata`
- 更新 `content.draft.json`
- 新建节点默认 `lifecycle_state = draft_only`

说明：

- draft 中引用节点时应使用 `Node.id`

### 更新节点

`PATCH /nodes/{node_id}`

语义：

- 若节点为 `draft_only`，直接更新当前节点数据
- 若节点为 `committed`，创建替代 Node，并更新 draft 中的节点引用
- committed 节点的替代 Node 需要复用旧 `uuid`，并令 `version = old.version + 1`
- 如有必要同步更新 `FileMetadata`
- 更新 `content.draft.json`

说明：

- `node_id` 是 draft 工作态引用键
- 若需要稳定读取某个特定节点版本，应使用 `uuid + version`

### 查询特定节点版本

`GET /node-lineages/{uuid}/versions/{version}`

语义：

- 按 `uuid + version` 返回某个确定的节点版本
- 可用于调试、审计、回滚解析和快照校验

### commit latest

`POST /contents/{content_id}/commit`

语义：

- 按 `content.draft.json` 中的 `Node.id` 引用加载节点内容
- 将当前草稿编排固化为 `content.latest.json`
- 并把 latest 中引用到的节点标记为 `committed`

### create version

`POST /contents/{content_id}/versions`

语义：

- 从 `content.latest.json` 创建 `content.<version>.json`
- 将顶层 `state` 重写为 `version`
- 将顶层 `version` 写为新生成的整数版本号
- 写入 `content_versions` 元数据记录

### rollback

`POST /contents/{content_id}/rollback`

请求体示例：

```json
{
  "version": 3
}
```

语义：

- 读取目标 `content.<version>.json`
- 逐个节点按 `nodeId` 或 `uuid + version` 解析数据库中的 `Node`
- 若数据库中不存在目标节点，则按快照补建节点
- 生成新的 `content.draft.json`
- 默认不覆盖 `content.latest.json`

补充约束：

- 请求体中的 `version` 必须是纯整数
- 文件名中的版本号应格式化为 6 位零填充数字
- `label` 如存在，只作为展示字段，不参与查询和回滚定位

### 版本查询

`GET /contents/{content_id}/versions`

语义：

- 从 `content_versions` 返回版本列表

`GET /versions/contents/{content_id}/{version}`

语义：

- 先从 `content_versions` 解析版本元数据
- 再加载对应的 `content.<version>.json`

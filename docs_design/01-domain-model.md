# 领域模型设计

## 1. 设计目标

领域模型需要满足：

- `Content` 保存内容级语义
- `Node` 统一表示文本和文件节点
- `FileMetadata` 只承载 file 节点细节
- `content.*.json` 承担编排和快照职责
- 在工程上尽量让已提交 Node 不可变

## 2. 核心建模思路

当前设计采用以下折衷模型：

```text
Collection
  └── Content
        └── Node(kind=text|file)
              └── FileMetadata (only when kind=file)
        └── ContentVersion

content.draft.json
  └── 保存 Node.id 引用顺序

content.latest.json / content.<version>.json
  └── 保存完整 Node 快照内容（含 uuid + version）
```

也就是说：

- 数据库保存当前节点实体。
- draft JSON 保存节点引用编排。
- latest/version JSON 保存节点快照投影。
- `content_versions` 保存版本元数据索引。
- 节点可变性由 `draft_only / committed` 生命周期控制。
- 节点逻辑身份由 `uuid + version` 表达。

## 3. 核心实体

### 3.1 Collection

职责：

- 权限边界
- 内容归属空间
- 默认配置承载点

建议字段：

```text
id
slug
name
description
visibility
owner_id
config_json
created_at
updated_at
archived_at
```

### 3.2 Content

职责：

- 表示一个内容对象
- 保存内容级 metadata
- 关联一组 Node
- 指向当前 draft/latest 快照

建议字段：

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

说明：

- `draft_snapshot_key` 指向 `content.draft.json`
- `latest_snapshot_key` 指向 `content.latest.json`
- `latest_version` 仅作为最近一次版本号缓存，建议默认值为 `0`
- 版本列表与版本查询的真实来源是 `ContentVersion`

### 3.3 ContentVersion

职责：

- 保存版本元数据索引
- 连接逻辑版本号与对象存储中的快照文件
- 承接版本查询、版本列表和审计信息

建议字段：

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

设计说明：

- `version` 在单个 `content_id` 下唯一。
- `snapshot_key` 指向 `content.<version>.json`。
- `snapshot_checksum` 用于校验版本文件未被意外污染。
- `Content.latest_version` 是缓存，`ContentVersion` 才是版本索引主表。
- `version` 建议使用纯整数。
- 快照文件命名时将 `version` 格式化为 6 位零填充数字。
- `label` 是展示字段，不参与版本定位。

### 3.4 Node

职责：

- 统一表示 content 中的节点
- 用 `kind` 区分 `text` / `file`
- 保存节点当前内容和基础信息

建议字段：

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

设计说明：

- `id` 是物理主键，用于数据库内部关联和 `draft` 引用。
- `uuid` 是逻辑节点标识，用于标识同一条节点演进链。
- `version` 是该逻辑节点的代际版本号，默认从 `0` 开始。
- 查询一个特定节点版本时，以 `uuid + version` 为稳定坐标。
- `version` 表示节点代际，不表示草稿期的每次保存次数。
- `kind = text` 时，`text_content` 有值。
- `kind = file` 时，`text_content` 为空，详细信息放到 `FileMetadata`。
- `lifecycle_state` 建议取值为 `draft_only` / `committed`。
- `draft_only` 表示该节点尚未进入 latest/version。
- `committed` 表示该节点已经进入 latest 或 version，不允许原地修改。
- `prev_node_id` 用于记录 copy-on-write 来源链。
- `draft_only` 原地修改不强制递增 `version`。
- 对 `committed` 节点做 copy-on-write 时，应复用 `uuid`，并令 `version = old.version + 1`。

### 3.5 FileMetadata

职责：

- 保存 file 节点的详细信息
- 负责文件定位和渲染所需 metadata

建议字段：

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

设计说明：

- `node_id` 唯一关联到一条 `Node(kind=file)`。
- `bucket + object_key` 用于定位底层文件对象。
- 如果 `node_id` 指向的节点已经 committed，则对应 `FileMetadata` 也应视为不可变。

## 4. 快照文件结构

### 4.1 Draft 结构

建议 `content.draft.json` 使用轻量引用结构：

```json
{
  "contentId": "content_xxx",
  "state": "draft",
  "label": "draft",
  "nodes": [
    {
      "nodeId": 101
    },
    {
      "nodeId": 205
    }
  ]
}
```

说明：

- `nodes` 数组按顺序排列。
- draft 中的节点引用应采用 `Node.id`，不使用 `uuid + version`。
- draft 只承担“当前编排”职责，不承担完整快照职责。

### 4.2 Latest / Version 结构

建议 `content.latest.json` 和 `content.<version>.json` 使用完整快照结构：

```json
{
  "contentId": "content_xxx",
  "state": "latest",
  "version": 12,
  "label": "latest",
  "nodes": [
    {
      "nodeId": 101,
      "uuid": "node_txt_1",
      "version": 0,
      "kind": "text",
      "text": "hello",
      "meta": {}
    },
    {
      "nodeId": 205,
      "uuid": "node_file_1",
      "version": 0,
      "kind": "file",
      "file": {
        "filename": "demo.png",
        "bucket": "content-assets",
        "objectKey": "path/to/object"
      }
    }
  ]
}
```

说明：

- latest/version 保存完整节点快照。
- 可以冗余 `nodeId`，但不依赖数据库才能完成读取。
- `uuid + version` 才是快照中的稳定节点坐标。
- 旧快照不应受后续 Node 修改污染。
- `latest.version` 建议为整数，若尚未创建任何人工 version，可使用 `0`。

## 5. 关系图

```text
Collection   1 --- N Content
Content      1 --- N ContentVersion
Content      1 --- N Node
Node         1 --- 0..1 FileMetadata
Node         0..1 -> Node(prev_node_id)
Content      1 --- 1 Snapshot(draft)
Content      1 --- 1 Snapshot(latest)
Content      1 --- N Snapshot(version)
```

## 6. 关键建模决策

### 决策一：Node 统一承载文本和文件节点

这样可以：

- 降低模型数量
- 统一节点生命周期
- 统一 API 和查询入口

### 决策二：FileMetadata 独立拆表

这样可以：

- 避免通用节点表充满文件专属字段
- 让 file 节点的扩展更容易
- 保持 `Node` 模型紧凑

### 决策三：Node 采用 draft_only / committed 生命周期

这样可以：

- 让草稿期编辑保持轻量
- 让已提交节点尽量不可变
- 避免 latest/version 被后续草稿编辑污染

推荐规则：

- 新建节点默认为 `draft_only`
- commit latest 时，被 latest 引用到的节点都转为 `committed`
- `draft_only` 节点可原地修改，但不把 `version` 当成草稿保存计数器
- committed 节点后续编辑时，不可原地修改，必须新建 Node，并让新的 `prev_node_id` 指向旧节点
- committed 节点 copy-on-write 时复用原 `uuid`，并把 `version` 递增 1

### 决策四：编排放进 content.*.json

这样可以：

- 不必引入额外的节点编排关系表
- draft/latest/version 的语义天然明确
- 快照导出和回滚更直接

进一步约束：

- draft 只保存 `Node.id` 引用
- latest/version 保存完整节点快照
- version 快照回滚到 draft 时，必须先归一化成一组 `Node.id`

### 决策五：数据库保存当前态，JSON 保存编排快照

这样可以：

- 当前节点可查、可改、可过滤
- draft 文件足够轻，适合高频更新
- latest/version 快照可导出、可回滚、可分发
- 两层职责清晰，不互相覆盖

### 决策六：版本索引单独落库

这样可以：

- 避免只靠对象存储命名约定做版本查询
- 支持版本列表、标签、审计、校验和
- 让 API 不必直接扫描对象存储

### 决策七：rollback 是“快照归一化”而不是“文件覆盖”

这样可以：

- 保持 `draft` 的 ref-only 结构不变
- 保持 `version` 的完整快照结构不变
- 让回滚后的 draft 继续服从当前节点模型和 copy-on-write 规则

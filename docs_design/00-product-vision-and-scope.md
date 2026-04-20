# 产品定位与范围

## 1. 项目定位

该系统是一个面向结构化内容与文件混合管理的内容基础设施平台。

可以概括为：

> 一个以数据库节点模型为当前态、以 `content.*.json` 为编排与快照载体、支持文件托管和后续发布的内容平台。

## 2. 核心目标

首版系统优先解决以下问题：

- 在统一模型下管理文本节点和文件节点。
- 用一张 `Node` 表统一表示 content 中的节点数据。
- 用 `uuid + version` 表示逻辑节点及其代际版本。
- 用 `FileMetadata` 保存 file 节点的详细信息。
- 用 `content_versions` 保存版本元数据索引。
- 用 `content.draft.json` 保存节点引用编排。
- 用 `content.latest.json`、`content.<version>.json` 保存完整节点快照。
- 在不引入过重历史模型的前提下，让节点尽量不可变。

## 3. 一期范围

一期建议范围如下：

- `Collection` 作为业务空间和权限边界
- `Content` 作为内容聚合与分发单元
- `Node` 保存文本或文件节点，`kind` 区分类型
- `Node` 通过 `uuid + version` 表达逻辑身份和版本代际
- `Node` 支持 `draft_only / committed` 生命周期
- `FileMetadata` 保存 file 节点的文件信息
- `content_versions` 保存版本号、标签、快照路径、创建人等元数据
- `content.*.json` 保存节点编排与三态快照
- 基础 RBAC 与 REST API
- 数据库存当前节点，对象存储存文件二进制和内容快照 JSON

## 4. 关键术语

### Content

一个内容对象，保存内容级 metadata，并关联一组节点。

### Node

统一节点实体，保存 content 中的一个节点。通过 `kind` 区分 `text` 或 `file`。

在当前设计中：

- `id` 是物理主键
- `uuid` 是逻辑节点标识
- `version` 是逻辑节点的代际版本号，默认从 `0` 开始
- `draft_only` 节点可直接修改
- `committed` 节点不可直接修改
- 已提交节点的后续修改通过 copy-on-write 完成

补充约束：

- `draft_only` 原地修改不强制递增 `version`
- 对 `committed` 节点做修改时，新节点复用旧 `uuid`，并令 `version = old.version + 1`

### FileMetadata

文件节点的详细信息表，只在 `Node.kind = file` 时存在。

### content_versions

版本元数据索引表，用于支持版本列表、版本查询、审计信息和对象存储快照定位。

约束：

- `version` 是纯整数版本号。
- 快照文件名使用 6 位零填充数字，例如 `content.000001.json`。
- `label` 是展示文本，不参与版本定位。

### content.draft.json

当前草稿编排文件，只保存 `Node.id` 引用和顺序。

### content.latest.json

当前稳定快照文件，保存完整节点内容。

### content.<version>.json

从 latest 手动创建的不可变版本快照，保存完整节点内容。

命名约束：

- `<version>` 在文件名中应格式化为 6 位零填充数字。
- 例如：第 12 个版本写作 `content.000012.json`。

### rollback

回滚不会直接把 `content.<version>.json` 文件覆盖为 `content.draft.json`。

系统应当先读取目标快照，再把快照中的节点解析或补建为数据库 `Node`，最后重建只含 `Node.id` 的 `content.draft.json`。

## 5. 成功标准

当系统满足以下条件时，说明基础设计有效：

- Content 可以稳定地组织一组 Node
- Node 可以统一表示文本和文件
- file 节点的文件细节不会污染通用节点模型
- 快照编排和当前节点实体边界清晰
- commit 之后的节点不会被后续编辑污染
- 历史版本可以通过 `content_versions` 稳定查询
- 回滚可以稳定地把历史快照恢复为可编辑 draft
- 后续发布、回滚、导出时无需推翻核心模型

# 版本与发布设计

## 1. 核心思路

在当前折衷模型下：

- 数据库中的 `Node` 保存当前节点状态
- `content.draft.json` 保存节点引用编排
- `content.latest.json` / `content.<version>.json` 保存完整节点快照
- `content_versions` 保存版本元数据索引
- `Node` 通过 `draft_only / committed` 控制可变性
- `Node.uuid + version` 表示稳定的节点版本坐标

推荐采用三类快照文件：

- `content.draft.json`
- `content.latest.json`
- `content.<version>.json`

版本号约束：

- API 和 JSON 数据中的 `version` 一律使用纯整数。
- 对象存储文件名中的 `<version>` 使用 6 位零填充数字。
- `label` 是展示字段，与版本编号无直接关系。

## 2. Draft 策略

`content.draft.json` 表示当前草稿编排。

它只保存：

- 节点顺序
- 节点引用

不保存：

- 完整 text 内容
- 完整 file metadata 快照

当用户做以下动作时，需要更新 draft：

- 新增节点
- 删除节点
- 调整节点顺序
- 替换节点引用
- 节点内容发生变化后重新导出当前编排

草稿期节点规则：

- 新建节点默认是 `draft_only`
- `draft_only` 节点允许直接修改
- 只要节点还未进入 latest/version，就不必强制 copy-on-write
- draft 对节点的引用应使用 `Node.id`
- `draft_only` 原地修改不强制递增 `Node.version`
- `Node.version` 表示 copy-on-write 代际，不表示 draft 保存次数

## 3. Latest 策略

`content.latest.json` 表示最近一次确认后的稳定快照。

建议流程：

1. 读取当前 `content.draft.json` 中的 `Node.id` 列表
2. 从数据库加载这些 `Node.id` 对应的节点内容
3. 按 draft 顺序生成完整快照
4. 写入 `content.latest.json`
5. 更新 `Content.latest_snapshot_key`
6. 将被 latest 引用到的 `Node` 批量标记为 `committed`
7. 令 `content.latest.json.state = latest`
8. 令 `content.latest.json.version = Content.latest_version`

补充说明：

- `Content.latest_version` 建议默认值为 `0`
- 因此 `content.latest.json.version` 在首个 version 创建前也应是整数 `0`

## 4. Version 策略

`content.<version>.json` 表示从 latest 手动创建的不可变版本快照。

建议流程：

1. 读取当前 `content.latest.json`
2. 深拷贝 latest 中的节点快照内容
3. 生成新的整数版本号 `version`
4. 将顶层 `state` 从 `latest` 改为 `version`
5. 将顶层 `version` 写为新生成的整数版本号
6. 如有需要，写入用户提供的 `label`
7. 以 6 位零填充版本号生成文件名 `content.<version>.json`
8. 写入对象存储中的目标版本文件
9. 插入一条 `content_versions` 元数据记录
10. 更新 `Content.latest_version` 缓存字段

说明：

- 进入 version 的节点天然应保持 `committed`
- version 文件本身严格不可变
- version 文件应保留完整节点内容，而不是只存引用
- 版本查询、版本列表、标签读取都应优先走 `content_versions`
- version 文件是从 latest 快照派生并重写头部字段得到，不是字节级复制

## 5. 节点更新策略

### 文本节点

- 若节点是 `draft_only`，允许直接更新 `Node.text_content`
- 若节点是 `committed`，必须新建 Node，并让新节点的 `prev_node_id` 指向旧节点
- committed 节点 copy-on-write 后，新节点应复用旧 `uuid`，并令 `version = old.version + 1`
- draft 编排改为引用新节点的 `Node.id` 后，重新生成 `content.draft.json`

### 文件节点

- 若节点是 `draft_only`，允许更新 `FileMetadata`
- 若节点是 `committed`，必须新建 `Node(kind=file)` 和对应 `FileMetadata`
- committed file 节点 copy-on-write 后，新节点应复用旧 `uuid`，并令 `version = old.version + 1`
- draft 编排改为引用新节点的 `Node.id` 后，重新生成 `content.draft.json`

## 6. 回滚策略

回滚建议基于 `content.<version>.json`：

1. 读取目标版本文件
2. 依次处理快照中的每个节点项
3. 优先按 `nodeId` 查找数据库节点
4. 若 `nodeId` 不可用，则按 `uuid + version` 查找数据库节点
5. 若数据库中不存在该节点，则按快照内容补建一个 `Node`
6. 生成新的 `content.draft.json`，其中仅保存恢复后的 `Node.id` 顺序引用

注意：

- 回滚不是“把 version 文件原样复制成 draft 文件”
- 回滚的结果是“重建出一个 ref-only draft”
- 如果回滚过程中补建了节点，这些节点应标记为 `committed`
- rollback 默认不覆盖 `content.latest.json`
- 如需让回滚结果成为新的 latest，应显式再次执行 commit

推荐规则：

- 回滚恢复的是 draft 编排
- draft 中引用到的 committed 节点仍保持 committed
- 若回滚后继续修改这些节点，仍然走 copy-on-write
- 若快照中的某个节点在数据库中已缺失，系统可按快照补建该节点，再让 draft 引用新建出的 `Node.id`

## 7. 一个重要取舍

这里必须明确：

- 数据库中的 `Node` 是当前态
- draft 是引用编排态
- latest/version 是完整快照态
- `content_versions` 是版本索引态
- 可编辑性不由“当前是否在 draft 中”决定，而由“是否已提交过”决定

因此如果版本回滚后要恢复“数据库当前态”，必须显式执行同步逻辑，不能默认假设两者天然一致。

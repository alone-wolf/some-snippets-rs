# 演进路线与待决策问题

## 1. 当前优先级

建议先完成以下闭环：

1. `Content` 表
2. `content_versions` 表
3. `Node` 表
4. `FileMetadata` 表
5. `Node.draft_only / committed` 生命周期
6. committed 节点 copy-on-write
7. `content.draft.json`
8. `content.latest.json`
9. `content.<version>.json`

## 2. 第二阶段

在基础模型稳定后，再考虑：

- 搜索与审计增强
- 更细粒度的版本回滚策略

## 3. 当前最重要的设计结论

- `Node` 是统一节点模型
- `Node.id` 与 `Node.uuid + version` 分别承担物理引用与逻辑版本坐标
- `FileMetadata` 是 file 节点的附属信息
- `Content` 只保存内容级 metadata
- `content_versions` 是版本元数据索引
- `content.draft.json` 保存 `Node.id` 引用编排
- `content.latest.json` / `content.<version>.json` 保存完整节点快照
- `draft_only` 节点可直接修改
- `committed` 节点后续修改必须 copy-on-write
- rollback 必须把 version 快照归一化为新的 draft 引用文件
- 数据库当前态与快照态需要显式同步逻辑

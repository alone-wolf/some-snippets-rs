# 权限与策略设计

## 1. 设计目标

权限设计需要解决：

- 谁可以访问某个 Content 及其节点
- 谁可以创建、编辑、删除 Node
- 谁可以维护 draft、commit latest、create version、rollback

首版建议采用：

> Collection 级治理边界 + RBAC 为主

## 2. 建议权限动作

```text
collection:read
collection:update
collection:manage_members

content:read
content:create
content:update
content:delete
content:commit_latest
content:create_version
content:rollback

node:read
node:create
node:update
node:delete

file:read
file:upload
file:delete
```

## 3. 状态与权限联动

- `archived` content 默认不可编辑
- 编辑节点需要 `node:update`
- 提交 latest 需要 `content:commit_latest`
- 创建 version 需要 `content:create_version`
- 回滚需要 `content:rollback`
- 对于 `committed` 节点，`node:update` 的语义应解释为“创建替代节点并更新 draft”，而不是原地改旧节点

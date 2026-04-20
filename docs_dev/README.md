# 开发任务拆解

本目录将 `docs_design` 中已经确认的设计，拆解为可直接落地的开发任务。

任务拆解原则：

- 每个任务都应该能独立开工。
- 每个任务都给出明确输入、输出、依赖和验收标准。
- 默认技术栈为 `Rust + axum + SeaORM + Postgres/SQLite + 对象存储抽象`。
- 任务顺序按推荐实施顺序排列，前置任务完成后即可进入下一个任务。

## 当前实现主线

建议按以下顺序推进：

1. `T01` 初始化工程骨架
2. `T02` 基础配置、错误模型与公共能力
3. `T03` 数据库 migration: `collections / contents / content_versions`
4. `T04` 数据库 migration: `nodes / file_metadata`
5. `T05` 对象存储与快照命名抽象
6. `T06` Node 与 FileMetadata 的仓储/服务层
7. `T07` Draft 快照编排服务
8. `T08` Commit latest 流程
9. `T09` Create version 流程
10. `T10` Rollback 流程
11. `T11` REST API 与 DTO
12. `T12` 权限校验与审计接入
13. `T13` 集成测试与样例夹具

## `web-admin` 前端实现主线

建议在后端核心链路稳定后，按以下顺序推进：

14. `T14` 初始化 `web-admin` 工程骨架
15. `T15` `axum` 静态托管与开发代理支持
16. `T16` `web-admin` App Shell、路由与 API 基础层
17. `T17` Collection / Content 管理页面
18. `T18` 内容编辑工作台
19. `T19` 版本管理页面
20. `T20` 前端测试、构建与交付约束

## 设计输入

主要参考以下设计文档：

- `docs_design/01-domain-model.md`
- `docs_design/03-versioning-and-publishing.md`
- `docs_design/04-storage-and-data-layout.md`
- `docs_design/05-api-design.md`
- `docs_design/06-service-architecture-axum.md`
- `docs_design/07-database-schema.md`
- `docs_design/09-content-json-schema.md`
- `docs_design/10-web-frontend-and-hosting.md`

## 建议代码布局

建议首版按以下模块组织：

```text
src/
  app/
  config/
  error/
  modules/
    collection/
    content/
    node/
    file/
    auth/
  storage/
    db/
    object_store/
    snapshot/
  web/
    dto/
    handlers/
    middleware/
web-admin/
  src/
  public/
  tests/
tests/
```

## 输出要求

每个 task 完成后，建议至少补充：

- 相关代码
- 对应 migration 或 schema
- 最小可运行测试
- 必要的开发文档或注释

# T11 REST API 与 DTO

## 状态

- 已完成（2026-03-29）

## 目标

将已经实现的核心服务暴露为 API，并确保 DTO、错误码和 JSON 结构与设计文档一致。

## 输入

- `docs_design/05-api-design.md`
- `docs_design/09-content-json-schema.md`

## 前置依赖

- `T07`
- `T08`
- `T09`
- `T10`

## 具体工作

1. 实现内容接口：
   - `POST /collections/{collection_id}/contents`
   - `GET /contents/{content_id}`
   - `PATCH /contents/{content_id}`
2. 实现节点接口：
   - `POST /contents/{content_id}/nodes`
   - `PATCH /nodes/{node_id}`
   - `GET /nodes/{node_id}`
   - `GET /node-lineages/{uuid}/versions/{version}`
3. 实现内容流程接口：
   - `POST /contents/{content_id}/commit`
   - `POST /contents/{content_id}/versions`
   - `POST /contents/{content_id}/rollback`
4. 实现快照查询接口：
   - `GET /draft/contents/{content_id}`
   - `GET /latest/contents/{content_id}`
   - `GET /contents/{content_id}/versions`
   - `GET /versions/contents/{content_id}/{version}`
5. 为所有请求和响应定义 DTO。

## 建议产物

- `src/web/handlers/content.rs`
- `src/web/handlers/node.rs`
- `src/web/dto/content.rs`
- `src/web/dto/node.rs`
- `src/web/router.rs`

## 验收标准

1. 核心路由全部可访问。
2. 请求参数中的 `version` 一律是纯整数。
3. 返回结构与设计文档保持一致。

## 不在本任务内

- 权限细节
- 复杂搜索能力

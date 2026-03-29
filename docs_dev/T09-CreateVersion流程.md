# T09 Create version 流程

## 状态

- 已完成（2026-03-29）

## 目标

实现从 `content.latest.json` 派生 `content.<version>.json` 的版本创建流程，并写入 `content_versions` 索引。

## 输入

- `docs_design/03-versioning-and-publishing.md`
- `docs_design/05-api-design.md`
- `docs_design/09-content-json-schema.md`

## 前置依赖

- `T05`
- `T08`

## 具体工作

1. 读取当前 `content.latest.json`。
2. 生成新的整数版本号：
   - 基于 `contents.latest_version + 1`
   - 或基于 `content_versions` 的最大值
3. 深拷贝 latest 快照。
4. 重写快照头部：
   - `state = version`
   - `version = new_version`
   - `label = user_input_label`
5. 写入 `content.00000x.json`。
6. 计算 checksum。
7. 插入 `content_versions`。
8. 更新 `contents.latest_version`。

## 建议产物

- `src/storage/snapshot/version.rs`
- `src/modules/content/version_service.rs`

## 验收标准

1. 生成的 version 文件满足 JSON schema。
2. `version` 为纯整数，文件名为 6 位零填充数字。
3. `content_versions` 与对象存储中的 version 文件保持一致。

## 不在本任务内

- 回滚流程
- 权限系统

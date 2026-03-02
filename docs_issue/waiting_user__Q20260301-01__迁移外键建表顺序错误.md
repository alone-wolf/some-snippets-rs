# 问题 ID
Q20260301-01

# 当前状态
waiting_user

# 最后更新时间
2026-03-01 21:47 +08:00

# 问题标题
迁移脚本在创建 `snippets` 表时引用了尚未创建的 `histories` 表外键

# 问题摘要
迁移外键建表顺序错误

# 问题描述
当前迁移脚本在 `m20260215_000001_create_tables.rs` 中先创建 `snippets` 表，并在该表定义 `current_history_id -> histories.id` 外键；但 `histories` 表在后续步骤才创建。该顺序在 SQLite 下可能未立即报错，但在 PostgreSQL/MySQL 等严格校验外键目标表存在性的数据库中会导致迁移执行失败。

# 严重程度
High

# 影响对象
- `migration` crate 的初始化流程
- 使用 `DATABASE_URL` 指向非 SQLite 数据库的部署环境
- 首次建库或 CI 冷启动迁移任务

# 问题原因
迁移脚本按业务逻辑顺序创建表时，未同时满足外键依赖拓扑顺序，导致 `snippets.current_history_id` 的被引用表 `histories` 在定义时尚不存在。

# 核心证据路径
`migration/src/m20260215_000001_create_tables.rs`

# 待确认差异
无（`docs_issue/` 当前无历史问题文件）

# 造成问题的证据
- 代码路径：`migration/src/m20260215_000001_create_tables.rs`（`Snippets` 建表中定义 `fk_snippets_current_history_id`，而 `Histories` 建表在后续）
- 日志/报错：在严格外键校验数据库中预期出现“referenced table does not exist”类错误
- 配置位置：`DATABASE_URL` 可切换到 PostgreSQL/MySQL（README 与脚本均支持非 SQLite）
- 复现步骤：
  1. 使用空数据库并设置 `DATABASE_URL` 为 PostgreSQL/MySQL。
  2. 执行 `cargo run -p migration -- -u "$DATABASE_URL" up`。
  3. 迁移在创建 `snippets` 表阶段失败，报外键引用目标表不存在。

# 影响
会阻断非 SQLite 环境的建库与发布流程，导致 CI/CD 或新环境初始化失败；同时引入数据库方言相关行为差异，增加迁移可维护成本与交付风险。

# 建议解决方案
1. 调整建表顺序，确保被引用表先于引用表创建（例如先建 `histories`，再为 `snippets` 增加 `current_history_id` 外键）。
2. 或拆分为两步：先创建 `snippets`（不含该外键）与 `histories`，再通过后续迁移 `alter table` 补充外键约束。
3. 在迁移验证中补充至少一种严格外键校验数据库的执行检查，避免同类问题回归。

# 验收标准
1. 在空 PostgreSQL/MySQL 数据库执行 `cargo run -p migration -- -u "$DATABASE_URL" up` 可一次性成功完成，无外键目标表不存在错误。
2. `snippets.current_history_id` 到 `histories.id` 的外键约束在迁移完成后存在且生效（可通过 `information_schema` 或等效 SQL 检查）。
3. SQLite 场景迁移行为不回退：`cargo run -p migration -- -u sqlite://snippets.db?mode=rwc up` 仍可成功执行。

# 验证记录
- 标准 1 -> 验证动作：待修复后执行迁移命令（PostgreSQL/MySQL） | 结果：N/A | 证据/原因：当前为问题登记阶段，尚未进入修复与验证。
- 标准 2 -> 验证动作：待修复后执行外键元数据查询 | 结果：N/A | 证据/原因：当前为问题登记阶段，尚未进入修复与验证。
- 标准 3 -> 验证动作：待修复后执行 SQLite 迁移命令 | 结果：N/A | 证据/原因：当前为问题登记阶段，尚未进入修复与验证。

# 评论
（由用户填写：同意修复 / 修改方案 / 暂不处理 / 拒绝）

# 状态变更记录
- 时间：2026-03-01 21:47 +08:00 | 状态：waiting_user | 原因：新建问题并等待用户确认 | 操作者：codex | 关联提交：N/A
- 时间：YYYY-MM-DD HH:MM +00:00 | 状态： | 原因： | 操作者： | 关联提交：
- 时间：YYYY-MM-DD HH:MM +00:00 | 状态： | 原因： | 操作者： | 关联提交：

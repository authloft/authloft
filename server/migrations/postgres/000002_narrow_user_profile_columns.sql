-- user 表资料列宽收窄（接口文档 §3.2 / §5.4、后端架构 §4.2）：nickname
-- 上限 12 字、avatar_url 上限 120 字符——VARCHAR 宽度即字符数，与 mysql
-- 方言及服务层 utf8.RuneCountInString 同口径；服务层写入入口同步按该上限
-- 做字段级校验，超宽在写库前拒绝，不落到 DB 层报错。
-- user_thirdparty_bind 的同名列为渠道原始资料快照，不属用户资料列宽约束
--（后端架构 §4.3），保持原宽度不变。
-- PG 口径：列属性（NOT NULL / DEFAULT）独立于类型，改列宽只需 ALTER
-- COLUMN TYPE，既有默认值与非空约束随列保留。PG DDL 具事务性，失败的
-- 迁移整体回滚（§3.16 失败与恢复）。

-- +goose Up

ALTER TABLE "user"
  ALTER COLUMN nickname   TYPE VARCHAR(12),
  ALTER COLUMN avatar_url TYPE VARCHAR(120);

-- +goose Down

ALTER TABLE "user"
  ALTER COLUMN nickname   TYPE VARCHAR(128),
  ALTER COLUMN avatar_url TYPE VARCHAR(512);

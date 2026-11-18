-- user 表资料列宽收窄（接口文档 §3.2 / §5.4、后端架构 §4.2）：nickname
-- 上限 12 字、avatar_url 上限 120 字符——VARCHAR 宽度即字符数，与 utf8mb4
-- 及服务层 utf8.RuneCountInString 同口径；服务层写入入口同步按该上限做
-- 字段级校验，超宽在写库前拒绝，不落到 DB 层报错。
-- user_thirdparty_bind 的同名列为渠道原始资料快照，不属用户资料列宽约束
--（后端架构 §4.3），保持原宽度不变。
-- MariaDB DDL 非事务：两列合并于单条 ALTER，避免半成品态（§3.16 失败与
-- 恢复——失败不记版本、修复后重跑即重试同版本）。

-- +goose Up

ALTER TABLE `user`
  MODIFY COLUMN `nickname`   VARCHAR(12)  NOT NULL DEFAULT '',
  MODIFY COLUMN `avatar_url` VARCHAR(120) NOT NULL DEFAULT '';

-- +goose Down

ALTER TABLE `user`
  MODIFY COLUMN `nickname`   VARCHAR(128) NOT NULL DEFAULT '',
  MODIFY COLUMN `avatar_url` VARCHAR(512) NOT NULL DEFAULT '';

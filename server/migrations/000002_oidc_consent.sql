-- 授权记录迁移（§4.5）：①建 oidc_consent 表（同意页落库，用户对客户端的
-- 长期授权口径，与 oidc_refresh_token.scopes 单次令牌快照互不替代）；
-- ②存量 oidc_client.scopes 补齐 openid（openid 全链路强制的前置，接口
-- 文档 §5.5）。同一文件两件事均幂等（§3.16 goose 可重入约定：MariaDB
-- DDL 非事务，失败不记版本、重跑重试同版本，防半成品残留）。

-- +goose Up

CREATE TABLE IF NOT EXISTS oidc_consent (
  id         BIGINT PRIMARY KEY AUTO_INCREMENT,
  user_id    BIGINT      NOT NULL COMMENT '引用 user.id',
  client_id  VARCHAR(64) NOT NULL COMMENT 'oidc_client.client_id',
  scopes     VARCHAR(512) NOT NULL DEFAULT '' COMMENT '已授权 scope 并集，空格分隔',
  created_at DATETIME    NOT NULL,
  updated_at DATETIME    NOT NULL,
  UNIQUE KEY uk_user_client (user_id, client_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 存量客户端补齐 openid（§4.5）：FIND_IN_SET 判重、WHERE 限定未含者，
-- 重复执行不重复补；oidc_client.scopes 逗号分隔口径不变。
UPDATE oidc_client
SET scopes = CONCAT(scopes, ',openid')
WHERE FIND_IN_SET('openid', scopes) = 0;

-- +goose Down

-- 回退一版（§3.16：down 按工具标准提供，日常升级不使用）。仅删表；
-- openid 补齐不做回退——无从区分哪些客户端原本缺 openid，删补齐值会伤
-- 存量数据，down 不承担数据回退。
DROP TABLE IF EXISTS oidc_consent;

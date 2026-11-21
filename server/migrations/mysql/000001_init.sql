-- 首版迁移：后端架构 §4 全部 13 张表（§3.16，含 oidc_consent 授权记录表
-- 与存量 oidc_client.scopes 补齐 openid）。
-- 单文件注解格式（Up / Down 两段）：goose v3 Provider 将每个 .sql 文件
-- 视为一条迁移，不支持 .up.sql/.down.sql 成对命名（成对文件同版本会报
-- duplicate migration version）。
-- CREATE TABLE 使用 IF NOT EXISTS 保持可重入：MariaDB DDL 非事务，失败的
-- 迁移不记版本、可能残留半成品表，重跑 migrate up 即重试同版本
-- （§3.16 失败与恢复）——已存在的表跳过，缺的补齐。
-- 种子数据边界（§3.16）：迁移只管结构，不含 INSERT；默认 settings 由启动
-- 预热补齐（§4.7），管理员 ID=1 由 setup 代码插入（§3.15）。

-- +goose Up

CREATE TABLE IF NOT EXISTS provider (
  id             BIGINT       PRIMARY KEY AUTO_INCREMENT,
  provider_key   VARCHAR(64)  NOT NULL COMMENT '全局唯一标识，逻辑引用使用',
  union_provider VARCHAR(64)  NOT NULL COMMENT 'Union ID 归属 Provider',
  display_name   VARCHAR(128) NOT NULL COMMENT '展示名，如“QQ”“阿里云短信”',
  category       VARCHAR(32)  NOT NULL COMMENT 'auth|captcha|sms|email|storage|notify|union',
  type           VARCHAR(64)  NOT NULL COMMENT 'qq|wechat_mp|turnstile|aliyun_sms|s3|local|...',

  enable_signin  TINYINT(1)   NOT NULL DEFAULT 1 COMMENT '允许用于登录',
  enable_signup  TINYINT(1)   NOT NULL DEFAULT 1 COMMENT '允许该渠道建号',
  auto_bind      TINYINT(1)   NOT NULL DEFAULT 0 COMMENT '按邮箱/手机号自动绑定已有账号',
  auto_bind_fields VARCHAR(128) NOT NULL DEFAULT 'email,phone',
  is_enabled     TINYINT(1)   NOT NULL DEFAULT 1,

  ui_group       VARCHAR(32)  NOT NULL DEFAULT 'social' COMMENT 'social|enterprise|dev|other',
  sort_order     INT          NOT NULL DEFAULT 0,
  icon_url       VARCHAR(512) NOT NULL DEFAULT '',

  ext            MEDIUMBLOB   COMMENT 'provider.Ext 序列化后（Protobuf）',

  remark         VARCHAR(512) NOT NULL DEFAULT '',
  created_at     DATETIME     NOT NULL,
  updated_at     DATETIME     NOT NULL,
  UNIQUE KEY uk_provider_key (provider_key),
  KEY idx_category_enabled (category, is_enabled),
  KEY idx_type (type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS user (
  id             BIGINT PRIMARY KEY AUTO_INCREMENT,
  username       VARCHAR(64)  NOT NULL COMMENT '用户名必选，设置后不可改',
  phone          VARCHAR(32)  DEFAULT NULL,
  email          VARCHAR(128) DEFAULT NULL,
  phone_verified TINYINT(1)   NOT NULL DEFAULT 0,
  email_verified TINYINT(1)   NOT NULL DEFAULT 0,
  nickname       VARCHAR(12) NOT NULL DEFAULT '',
  avatar_url     VARCHAR(120) NOT NULL DEFAULT '',
  user_status    TINYINT      NOT NULL DEFAULT 1 COMMENT '1正常 0禁用',
  mfa_required   TINYINT(1)   NOT NULL DEFAULT 0 COMMENT '用户自助两步验证开关；1开启 0关闭',
  epoch          SMALLINT     NOT NULL DEFAULT 0 COMMENT '安全版本号，改密/重置/管理员禁用时递增',
  last_login_at  DATETIME,
  created_at     DATETIME     NOT NULL,
  updated_at     DATETIME     NOT NULL,
  UNIQUE KEY uk_username (username),
  UNIQUE KEY uk_phone (phone),
  UNIQUE KEY uk_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS user_profile (
  user_id    BIGINT PRIMARY KEY,
  gender     TINYINT      DEFAULT 0,
  birthday   DATE,
  locale     VARCHAR(16)  DEFAULT '',
  timezone   VARCHAR(64)  DEFAULT '',
  extra      VARBINARY(2048) COMMENT 'msgpack 序列化的扩展资料',
  updated_at DATETIME NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 统一凭证表：一行一种凭证，新增凭证类型不加列
CREATE TABLE IF NOT EXISTS user_credential (
  id            BIGINT PRIMARY KEY AUTO_INCREMENT,
  user_id       BIGINT       NOT NULL,
  kind          VARCHAR(32)  NOT NULL COMMENT 'password|totp|webauthn|recovery_code',
  secret        VARBINARY(1024) NOT NULL COMMENT 'password=argon2id 串；totp=Base32 明文密钥',
  label         VARCHAR(128) NOT NULL DEFAULT '' COMMENT '用户自定义名称，如“MacBook Touch ID”',
  meta          VARBINARY(2048) COMMENT 'credential.Meta 的 Protobuf 序列化',
  is_enabled    TINYINT(1)   NOT NULL DEFAULT 1,
  last_used_at  DATETIME,
  created_at    DATETIME     NOT NULL,
  updated_at    DATETIME     NOT NULL,
  KEY idx_user_kind (user_id, kind)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- WebAuthn 额外有一个凭据表
CREATE TABLE IF NOT EXISTS user_credential_webauthn (
  id            BIGINT PRIMARY KEY COMMENT '主键，与 user_credential.id 保持一致',
  user_id       BIGINT       NOT NULL,
  kind          VARCHAR(32)  NOT NULL DEFAULT 'webauthn',
  public_key    VARBINARY(2048) COMMENT 'webauthn 公钥（COSE）',
  credential_id VARCHAR(512) NOT NULL DEFAULT '' COMMENT 'webauthn 凭据 ID（base64url）',
  sign_count    BIGINT       NOT NULL DEFAULT 0 COMMENT 'webauthn 签名计数，防克隆',
  UNIQUE KEY uk_kind_credid (kind, credential_id),
  KEY idx_user_kind (user_id, kind)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Union 归并不设独立列 / 独立索引：由额外一行 Union Provider（category=union）
-- 绑定记录承担，该行 open_id 即 unionid 值（§4.3 / §12.7）。
CREATE TABLE IF NOT EXISTS user_thirdparty_bind (
  id         BIGINT PRIMARY KEY AUTO_INCREMENT,
  user_id    BIGINT       NOT NULL,
  provider_key VARCHAR(64) NOT NULL COMMENT '引用 provider.provider_key，不存渠道类型',
  open_id    VARCHAR(128) NOT NULL,
  nickname   VARCHAR(128) NOT NULL DEFAULT '',
  avatar_url VARCHAR(512) NOT NULL DEFAULT '',
  extra      MEDIUMBLOB   COMMENT 'msgpack 序列化的第三方原始资料（仅排查用）',
  created_at DATETIME     NOT NULL,
  UNIQUE KEY uk_provider_openid (provider_key, open_id),
  KEY idx_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS sso_client (
  id            BIGINT PRIMARY KEY AUTO_INCREMENT,
  client_id     VARCHAR(64)  NOT NULL,
  client_secret CHAR(64) NOT NULL,
  name          VARCHAR(128) NOT NULL DEFAULT '',
  redirect_uris VARBINARY(2048) NOT NULL COMMENT 'client.RedirectUris 的 Protobuf 序列化',
  login_methods VARBINARY(1024) NOT NULL COMMENT 'client.ClientLoginMethods 的 Protobuf 序列化；空 = 跟随全局',
  auth_providers VARBINARY(1024) NOT NULL COMMENT 'client.ClientAuthProviders 的 Protobuf 序列化；空 = 跟随全局',
  default_redirect_uri VARCHAR(1024) NOT NULL DEFAULT '' COMMENT '登录完成默认回跳地址；空 = 未配置',
  template_key  VARCHAR(64)  NOT NULL DEFAULT '' COMMENT '绑定的自定义模板 key',
  template_vars TEXT         COMMENT '模板变量 JSON',
  is_enabled    TINYINT(1) NOT NULL DEFAULT 1,
  created_at    DATETIME NOT NULL,
  updated_at    DATETIME NOT NULL,
  UNIQUE KEY uk_client_id (client_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS oidc_client (
  id            BIGINT PRIMARY KEY AUTO_INCREMENT,
  client_id     VARCHAR(64)  NOT NULL,
  client_secret CHAR(64) NOT NULL,
  name          VARCHAR(128) NOT NULL DEFAULT '',
  redirect_uris VARBINARY(2048) NOT NULL COMMENT 'client.RedirectUris 的 Protobuf 序列化',
  scopes        VARCHAR(512) NOT NULL DEFAULT 'openid,profile,email',
  access_token_ttl  INT NOT NULL DEFAULT 3600,
  refresh_token_ttl INT NOT NULL DEFAULT 2592000,
  template_key  VARCHAR(64)  NOT NULL DEFAULT '' COMMENT '绑定的自定义模板 key',
  template_vars TEXT         COMMENT '模板变量 JSON',
  is_enabled    TINYINT(1) NOT NULL DEFAULT 1,
  created_at    DATETIME NOT NULL,
  updated_at    DATETIME NOT NULL,
  UNIQUE KEY uk_client_id (client_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 自定义模板（§4.9）：DB 自定义模板，与常驻内存的内置模板双轨共存
-- （§3.13）；无版本号、无内置标记列，缓存失效靠写路径 DEL（§5.1）。
CREATE TABLE IF NOT EXISTS template (
  id           BIGINT       PRIMARY KEY AUTO_INCREMENT,
  template_key VARCHAR(64)  NOT NULL COMMENT '模板 key',
  name         VARCHAR(128) NOT NULL DEFAULT '',
  content      MEDIUMTEXT   NOT NULL COMMENT '模板 HTML 原文',
  created_at   DATETIME     NOT NULL,
  updated_at   DATETIME     NOT NULL,
  UNIQUE KEY uk_template_key (template_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 刷新令牌存库：需要可吊销、可列表、有效期长
CREATE TABLE IF NOT EXISTS oidc_refresh_token (
  id         BIGINT PRIMARY KEY AUTO_INCREMENT,
  token_hash CHAR(64)     NOT NULL COMMENT 'sha256(refresh_token)',
  client_id  VARCHAR(64)  NOT NULL,
  user_id    BIGINT       NOT NULL,
  session_id VARCHAR(64)  NOT NULL DEFAULT '',
  scopes     VARCHAR(512) NOT NULL DEFAULT '',
  revoked_at DATETIME,
  expires_at DATETIME NOT NULL,
  created_at DATETIME NOT NULL,
  UNIQUE KEY uk_token_hash (token_hash),
  KEY idx_user (user_id),
  KEY idx_session (session_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 事件日志（§4.6）：登录日志与审计日志合并表，RANGE 分区按 created_at 落区。
-- 分区键必须含于全部唯一索引，故主键复合化为 (id, created_at)（自增列居首，
-- 满足 AUTO_INCREMENT 的索引首列要求）；四个二级索引语义不变。实体分区由
-- 分区维护任务切分与淘汰，建表只建 pmax 兜底分区：任务延迟期间数据落入
-- 兜底，不失败、不丢。
CREATE TABLE IF NOT EXISTS event_log (
  id         BIGINT       NOT NULL AUTO_INCREMENT,
  event      VARCHAR(48)  NOT NULL COMMENT 'login_success|change_password|reset_password|bind_phone|bind_email|enable_mfa|disable_mfa|webauthn_register|webauthn_delete|thirdparty_bind|thirdparty_unbind|admin_disable_user|admin_reset_password|provider_create|provider_update|settings_update|...',
  actor_type VARCHAR(16)  NOT NULL COMMENT 'user|admin|system',
  actor_id   BIGINT       NOT NULL DEFAULT 0 COMMENT 'user=该用户 uid；admin=操作管理员 uid；system=0',
  user_id    BIGINT       NOT NULL DEFAULT 0 COMMENT '被操作对象；自身操作时与 actor_id 相同',
  client_id  VARCHAR(64)  NOT NULL DEFAULT '' COMMENT 'OIDC 客户端，登录类事件填充',
  amr        VARCHAR(128) NOT NULL DEFAULT '' COMMENT '登录类事件：通过的认证方法，如 pwd,otp,mfa',
  ip         VARCHAR(64)  NOT NULL DEFAULT '',
  ua         VARCHAR(512) NOT NULL DEFAULT '',
  target     VARCHAR(128) NOT NULL DEFAULT '' COMMENT '操作目标，如 provider_key',
  detail     VARBINARY(2048) COMMENT 'msgpack 序列化的附加信息',
  created_at DATETIME     NOT NULL,
  PRIMARY KEY (id, created_at),
  KEY idx_actor_time (actor_type, actor_id, created_at),
  KEY idx_user_time  (user_id, created_at),
  KEY idx_event_time (event, created_at),
  KEY idx_time (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
PARTITION BY RANGE (TO_DAYS(created_at))
(PARTITION pmax VALUES LESS THAN MAXVALUE);

CREATE TABLE IF NOT EXISTS settings (
  k          VARCHAR(64)  PRIMARY KEY COMMENT '键名',
  v          TEXT         NOT NULL COMMENT 'JSON 编码值',
  updated_at DATETIME     NOT NULL,
  updated_by BIGINT       NOT NULL DEFAULT 0 COMMENT '操作管理员 uid'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 用户权限点映射（§4.8）：行存在即持有，首版仅 superadmin（安装时授予）。
CREATE TABLE IF NOT EXISTS user_permission (
  user_id BIGINT      NOT NULL COMMENT '用户 ID，引用 user.id',
  point   VARCHAR(32) NOT NULL COMMENT '权限点标识',
  PRIMARY KEY (user_id, point)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 授权记录（§4.5）：用户对客户端的长期授权口径，与
-- oidc_refresh_token.scopes 的单次令牌快照互不替代。
CREATE TABLE IF NOT EXISTS oidc_consent (
  id         BIGINT PRIMARY KEY AUTO_INCREMENT,
  user_id    BIGINT      NOT NULL COMMENT '引用 user.id',
  client_id  VARCHAR(64) NOT NULL COMMENT 'oidc_client.client_id',
  scopes     VARCHAR(512) NOT NULL DEFAULT '' COMMENT '已授权 scope 并集，空格分隔',
  created_at DATETIME    NOT NULL,
  updated_at DATETIME    NOT NULL,
  UNIQUE KEY uk_user_client (user_id, client_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- +goose Down

-- 回退脚本（§3.16：down 按工具标准提供，日常升级不使用；数据备份责任
-- 归部署方，执行迁移前自行备份）。倒序删除 §4 全部 13 张表。
-- openid 补齐不做回退——无从区分哪些客户端原本缺 openid，删补齐值会伤
-- 存量数据；down 只负责删表。
DROP TABLE IF EXISTS oidc_consent;
DROP TABLE IF EXISTS user_permission;
DROP TABLE IF EXISTS settings;
DROP TABLE IF EXISTS event_log;
DROP TABLE IF EXISTS oidc_refresh_token;
DROP TABLE IF EXISTS template;
DROP TABLE IF EXISTS oidc_client;
DROP TABLE IF EXISTS sso_client;
DROP TABLE IF EXISTS user_thirdparty_bind;
DROP TABLE IF EXISTS user_credential_webauthn;
DROP TABLE IF EXISTS user_credential;
DROP TABLE IF EXISTS user_profile;
DROP TABLE IF EXISTS user;
DROP TABLE IF EXISTS provider;

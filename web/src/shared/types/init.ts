/**
 * window.__AUTHLOFT_INIT__ 的类型与读取函数（docs/前端架构.md §3.4 init.ts 行
 * 344；注入白名单见 docs/接口文档.md §8 唯一定义）。Go 渲染空壳 HTML 时注入；
 * 前端不得假设其中存在任何凭证（docs/前端架构.md §1.5 行 102：没有会话 ID、
 * 没有 login_token、没有 Provider 密钥）。
 *
 * 注入值是原始 JSON（protojson 口径：camelCase、省略零值、int64 十进制字符串，
 * 接口文档 §1.12），不经 connect-es 解码，故数值字段是 string 而非 gen 消息里的
 * bigint；captcha 结构无 int64 字段、三处同结构同字段名（§2.5 行 476），类型
 * 直接取 gen 的 api.common.v1.CaptchaConfig，不双份手写（前端架构 §3.1）。
 */
import type { CaptchaConfig } from '../../gen/proto/api/common/v1/captcha_pb';

/**
 * 渲染字段（§2.1 行 384-394；api.sso.v1.Field 的注入 JSON 形状，见 gen
 * envelope_pb.ts Field 注释）。type 取值是 §1.11 的封闭集合，跨版本可新增，
 * string 承载（§12.9 行 1754）。
 */
export interface SnapshotField {
  name: string;
  label?: string;
  type: string;
  required?: boolean;
  /** 输入长度（如验证码位数）；int64 → 十进制字符串（§1.12）。 */
  length?: string;
  /** 最大校验失败次数；int64 → 十进制字符串（§1.12）。 */
  maxAttempts?: string;
}

/**
 * thirdparty.providers 条目（§2.7.1 行 560-574；api.account.v1.ThirdpartyOption
 * 的注入 JSON 形状）。
 */
export interface SnapshotProvider {
  providerKey: string;
  displayName?: string;
  type: string;
  /** 交互通道：redirect | api | qrcode（§1.10 / §2.7.1 行 576）。 */
  channel: string;
  /** 空 / 省略 = 渲染通用占位图标（§2.7.1 行 578，不做本地文件回落）。 */
  icon?: string;
  /** int64 → 十进制字符串（§1.12）。 */
  sortOrder?: string;
}

/** __AUTHLOFT_INIT__.methods 的 methods[] 单个方式条目（§2.1 行 382-400）。 */
export interface LoginMethodEntry {
  method: string;
  /** primary / secondary（§2.1）。 */
  usage?: string[];
  /** 步骤序列，kind 取值见 §1.4（§2.1）。 */
  steps?: string[];
  /** form 步字段（api.sso.v1.Field 的注入 JSON 形状）。 */
  fields?: SnapshotField[];
  /** challenge 步字段（§2.1）。 */
  challengeFields?: SnapshotField[];
  /** 验证码位数；int64 → 十进制字符串（§1.12）。 */
  codeLength?: string;
  /** 同目标重发冷却（秒）；int64 → 十进制字符串（§1.12）。 */
  resendAfter?: string;
  /** 有效性（秒）；int64 → 十进制字符串（§1.12）。 */
  expiresIn?: string;
  /** 能力检测表达式（如 window.PublicKeyCredential；§3.2 useCapability 消费）。 */
  capability?: string;
  /** thirdparty 渠道列表（§2.7.1）。 */
  providers?: SnapshotProvider[];
}

/** __AUTHLOFT_INIT__.methods 的值（§2.1 行 370-402 注入结构）。 */
export interface MethodsSnapshot {
  /** 入口可见性，镜像 allow_password_reset / allow_registration（§5.6），按零值兜底。 */
  flags?: {
    passwordReset?: boolean;
    registration?: boolean;
  };
  /** 首屏 captcha 配置（§2.5 唯一定义；仅预判 type、预加载厂商脚本）。 */
  captcha?: CaptchaConfig;
  /** 登录方式列表（空数组 = 按开关隐藏入口，§2.1 行 407 / 412）。 */
  methods: LoginMethodEntry[];
}

/**
 * 形态 B 左栏账号摘要（§4.2 / §5.1 `oidc.account`）：昵称 / 头像 / 掩码标识
 * （手机号 / 邮箱二选一，均掩码；无则用户名）。后端注入 snake_case，前端不二次
 * 信任、不落任何凭证或明文。
 */
export interface OidcAccountContext {
  nickname: string;
  avatar_url: string;
  identifier: string;
}

/**
 * OIDC 渲染形态（§4.2 三态）：`login` 登录双栏、`consent` 同意双栏。形态 C
 * 免同意直跳由后端 302，不渲染本页、前端不感知。注入值可能为未知串，消费方
 * 按严格相等分派、落到默认分支。
 */
export type OidcMode = 'login' | 'consent';

/**
 * OIDC 授权上下文（§4.2 行 1081：七个原样参数；前端首次请求原样回传，不解析）。
 * 形态 A/B 另带 `mode`（渲染分派）、`client_name`（右栏应用名）；形态 B 再带
 * `account`（左栏账号摘要，形态 A 省略）。三者是注入的展示/分派字段，不进
 * `oidcToStruct` 的回传 Struct（服务端按注入重校，不接受前端扩权）。
 */
export interface OidcContext {
  client_id: string;
  redirect_uri: string;
  scope?: string;
  state?: string;
  nonce?: string;
  code_challenge?: string;
  code_challenge_method?: string;
  mode?: OidcMode;
  client_name?: string;
  account?: OidcAccountContext;
  /**
   * 形态 B 注入的已授权 scope 集（§8 / §4.2 形态 B）：该用户对该客户端的
   * 已授权并集，空格分隔、编码与 scope 一致，空集合法（空串）。UI 据此锁定
   * 已授权项不可取消（授权记录只扩不缩）。形态 A 无此键，消费方按
   * undefined 回退现状（仅 openid 恒锁）。属展示/锁定字段，不进
   * oidcToStruct 的回传白名单（防前端扩权，服务端按注入重校）。
   */
  granted_scopes?: string;
}

/**
 * SSO 应用上下文（接口文档 §2.1：client_id 命中 sso_client 行时
 * 注入；OIDC authorize 入口不注入）。clientId 供首签请求回传 ssoClientId
 * （§2.2 / §2.7.2 / §2.8）；name 仅供前端展示、不参与任何判定。
 */
export interface SsoContext {
  clientId: string;
  name?: string;
}

/**
 * __AUTHLOFT_INIT__.passwordPolicy（§2.1）：注册 / 重置 / 改密 / admin 重置
 * 四入口前端预校验与强度提示的三项参数，与 settings pwd_* 三键（§5.6）同源
 * 同值。长度 / 类数为计数类数值，按 §1.12 以十进制字符串下发；缺失 / 越界
 * 项由消费侧回落默认档（shared/utils/validate.ts 的 DEFAULT_PASSWORD_POLICY）。
 * 服务端校验为权威，前端仅体验层同值预判（password_weak 由响应 status 判定）。
 */
export interface PasswordPolicyInit {
  /** pwd_min_length（§5.6，默认 8）。 */
  minLength: string;
  /** pwd_max_length（§5.6，默认 64；服务端硬上限 64）。 */
  maxLength: string;
  /** pwd_require_classes（§5.6，默认 3；1–3）。 */
  requireClasses: string;
}

/**
 * 注入白名单（接口文档 §8 唯一定义）：al_root / static_base / passwordPolicy
 * （三端）、methods（login 必填，缺失即服务端故障）、oidc / sso（login 可选）。
 * 转义、no-store、CSP nonce 由后端保证（前端架构 §1.5 行 104），前端不做二次信任。
 */
export interface AuthloftInit {
  al_root: string;
  static_base: string;
  methods?: MethodsSnapshot;
  oidc?: OidcContext;
  sso?: SsoContext;
  passwordPolicy?: PasswordPolicyInit;
}

declare global {
  interface Window {
    __AUTHLOFT_INIT__?: AuthloftInit;
    __AUTHLOFT_SITE_NAME__?: string;
  }
}

export function getSiteName(): string {
  return window.__AUTHLOFT_SITE_NAME__ || 'Authloft';
}

/**
 * 读取注入变量（§8）。methods 缺失时渲染错误态并提示刷新属 login bootstrap
 * 的职责（前端架构 §1.5 行 98：无回退接口），本函数只负责读取；
 * 非浏览器环境返回 undefined。
 */
export function getInit(): AuthloftInit | undefined {
  if (typeof window === 'undefined') {
    return undefined;
  }
  return window.__AUTHLOFT_INIT__;
}

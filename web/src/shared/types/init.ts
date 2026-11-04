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
  readonly name: string;
  readonly label?: string;
  readonly type: string;
  readonly required?: boolean;
  /** 输入长度（如验证码位数）；int64 → 十进制字符串（§1.12）。 */
  readonly length?: string;
  /** 最大校验失败次数；int64 → 十进制字符串（§1.12）。 */
  readonly maxAttempts?: string;
}

/**
 * thirdparty.providers 条目（§2.7.1 行 560-574；api.account.v1.ThirdpartyOption
 * 的注入 JSON 形状）。
 */
export interface SnapshotProvider {
  readonly providerKey: string;
  readonly displayName?: string;
  readonly type: string;
  /** 交互通道：redirect | api | qrcode（§1.10 / §2.7.1 行 576）。 */
  readonly channel: string;
  /** 空 / 省略 = 渲染通用占位图标（§2.7.1 行 578，不做本地文件回落）。 */
  readonly icon?: string;
  readonly uiGroup?: string;
  /** int64 → 十进制字符串（§1.12）。 */
  readonly sortOrder?: string;
}

/** __AUTHLOFT_INIT__.methods 的 methods[] 单个方式条目（§2.1 行 382-400）。 */
export interface LoginMethodEntry {
  readonly method: string;
  /** primary / secondary（§2.1）。 */
  readonly usage?: string[];
  /** 步骤序列，kind 取值见 §1.4（§2.1）。 */
  readonly steps?: string[];
  /** form 步字段（api.sso.v1.Field 的注入 JSON 形状）。 */
  readonly fields?: SnapshotField[];
  /** challenge 步字段（§2.1）。 */
  readonly challengeFields?: SnapshotField[];
  /** 验证码位数；int64 → 十进制字符串（§1.12）。 */
  readonly codeLength?: string;
  /** 同目标重发冷却（秒）；int64 → 十进制字符串（§1.12）。 */
  readonly resendAfter?: string;
  /** 有效性（秒）；int64 → 十进制字符串（§1.12）。 */
  readonly expiresIn?: string;
  /** 能力检测表达式（如 window.PublicKeyCredential；§3.2 useCapability 消费）。 */
  readonly capability?: string;
  /** thirdparty 渠道列表（§2.7.1）。 */
  readonly providers?: SnapshotProvider[];
}

/** __AUTHLOFT_INIT__.methods 的值（§2.1 行 370-402 注入结构）。 */
export interface MethodsSnapshot {
  /** 入口可见性，镜像 allow_password_reset / allow_registration（§5.6），按零值兜底。 */
  readonly flags?: {
    readonly passwordReset?: boolean;
    readonly registration?: boolean;
  };
  /** 首屏 captcha 配置（§2.5 唯一定义；仅预判 type、预加载厂商脚本）。 */
  readonly captcha?: CaptchaConfig;
  /** 登录方式列表（空数组 = 按开关隐藏入口，§2.1 行 407 / 412）。 */
  readonly methods: LoginMethodEntry[];
}

/** OIDC 授权上下文（§4.2 行 1081：七个原样参数；前端首次请求原样回传，不解析）。 */
export interface OidcContext {
  readonly client_id: string;
  readonly redirect_uri: string;
  readonly scope?: string;
  readonly state?: string;
  readonly nonce?: string;
  readonly code_challenge?: string;
  readonly code_challenge_method?: string;
}

/**
 * 注入白名单（接口文档 §8 唯一定义）：al_root / static_base（三端）、
 * methods（login 必填，缺失即服务端故障）、oidc（login 可选）。
 * 转义、no-store、CSP nonce 由后端保证（前端架构 §1.5 行 104），前端不做二次信任。
 */
export interface AuthloftInit {
  readonly al_root: string;
  readonly static_base: string;
  readonly methods?: MethodsSnapshot;
  readonly oidc?: OidcContext;
}

declare global {
  interface Window {
    __AUTHLOFT_INIT__?: AuthloftInit;
  }
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

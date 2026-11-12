/**
 * 两层错误口径——「§1.6 词汇、两个位置」（docs/接口文档.md §1.6 行 267；docs/前端架构.md §3.1 errors.ts）：
 * ① 位置一（登录流程域，SsoService 登录流程方法，HTTP 200）：响应**顶层 `status`**，
 *    取值即 §1.6 封闭全量表（33 词，其中 `captcha_required` / `captcha_invalid`
 *    仅作 `ErrorInfo.code`、不作 `status`，故不进流程态表），含流程态
 *    （next / mfa_required / success / failed…）→ `{retryable, action, i18nKey}`，
 *    业务分支走 reducer，不经 transport 拦截；
 * ② 位置二（其余域）：非 200 Connect 错误体 details 的 **`ErrorInfo.code`**（§1.5 行 199-221）
 *    ——无 detail 时按 Connect 标准码（§1.5 行 184-193）兜底，统一拦截文案；
 *    captcha 失败所需配置从同一错误体 details 的 `api.common.v1.CaptchaConfig` 读取
 *    （§1.5 行 228、§2.5），不再依赖登录流程信封。
 * 未知 `status` / `code` 一律走兜底，不暴露内部信息；`ErrorInfo.message` /
 * `ConnectError.message` 只作展示兜底（§1.5 行 202：i18n 优先，其次本字段），不参与分支。
 */
import type { CaptchaConfig } from '../../gen/proto/api/common/v1/captcha_pb';

// ---------------------------------------------------------------------------
// ApiError：transport 错误归一的目标形态（http.ts 构造，docs/前端架构.md §3.1）
// ---------------------------------------------------------------------------

export interface ApiErrorInit {
  httpStatus: number;
  code: string;
  message: string;
  requestId: string;
  /** ErrorInfo.retry_after（§1.5 行 220）：冷却 / 封禁剩余秒数，驱动倒计时。 */
  retryAfter?: bigint;
  /** ErrorInfo.attempts_left（§1.5 行 221）：剩余尝试次数。 */
  attemptsLeft?: bigint;
  /** captcha 失败时错误体 details 并列的 `api.common.v1.CaptchaConfig`（§1.5 行 228、§2.5）。 */
  captcha?: CaptchaConfig;
}

/** 统一错误体：非 200 Connect 错误体（ErrorInfo detail 或标准码兜底）与传输层失败的归一形态（docs/接口文档.md §1.5）。 */
export class ApiError extends Error {
  httpStatus: number;

  code: string;

  requestId: string;

  /** 冷却 / 封禁剩余秒数（§1.5 行 220）；未携带或零值（protojson 省略零值，§1.1）为 undefined。 */
  retryAfter?: bigint;

  /** 剩余尝试次数（§1.5 行 221）；未携带或零值为 undefined。 */
  attemptsLeft?: bigint;

  /** captcha 失败时错误体 details 携带的权威配置（§1.5 行 228、§2.5）；其余错误为 undefined。 */
  captcha?: CaptchaConfig;

  constructor(init: ApiErrorInit) {
    super(init.message);
    this.name = 'ApiError';
    this.httpStatus = init.httpStatus;
    this.code = init.code;
    this.requestId = init.requestId;
    this.retryAfter =
      init.retryAfter !== undefined && init.retryAfter > BigInt(0)
        ? init.retryAfter
        : undefined;
    this.attemptsLeft =
      init.attemptsLeft !== undefined && init.attemptsLeft > BigInt(0)
        ? init.attemptsLeft
        : undefined;
    this.captcha = init.captcha;
  }
}

// ---------------------------------------------------------------------------
// 层①（位置一）：登录流程域顶层 status（HTTP 200，§1.3 信封；
// 取值即 §1.6 封闭全量表，docs/接口文档.md 行 230-261）
// ---------------------------------------------------------------------------

/** §1.6「前端动作」列归纳出的封闭集合；业务分支只认 status（docs/前端架构.md §9 第 9 条）。 */
export type StatusAction =
  /** next：按 next_step 继续渲染。 */
  | 'render_next_step'
  /** mfa_required：就地渲染 mfa.methods 选择器，不跳页。 */
  | 'render_mfa'
  /** binding_required：渲染绑定选择页（§2.7.5）。 */
  | 'render_binding'
  /** success：清空 login_token → 跳转同步 → redirect_to。 */
  | 'complete'
  /** pending / scanned：继续轮询，无动作。 */
  | 'continue_polling'
  /** expired：停止轮询，提示刷新二维码。 */
  | 'stop_polling'
  /** step / token / state 类失败：回到第一步。 */
  | 'restart'
  /** captcha_required：打开 captcha 弹窗（配置取错误体 details 的 CaptchaConfig），确认后重提。 */
  | 'require_captcha'
  /** captcha_invalid：弹窗不关，按错误体 details 的 CaptchaConfig 换新凭据后重提。 */
  | 'reset_captcha'
  /** too_many_requests / locked：倒计时（retry_after）/ 展示剩余时长。 */
  | 'countdown'
  /** 字段级提示。 */
  | 'field_error'
  /** method_disabled / provider_disabled：刷新方式列表。 */
  | 'refresh_methods'
  /** 普通提示：i18n 优先，信封 error.message 作兜底展示（§1.6 行 239 / 行 271）。 */
  | 'message';

/** 层①解析结果。 */
export interface StatusResolution {
  /** §1.6「可重试」列；流程态（next / success / pending 等）恒为 false。 */
  retryable: boolean;
  /** §1.6「前端动作」列的归纳。 */
  action: StatusAction;
  /** i18n 键，口径 `errors.status.<status>`；文案由 shared/i18n 字典（后续实现）落。 */
  i18nKey: string;
}

/**
 * §1.6 封闭全量表（docs/接口文档.md 行 230-261）词汇全集（33 词）——登录流程域
 * 顶层 `status` 与其余域 `ErrorInfo.code` 共用同一套词汇（§1.6 行 286）。
 * `captcha_required` / `captcha_invalid` 仅作 `ErrorInfo.code`、不作 `status`
 * （§1.6 行 286），故不在下方流程态表内。
 */
export type FlowStatusKey =
  | 'next'
  | 'mfa_required'
  | 'binding_required'
  | 'success'
  | 'pending'
  | 'scanned'
  | 'expired'
  | 'failed'
  | 'captcha_required'
  | 'captcha_invalid'
  | 'too_many_requests'
  | 'too_many_attempts'
  | 'locked'
  | 'invalid_request'
  | 'invalid_credentials'
  | 'invalid_code'
  | 'code_expired'
  | 'method_disabled'
  | 'step_invalid'
  | 'token_invalid'
  | 'token_expired'
  | 'state_mismatch'
  | 'user_disabled'
  | 'user_not_found'
  | 'password_weak'
  | 'username_taken'
  | 'target_taken'
  | 'signup_disabled'
  | 'reset_disabled'
  | 'provider_disabled'
  | 'file_too_large'
  | 'file_type_not_allowed'
  | 'internal_error';

/**
 * 真正的流程态（位置一）：§1.6 词汇去掉仅作 `ErrorInfo.code` 的
 * `captcha_required` / `captcha_invalid`（§1.6 行 286「四个码都不是 status」）。
 */
export type FlowStatus = Exclude<
  FlowStatusKey,
  'captcha_required' | 'captcha_invalid'
>;

/** 流程态表类型别名（保持声明行简短，避免格式化把整张表整体重排）。 */
type FlowStatusTable = Readonly<Record<FlowStatus, StatusResolution>>;

/**
 * 流程态表（位置一）：登录流程域顶层 status（§1.6 全表去掉两个 code-only 词）
 * → 处置口径（表驱动，逐项对照 docs/接口文档.md 行 230-261）。`failed` 的
 * 「可重试」文档标注「视 error」，需调用方结合信封 error 内容判断，表取保守值 false。
 */
export const FLOW_STATUS_TABLE: FlowStatusTable = {
  next: {
    retryable: false,
    action: 'render_next_step',
    i18nKey: 'errors.status.next',
  },
  mfa_required: {
    retryable: false,
    action: 'render_mfa',
    i18nKey: 'errors.status.mfa_required',
  },
  binding_required: {
    retryable: false,
    action: 'render_binding',
    i18nKey: 'errors.status.binding_required',
  },
  success: {
    retryable: false,
    action: 'complete',
    i18nKey: 'errors.status.success',
  },
  pending: {
    retryable: false,
    action: 'continue_polling',
    i18nKey: 'errors.status.pending',
  },
  scanned: {
    retryable: false,
    action: 'continue_polling',
    i18nKey: 'errors.status.scanned',
  },
  expired: {
    retryable: false,
    action: 'stop_polling',
    i18nKey: 'errors.status.expired',
  },
  failed: {
    retryable: false,
    action: 'message',
    i18nKey: 'errors.status.failed',
  },
  too_many_requests: {
    retryable: false,
    action: 'countdown',
    i18nKey: 'errors.status.too_many_requests',
  },
  too_many_attempts: {
    retryable: false,
    action: 'message',
    i18nKey: 'errors.status.too_many_attempts',
  },
  locked: {
    retryable: false,
    action: 'countdown',
    i18nKey: 'errors.status.locked',
  },
  invalid_request: {
    retryable: false,
    action: 'field_error',
    i18nKey: 'errors.status.invalid_request',
  },
  invalid_credentials: {
    retryable: true,
    action: 'message',
    i18nKey: 'errors.status.invalid_credentials',
  },
  invalid_code: {
    retryable: true,
    action: 'message',
    i18nKey: 'errors.status.invalid_code',
  },
  code_expired: {
    retryable: false,
    action: 'message',
    i18nKey: 'errors.status.code_expired',
  },
  method_disabled: {
    retryable: false,
    action: 'refresh_methods',
    i18nKey: 'errors.status.method_disabled',
  },
  step_invalid: {
    retryable: false,
    action: 'restart',
    i18nKey: 'errors.status.step_invalid',
  },
  token_invalid: {
    retryable: false,
    action: 'restart',
    i18nKey: 'errors.status.token_invalid',
  },
  token_expired: {
    retryable: false,
    action: 'restart',
    i18nKey: 'errors.status.token_expired',
  },
  state_mismatch: {
    retryable: false,
    action: 'restart',
    i18nKey: 'errors.status.state_mismatch',
  },
  user_disabled: {
    retryable: false,
    action: 'message',
    i18nKey: 'errors.status.user_disabled',
  },
  user_not_found: {
    retryable: true,
    action: 'message',
    i18nKey: 'errors.status.user_not_found',
  },
  password_weak: {
    retryable: true,
    action: 'field_error',
    i18nKey: 'errors.status.password_weak',
  },
  username_taken: {
    retryable: true,
    action: 'field_error',
    i18nKey: 'errors.status.username_taken',
  },
  target_taken: {
    retryable: true,
    action: 'field_error',
    i18nKey: 'errors.status.target_taken',
  },
  signup_disabled: {
    retryable: false,
    action: 'message',
    i18nKey: 'errors.status.signup_disabled',
  },
  reset_disabled: {
    retryable: false,
    action: 'message',
    i18nKey: 'errors.status.reset_disabled',
  },
  provider_disabled: {
    retryable: false,
    action: 'refresh_methods',
    i18nKey: 'errors.status.provider_disabled',
  },
  file_too_large: {
    retryable: true,
    action: 'message',
    i18nKey: 'errors.status.file_too_large',
  },
  file_type_not_allowed: {
    retryable: true,
    action: 'message',
    i18nKey: 'errors.status.file_type_not_allowed',
  },
  internal_error: {
    retryable: true,
    action: 'message',
    i18nKey: 'errors.status.internal_error',
  },
};

/** 未知流程态的兜底口径：不暴露内部信息（§1.6 行 272）。 */
const FLOW_STATUS_FALLBACK: StatusResolution = {
  retryable: false,
  action: 'message',
  i18nKey: 'errors.status.unknown',
};

/** 解析登录流程域顶层 status（§1.3 信封，位置一）；未知值走兜底，不透出原文。 */
export function resolveFlowStatus(status: string): StatusResolution {
  return (
    (FLOW_STATUS_TABLE as Readonly<Record<string, StatusResolution>>)[status] ??
    FLOW_STATUS_FALLBACK
  );
}

// ---------------------------------------------------------------------------
// status → 字段名映射（评审 P1-2：field_error 语义的字段落点）
// ---------------------------------------------------------------------------

/**
 * field_error 类 status → 后端下发 fields[].name（纯前端表；字段名与登录流程
 * 因子下发的字段名同源，见 server factor 层下发：username / password / code /
 * target）。命中后调用方把文案同时 / 改落到字段下方错误槽（FieldRenderer
 * errors prop）并标 aria-invalid；未命中（如 invalid_request 无确定字段）仍走
 * 底部 banner。invalid_credentials 系「用户名或密码错误」合并口径，锚定密码字段。
 */
export const STATUS_FIELD_MAP: Readonly<
  Partial<Record<FlowStatusKey, string>>
> = {
  invalid_credentials: 'password',
  invalid_code: 'code',
  code_expired: 'code',
  password_weak: 'password',
  username_taken: 'username',
  target_taken: 'target',
};

/** 查 status 的字段落点；未登记 / 未知 status → undefined（调用方回落 banner）。 */
export function fieldForStatus(status: string): string | undefined {
  return (STATUS_FIELD_MAP as Readonly<Record<string, string>>)[status];
}

// ---------------------------------------------------------------------------
// 层②（位置二）：ErrorInfo.code——其余域非 200 Connect 错误体（§1.5 行 199-221）
// ---------------------------------------------------------------------------

/** §1.5 Connect 标准码封闭集（行 184-193，connect-go v1.21.1 → HTTP 映射）；协议级错误无 ErrorInfo detail（行 224）。 */
export type ConnectStandardCode =
  | 'invalid_argument'
  | 'unauthenticated'
  | 'permission_denied'
  | 'not_found'
  | 'already_exists'
  | 'resource_exhausted'
  | 'internal'
  | 'unavailable';

/**
 * §1.6 失败类词汇（docs/接口文档.md 行 230-261 中非纯流程态的全部，26 词）；
 * 纯流程态（next / mfa_required / binding_required / success / pending / scanned /
 * expired）只在位置一出现，不得混入本位置（§1.6 行 267「两个位置」）；
 * `captcha_required` / `captcha_invalid` 仅在本位置出现（§1.6 行 286）。
 * `internal_error` 是 §1.6 词汇，与 Connect 标准码 `internal` 分属两套拼法，各自入表。
 */
export type BusinessCode =
  | 'failed'
  | 'captcha_required'
  | 'captcha_invalid'
  | 'too_many_requests'
  | 'too_many_attempts'
  | 'locked'
  | 'invalid_request'
  | 'invalid_credentials'
  | 'invalid_code'
  | 'code_expired'
  | 'method_disabled'
  | 'step_invalid'
  | 'token_invalid'
  | 'token_expired'
  | 'state_mismatch'
  | 'user_disabled'
  | 'user_not_found'
  | 'password_weak'
  | 'username_taken'
  | 'target_taken'
  | 'signup_disabled'
  | 'reset_disabled'
  | 'provider_disabled'
  | 'file_too_large'
  | 'file_type_not_allowed'
  | 'internal_error';

/** 位置二的取值域：§1.6 失败词（ErrorInfo.code）+ Connect 标准码（无 detail 兜底）；域内自造值（如 §13 的 config_invalid）走兜底。 */
export type ErrorCode = BusinessCode | ConnectStandardCode;

/** 层②解析结果：§1.6「可重试 / 前端动作」对两个位置同一套词汇（§8.2 A ①）；i18n 键口径 `errors.code.<code>`。 */
export interface CodeResolution {
  retryable: boolean;
  action: StatusAction;
  /** 未知 code（含客户端自造 code）走 `errors.code.unknown`。 */
  i18nKey: string;
}

/**
 * 层② §1.6 失败词的处置：两个位置共有的词与层①同表派生；captcha 两码仅此
 * 位置出现（§1.6 行 286），显式登记。i18n 键前缀统一为 errors.code.<词>。
 */
const failureResolutions: Readonly<Record<BusinessCode, CodeResolution>> = {
  failed: { ...FLOW_STATUS_TABLE.failed, i18nKey: 'errors.code.failed' },
  // captcha 两码仅作 ErrorInfo.code（§1.6 行 286），无对应流程态可派生，显式登记。
  captcha_required: {
    retryable: true,
    action: 'require_captcha',
    i18nKey: 'errors.code.captcha_required',
  },
  captcha_invalid: {
    retryable: true,
    action: 'reset_captcha',
    i18nKey: 'errors.code.captcha_invalid',
  },
  too_many_requests: {
    ...FLOW_STATUS_TABLE.too_many_requests,
    i18nKey: 'errors.code.too_many_requests',
  },
  too_many_attempts: {
    ...FLOW_STATUS_TABLE.too_many_attempts,
    i18nKey: 'errors.code.too_many_attempts',
  },
  locked: { ...FLOW_STATUS_TABLE.locked, i18nKey: 'errors.code.locked' },
  invalid_request: {
    ...FLOW_STATUS_TABLE.invalid_request,
    i18nKey: 'errors.code.invalid_request',
  },
  invalid_credentials: {
    ...FLOW_STATUS_TABLE.invalid_credentials,
    i18nKey: 'errors.code.invalid_credentials',
  },
  invalid_code: {
    ...FLOW_STATUS_TABLE.invalid_code,
    i18nKey: 'errors.code.invalid_code',
  },
  code_expired: {
    ...FLOW_STATUS_TABLE.code_expired,
    i18nKey: 'errors.code.code_expired',
  },
  method_disabled: {
    ...FLOW_STATUS_TABLE.method_disabled,
    i18nKey: 'errors.code.method_disabled',
  },
  step_invalid: {
    ...FLOW_STATUS_TABLE.step_invalid,
    i18nKey: 'errors.code.step_invalid',
  },
  token_invalid: {
    ...FLOW_STATUS_TABLE.token_invalid,
    i18nKey: 'errors.code.token_invalid',
  },
  token_expired: {
    ...FLOW_STATUS_TABLE.token_expired,
    i18nKey: 'errors.code.token_expired',
  },
  state_mismatch: {
    ...FLOW_STATUS_TABLE.state_mismatch,
    i18nKey: 'errors.code.state_mismatch',
  },
  user_disabled: {
    ...FLOW_STATUS_TABLE.user_disabled,
    i18nKey: 'errors.code.user_disabled',
  },
  user_not_found: {
    ...FLOW_STATUS_TABLE.user_not_found,
    i18nKey: 'errors.code.user_not_found',
  },
  password_weak: {
    ...FLOW_STATUS_TABLE.password_weak,
    i18nKey: 'errors.code.password_weak',
  },
  username_taken: {
    ...FLOW_STATUS_TABLE.username_taken,
    i18nKey: 'errors.code.username_taken',
  },
  target_taken: {
    ...FLOW_STATUS_TABLE.target_taken,
    i18nKey: 'errors.code.target_taken',
  },
  signup_disabled: {
    ...FLOW_STATUS_TABLE.signup_disabled,
    i18nKey: 'errors.code.signup_disabled',
  },
  reset_disabled: {
    ...FLOW_STATUS_TABLE.reset_disabled,
    i18nKey: 'errors.code.reset_disabled',
  },
  provider_disabled: {
    ...FLOW_STATUS_TABLE.provider_disabled,
    i18nKey: 'errors.code.provider_disabled',
  },
  file_too_large: {
    ...FLOW_STATUS_TABLE.file_too_large,
    i18nKey: 'errors.code.file_too_large',
  },
  file_type_not_allowed: {
    ...FLOW_STATUS_TABLE.file_type_not_allowed,
    i18nKey: 'errors.code.file_type_not_allowed',
  },
  internal_error: {
    ...FLOW_STATUS_TABLE.internal_error,
    i18nKey: 'errors.code.internal_error',
  },
};

/**
 * Connect 标准码兜底处置（§1.5 行 184-193）：标准码不进 §1.6 表（行 273），
 * 文案拦截、动作保守（message / 不可重试）。
 */
const standardResolutions: Readonly<
  Record<ConnectStandardCode, CodeResolution>
> = {
  invalid_argument: {
    retryable: false,
    action: 'message',
    i18nKey: 'errors.code.invalid_argument',
  },
  unauthenticated: {
    retryable: false,
    action: 'message',
    i18nKey: 'errors.code.unauthenticated',
  },
  permission_denied: {
    retryable: false,
    action: 'message',
    i18nKey: 'errors.code.permission_denied',
  },
  not_found: {
    retryable: false,
    action: 'message',
    i18nKey: 'errors.code.not_found',
  },
  already_exists: {
    retryable: false,
    action: 'message',
    i18nKey: 'errors.code.already_exists',
  },
  resource_exhausted: {
    retryable: false,
    action: 'message',
    i18nKey: 'errors.code.resource_exhausted',
  },
  internal: {
    retryable: false,
    action: 'message',
    i18nKey: 'errors.code.internal',
  },
  unavailable: {
    retryable: false,
    action: 'message',
    i18nKey: 'errors.code.unavailable',
  },
};

/**
 * 错误码表（位置二）：§1.6 失败词（26，其中 captcha 两码仅此位置出现）+ §1.5
 * Connect 标准码（8），共 34 键；新增取值必须同步本模块映射（§1.6 行 270）。
 */
export const CODE_TABLE: Readonly<Record<ErrorCode, CodeResolution>> = {
  ...failureResolutions,
  ...standardResolutions,
};

/** 未知 code 的兜底口径（客户端自造 code 一并兜底，不透出 message 原文）。 */
const CODE_FALLBACK: CodeResolution = {
  retryable: false,
  action: 'message',
  i18nKey: 'errors.code.unknown',
};

/**
 * 解析位置二（ErrorInfo.code / Connect 标准码兜底）：查表 →
 * `{retryable, action, i18nKey}`；未知 code 走兜底，不透出 `error.message` 原文。
 */
export function resolveCode(error: ApiError): CodeResolution {
  return (
    (CODE_TABLE as Readonly<Record<string, CodeResolution>>)[error.code] ??
    CODE_FALLBACK
  );
}

/** code 是否在位置二封闭集（34 键）内——http.ts 归一「已知码才透出 message」的判据（§1.5 行 202）。 */
export function isKnownCode(code: string): boolean {
  return Object.prototype.hasOwnProperty.call(CODE_TABLE, code);
}

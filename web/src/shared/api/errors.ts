/**
 * 两层错误口径——「§1.6 词汇、两个位置」（docs/接口文档.md §1.6 行 267；docs/前端架构.md §3.1 errors.ts）：
 * ① 位置一（登录流程域，SsoService 登录流程方法，HTTP 200）：响应**顶层 `status`**，
 *    取值即 §1.6 封闭全量表（33 词），含流程态（next / mfa_required / success / failed…）
 *    → `{retryable, action, i18nKey}`，业务分支走 reducer，不经 transport 拦截；
 * ② 位置二（其余域）：非 200 Connect 错误体 details 的 **`ErrorInfo.code`**（§1.5 行 199-221）
 *    ——无 detail 时按 Connect 标准码（§1.5 行 184-193）兜底，统一拦截文案。
 * 未知 `status` / `code` 一律走兜底，不暴露内部信息；`ErrorInfo.message` /
 * `ConnectError.message` 只作展示兜底（§1.5 行 202：i18n 优先，其次本字段），不参与分支。
 */

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
}

/** 统一错误体：非 200 Connect 错误体（ErrorInfo detail 或标准码兜底）与传输层失败的归一形态（docs/接口文档.md §1.5）。 */
export class ApiError extends Error {
  readonly httpStatus: number;

  readonly code: string;

  readonly requestId: string;

  /** 冷却 / 封禁剩余秒数（§1.5 行 220）；未携带或零值（protojson 省略零值，§1.1）为 undefined。 */
  readonly retryAfter?: bigint;

  /** 剩余尝试次数（§1.5 行 221）；未携带或零值为 undefined。 */
  readonly attemptsLeft?: bigint;

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
  /** captcha_required：按响应顶层 captcha 渲染 CaptchaWidget 并重提。 */
  | 'require_captcha'
  /** captcha_invalid：按响应顶层 captcha reset widget 后重试。 */
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
  readonly retryable: boolean;
  /** §1.6「前端动作」列的归纳。 */
  readonly action: StatusAction;
  /** i18n 键，口径 `errors.status.<status>`；文案由 shared/i18n 字典（后续实现）落。 */
  readonly i18nKey: string;
}

/**
 * §1.6 封闭全量表（docs/接口文档.md 行 230-261）——位置一（登录流程域 §1.3 顶层
 * status）的取值域；新增取值必须同步本模块映射（§1.6 行 270）。
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
 * 流程态表（位置一）：登录流程域顶层 status（§1.6 全表）→ 处置口径（表驱动，
 * 逐项对照 docs/接口文档.md 行 230-261）。`failed` 的「可重试」文档标注「视 error」，
 * 需调用方结合信封 error 内容判断，表取保守值 false。
 */
export const FLOW_STATUS_TABLE: Readonly<Record<FlowStatusKey, StatusResolution>> = {
  next: { retryable: false, action: 'render_next_step', i18nKey: 'errors.status.next' },
  mfa_required: { retryable: false, action: 'render_mfa', i18nKey: 'errors.status.mfa_required' },
  binding_required: { retryable: false, action: 'render_binding', i18nKey: 'errors.status.binding_required' },
  success: { retryable: false, action: 'complete', i18nKey: 'errors.status.success' },
  pending: { retryable: false, action: 'continue_polling', i18nKey: 'errors.status.pending' },
  scanned: { retryable: false, action: 'continue_polling', i18nKey: 'errors.status.scanned' },
  expired: { retryable: false, action: 'stop_polling', i18nKey: 'errors.status.expired' },
  failed: { retryable: false, action: 'message', i18nKey: 'errors.status.failed' },
  captcha_required: { retryable: true, action: 'require_captcha', i18nKey: 'errors.status.captcha_required' },
  captcha_invalid: { retryable: true, action: 'reset_captcha', i18nKey: 'errors.status.captcha_invalid' },
  too_many_requests: { retryable: false, action: 'countdown', i18nKey: 'errors.status.too_many_requests' },
  too_many_attempts: { retryable: false, action: 'message', i18nKey: 'errors.status.too_many_attempts' },
  locked: { retryable: false, action: 'countdown', i18nKey: 'errors.status.locked' },
  invalid_request: { retryable: false, action: 'field_error', i18nKey: 'errors.status.invalid_request' },
  invalid_credentials: { retryable: true, action: 'message', i18nKey: 'errors.status.invalid_credentials' },
  invalid_code: { retryable: true, action: 'message', i18nKey: 'errors.status.invalid_code' },
  code_expired: { retryable: false, action: 'message', i18nKey: 'errors.status.code_expired' },
  method_disabled: { retryable: false, action: 'refresh_methods', i18nKey: 'errors.status.method_disabled' },
  step_invalid: { retryable: false, action: 'restart', i18nKey: 'errors.status.step_invalid' },
  token_invalid: { retryable: false, action: 'restart', i18nKey: 'errors.status.token_invalid' },
  token_expired: { retryable: false, action: 'restart', i18nKey: 'errors.status.token_expired' },
  state_mismatch: { retryable: false, action: 'restart', i18nKey: 'errors.status.state_mismatch' },
  user_disabled: { retryable: false, action: 'message', i18nKey: 'errors.status.user_disabled' },
  user_not_found: { retryable: true, action: 'message', i18nKey: 'errors.status.user_not_found' },
  password_weak: { retryable: true, action: 'field_error', i18nKey: 'errors.status.password_weak' },
  username_taken: { retryable: true, action: 'field_error', i18nKey: 'errors.status.username_taken' },
  target_taken: { retryable: true, action: 'field_error', i18nKey: 'errors.status.target_taken' },
  signup_disabled: { retryable: false, action: 'message', i18nKey: 'errors.status.signup_disabled' },
  reset_disabled: { retryable: false, action: 'message', i18nKey: 'errors.status.reset_disabled' },
  provider_disabled: { retryable: false, action: 'refresh_methods', i18nKey: 'errors.status.provider_disabled' },
  file_too_large: { retryable: true, action: 'message', i18nKey: 'errors.status.file_too_large' },
  file_type_not_allowed: { retryable: true, action: 'message', i18nKey: 'errors.status.file_type_not_allowed' },
  internal_error: { retryable: true, action: 'message', i18nKey: 'errors.status.internal_error' },
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
 * expired）只在位置一出现，不得混入本位置（§1.6 行 267「两个位置」）。
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
  readonly retryable: boolean;
  readonly action: StatusAction;
  /** 未知 code（含客户端自造 code）走 `errors.code.unknown`。 */
  readonly i18nKey: string;
}

/**
 * 层② §1.6 失败词的处置：与层①同一张表派生（「一套词汇、两个位置」，§1.6 行 267），
 * 仅 i18n 键前缀不同（errors.status.<词> → errors.code.<词>）。
 */
const failureResolutions: Readonly<Record<BusinessCode, CodeResolution>> = {
  failed: { ...FLOW_STATUS_TABLE.failed, i18nKey: 'errors.code.failed' },
  captcha_required: { ...FLOW_STATUS_TABLE.captcha_required, i18nKey: 'errors.code.captcha_required' },
  captcha_invalid: { ...FLOW_STATUS_TABLE.captcha_invalid, i18nKey: 'errors.code.captcha_invalid' },
  too_many_requests: { ...FLOW_STATUS_TABLE.too_many_requests, i18nKey: 'errors.code.too_many_requests' },
  too_many_attempts: { ...FLOW_STATUS_TABLE.too_many_attempts, i18nKey: 'errors.code.too_many_attempts' },
  locked: { ...FLOW_STATUS_TABLE.locked, i18nKey: 'errors.code.locked' },
  invalid_request: { ...FLOW_STATUS_TABLE.invalid_request, i18nKey: 'errors.code.invalid_request' },
  invalid_credentials: { ...FLOW_STATUS_TABLE.invalid_credentials, i18nKey: 'errors.code.invalid_credentials' },
  invalid_code: { ...FLOW_STATUS_TABLE.invalid_code, i18nKey: 'errors.code.invalid_code' },
  code_expired: { ...FLOW_STATUS_TABLE.code_expired, i18nKey: 'errors.code.code_expired' },
  method_disabled: { ...FLOW_STATUS_TABLE.method_disabled, i18nKey: 'errors.code.method_disabled' },
  step_invalid: { ...FLOW_STATUS_TABLE.step_invalid, i18nKey: 'errors.code.step_invalid' },
  token_invalid: { ...FLOW_STATUS_TABLE.token_invalid, i18nKey: 'errors.code.token_invalid' },
  token_expired: { ...FLOW_STATUS_TABLE.token_expired, i18nKey: 'errors.code.token_expired' },
  state_mismatch: { ...FLOW_STATUS_TABLE.state_mismatch, i18nKey: 'errors.code.state_mismatch' },
  user_disabled: { ...FLOW_STATUS_TABLE.user_disabled, i18nKey: 'errors.code.user_disabled' },
  user_not_found: { ...FLOW_STATUS_TABLE.user_not_found, i18nKey: 'errors.code.user_not_found' },
  password_weak: { ...FLOW_STATUS_TABLE.password_weak, i18nKey: 'errors.code.password_weak' },
  username_taken: { ...FLOW_STATUS_TABLE.username_taken, i18nKey: 'errors.code.username_taken' },
  target_taken: { ...FLOW_STATUS_TABLE.target_taken, i18nKey: 'errors.code.target_taken' },
  signup_disabled: { ...FLOW_STATUS_TABLE.signup_disabled, i18nKey: 'errors.code.signup_disabled' },
  reset_disabled: { ...FLOW_STATUS_TABLE.reset_disabled, i18nKey: 'errors.code.reset_disabled' },
  provider_disabled: { ...FLOW_STATUS_TABLE.provider_disabled, i18nKey: 'errors.code.provider_disabled' },
  file_too_large: { ...FLOW_STATUS_TABLE.file_too_large, i18nKey: 'errors.code.file_too_large' },
  file_type_not_allowed: { ...FLOW_STATUS_TABLE.file_type_not_allowed, i18nKey: 'errors.code.file_type_not_allowed' },
  internal_error: { ...FLOW_STATUS_TABLE.internal_error, i18nKey: 'errors.code.internal_error' },
};

/**
 * Connect 标准码兜底处置（§1.5 行 184-193）：标准码不进 §1.6 表（行 273），
 * 文案拦截、动作保守（message / 不可重试）。
 */
const standardResolutions: Readonly<Record<ConnectStandardCode, CodeResolution>> = {
  invalid_argument: { retryable: false, action: 'message', i18nKey: 'errors.code.invalid_argument' },
  unauthenticated: { retryable: false, action: 'message', i18nKey: 'errors.code.unauthenticated' },
  permission_denied: { retryable: false, action: 'message', i18nKey: 'errors.code.permission_denied' },
  not_found: { retryable: false, action: 'message', i18nKey: 'errors.code.not_found' },
  already_exists: { retryable: false, action: 'message', i18nKey: 'errors.code.already_exists' },
  resource_exhausted: { retryable: false, action: 'message', i18nKey: 'errors.code.resource_exhausted' },
  internal: { retryable: false, action: 'message', i18nKey: 'errors.code.internal' },
  unavailable: { retryable: false, action: 'message', i18nKey: 'errors.code.unavailable' },
};

/**
 * 错误码表（位置二）：§1.6 失败词（26，与层①同动作）+ §1.5 Connect 标准码（8），
 * 共 34 键；新增取值必须同步本模块映射（§1.6 行 270）。
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

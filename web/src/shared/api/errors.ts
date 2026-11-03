/**
 * 两层错误口径——「§1.6 词汇、两个位置」（docs/接口文档.md §1.0 行 59；docs/前端架构.md §3.1 errors.ts）：
 * ① 位置一（登录流程域 /api/sso/**，§1.3 信封）：200 响应**顶层 `status`**，取值即
 *    §1.6 封闭全量表（§1.3 行 129），含流程态（next / mfa_required / success / failed…）
 *    → `{retryable, action, i18nKey}`，业务分支走 reducer，不经 http 层拦截；
 * ② 位置二（其余域）：`status:"error"` 的 **`error.code`**——200 业务失败（§1.6 词汇）
 *    与非 200 框架码（§1.5 六元封闭集）同一形状（§1.0），统一拦截文案。
 * 未知 `status` / `code` 一律走兜底，不暴露内部信息；`error.message` 只作展示兜底，不参与分支。
 */

// ---------------------------------------------------------------------------
// ApiError（自 http.ts 迁入；http.ts 仍 re-export 保持既有 import 路径兼容）
// ---------------------------------------------------------------------------

export interface ApiErrorInit {
  httpStatus: number;
  code: string;
  message: string;
  requestId: string;
}

/** 统一错误体：非 2xx 框架拒绝、2xx 内 status:"error" 业务失败与契约错误（docs/接口文档.md §1.0 / §1.5）。 */
export class ApiError extends Error {
  readonly httpStatus: number;

  readonly code: string;

  readonly requestId: string;

  constructor(init: ApiErrorInit) {
    super(init.message);
    this.name = 'ApiError';
    this.httpStatus = init.httpStatus;
    this.code = init.code;
    this.requestId = init.requestId;
  }
}

// ---------------------------------------------------------------------------
// 层①（位置一）：登录流程域顶层 status（/api/sso/**，§1.3 信封；
// 取值即 §1.6 封闭全量表，docs/接口文档.md §1.3 行 129）
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
  /** 普通提示：i18n 优先，信封 error.message 作兜底展示（§1.6 行 216 / 行 247）。 */
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
 * §1.6 封闭全量表（docs/接口文档.md 行 226-257）——位置一（登录流程域 §1.3 顶层
 * status）的取值域；新增取值必须同步本模块映射（§1.6 行 259）。
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
 * 逐项对照 docs/接口文档.md 行 226-257）。`failed` 的「可重试」文档标注「视 error」，
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

/** 未知流程态的兜底口径：不暴露内部信息（§1.6 行 259）。 */
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
// 层②（位置二）：error.code——其余域 200 status:"error" 业务失败（§1.6 词汇）
// 与非 200 框架拒绝（§1.5 六元）同一形状，统一拦截文案（§1.0 行 57-58）
// ---------------------------------------------------------------------------

/** §1.5 框架拒绝 code 封闭集合（六元，docs/接口文档.md 行 218）。 */
export type FrameworkCode =
  | 'bad_request'
  | 'unauthorized'
  | 'forbidden'
  | 'not_found'
  | 'unsupported_media_type'
  | 'internal_error';

/**
 * §1.6 失败类词汇（docs/接口文档.md 行 226-257 中非纯流程态的全部）；
 * 纯流程态（next / mfa_required / binding_required / success / pending / scanned /
 * expired）只在位置一出现，不得混入本位置（§1.6 行 59「两个位置」）。
 * `internal_error` 与 §1.5 六元同名同义，归入 FrameworkCode 不重复列出。
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
  | 'file_type_not_allowed';

/** 位置二（error.code）的取值域：框架码（六元）+ §1.6 业务失败词；域内定义值（如 §13 的 config_invalid）走兜底。 */
export type ErrorCode = FrameworkCode | BusinessCode;

/** 层②解析结果：统一拦截文案，仅 i18n 键，不透出 `error.message` 原文。 */
export interface CodeResolution {
  /** i18n 键，口径 `errors.code.<code>`；未知 code（含客户端自造 code）走 `errors.code.unknown`。 */
  readonly i18nKey: string;
}

/**
 * 错误码表（位置二）：六元框架码 + §1.6 失败词 → 统一拦截文案。
 * 200 业务失败的 error.code 与非 200 框架码共用本表（§1.0 同一形状）。
 */
export const CODE_TABLE: Readonly<Record<ErrorCode, CodeResolution>> = {
  bad_request: { i18nKey: 'errors.code.bad_request' },
  unauthorized: { i18nKey: 'errors.code.unauthorized' },
  forbidden: { i18nKey: 'errors.code.forbidden' },
  not_found: { i18nKey: 'errors.code.not_found' },
  unsupported_media_type: { i18nKey: 'errors.code.unsupported_media_type' },
  internal_error: { i18nKey: 'errors.code.internal_error' },
  failed: { i18nKey: 'errors.code.failed' },
  captcha_required: { i18nKey: 'errors.code.captcha_required' },
  captcha_invalid: { i18nKey: 'errors.code.captcha_invalid' },
  too_many_requests: { i18nKey: 'errors.code.too_many_requests' },
  too_many_attempts: { i18nKey: 'errors.code.too_many_attempts' },
  locked: { i18nKey: 'errors.code.locked' },
  invalid_request: { i18nKey: 'errors.code.invalid_request' },
  invalid_credentials: { i18nKey: 'errors.code.invalid_credentials' },
  invalid_code: { i18nKey: 'errors.code.invalid_code' },
  code_expired: { i18nKey: 'errors.code.code_expired' },
  method_disabled: { i18nKey: 'errors.code.method_disabled' },
  step_invalid: { i18nKey: 'errors.code.step_invalid' },
  token_invalid: { i18nKey: 'errors.code.token_invalid' },
  token_expired: { i18nKey: 'errors.code.token_expired' },
  state_mismatch: { i18nKey: 'errors.code.state_mismatch' },
  user_disabled: { i18nKey: 'errors.code.user_disabled' },
  user_not_found: { i18nKey: 'errors.code.user_not_found' },
  password_weak: { i18nKey: 'errors.code.password_weak' },
  username_taken: { i18nKey: 'errors.code.username_taken' },
  target_taken: { i18nKey: 'errors.code.target_taken' },
  signup_disabled: { i18nKey: 'errors.code.signup_disabled' },
  reset_disabled: { i18nKey: 'errors.code.reset_disabled' },
  provider_disabled: { i18nKey: 'errors.code.provider_disabled' },
  file_too_large: { i18nKey: 'errors.code.file_too_large' },
  file_type_not_allowed: { i18nKey: 'errors.code.file_type_not_allowed' },
};

/** 未知 code 的兜底口径（客户端自造 code 一并兜底，不透出 message 原文）。 */
const CODE_FALLBACK: CodeResolution = {
  i18nKey: 'errors.code.unknown',
};

/**
 * 解析位置二（error.code）统一拦截文案：六元框架码 + §1.6 失败词查表；
 * 未知 code（域内定义值如 §13 `config_invalid`、`content_type_mismatch` 等客户端自造 code）
 * 走兜底，不透出 `error.message` 原文。2xx 业务失败与非 2xx 框架拒绝同一入口。
 */
export function resolveCode(error: ApiError): CodeResolution {
  return (
    (CODE_TABLE as Readonly<Record<string, CodeResolution>>)[error.code] ??
    CODE_FALLBACK
  );
}

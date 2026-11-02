/**
 * 两层错误口径（docs/前端架构.md §3.1 行 269、§8.1 行 555）：
 * ① 200 响应内的业务 `status` → `{retryable, action, i18nKey}`（docs/接口文档.md §1.6 封闭集合）；
 * ② 4xx/5xx 的 `code`（docs/接口文档.md §1.5 六元封闭集）→ 统一拦截文案。
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

/** 非 2xx 响应与契约错误的统一错误体（docs/接口文档.md §1.5）。 */
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
// 层①：200 响应内的业务 status（docs/接口文档.md §1.6）
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

/** §1.6 status 封闭集合（docs/接口文档.md 行 207-238；新增取值必须同步本模块映射，行 246）。 */
export type StatusKey =
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
 * §1.6 全部 status → 处置口径（表驱动，逐项对照 docs/接口文档.md 行 207-238）。
 * `failed` 的「可重试」文档标注「视 error」，需调用方结合信封 error 内容判断，表取保守值 false。
 */
export const STATUS_TABLE: Readonly<Record<StatusKey, StatusResolution>> = {
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

/** 未知 status 的兜底口径：不暴露内部信息（§1.6 行 248）。 */
const STATUS_FALLBACK: StatusResolution = {
  retryable: false,
  action: 'message',
  i18nKey: 'errors.status.unknown',
};

/** 解析 200 响应内的业务 status；未知 status 走兜底，不透出原文。 */
export function resolveStatus(status: string): StatusResolution {
  return (
    (STATUS_TABLE as Readonly<Record<string, StatusResolution>>)[status] ??
    STATUS_FALLBACK
  );
}

// ---------------------------------------------------------------------------
// 层②：4xx/5xx 的 code（docs/接口文档.md §1.5 行 199 封闭集）
// ---------------------------------------------------------------------------

/** §1.5 错误体 code 封闭集合（docs/接口文档.md 行 199）。 */
export type ErrorCode =
  | 'bad_request'
  | 'unauthorized'
  | 'forbidden'
  | 'not_found'
  | 'unsupported_media_type'
  | 'internal_error';

/** 层②解析结果：统一拦截文案，仅 i18n 键，不透出 `error.message` 原文。 */
export interface CodeResolution {
  /** i18n 键，口径 `errors.code.<code>`；未知 code（含客户端自造 code）走 `errors.code.unknown`。 */
  readonly i18nKey: string;
}

/** §1.5 封闭集逐个映射（docs/接口文档.md 行 199）。 */
export const CODE_TABLE: Readonly<Record<ErrorCode, CodeResolution>> = {
  bad_request: { i18nKey: 'errors.code.bad_request' },
  unauthorized: { i18nKey: 'errors.code.unauthorized' },
  forbidden: { i18nKey: 'errors.code.forbidden' },
  not_found: { i18nKey: 'errors.code.not_found' },
  unsupported_media_type: { i18nKey: 'errors.code.unsupported_media_type' },
  internal_error: { i18nKey: 'errors.code.internal_error' },
};

/** 未知 code 的兜底口径（客户端自造 code 一并兜底，不透出 message 原文）。 */
const CODE_FALLBACK: CodeResolution = {
  i18nKey: 'errors.code.unknown',
};

/**
 * 解析 4xx/5xx 统一拦截文案：已知封闭集 code 查表；
 * 未知 code（含 `content_type_mismatch` 等客户端自造 code）走兜底，不透出 `error.message` 原文。
 */
export function resolveCode(error: ApiError): CodeResolution {
  return (
    (CODE_TABLE as Readonly<Record<string, CodeResolution>>)[error.code] ??
    CODE_FALLBACK
  );
}

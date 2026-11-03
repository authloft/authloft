// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径；
// 不调整 tsconfig，仅在测试文件放宽该 import 的类型解析。
// @ts-ignore
import { describe, expect, test } from 'rstack/test';
import {
  ApiError,
  CODE_TABLE,
  FLOW_STATUS_TABLE,
  isKnownCode,
  resolveCode,
  resolveFlowStatus,
  type FlowStatusKey,
  type StatusAction,
} from './errors';

/**
 * 位置一期望表：登录流程域顶层 status = §1.6 封闭全表 33 项
 * （docs/接口文档.md 行 230-261、§1.3 行 104；i18nKey 口径 errors.status.<status>）。
 */
const EXPECTED_FLOW_STATUS: Readonly<
  Record<string, { retryable: boolean; action: StatusAction; i18nKey: string }>
> = {
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

/** §1.6 纯流程态（仅位置一）：只在登录流程域顶层 status 出现，不得混入错误码表（§1.6 行 267）。 */
const FLOW_ONLY: ReadonlyArray<string> = [
  'next',
  'mfa_required',
  'binding_required',
  'success',
  'pending',
  'scanned',
  'expired',
];

/** §1.6 失败类词汇（26 词，两个位置都可能出现；internal_error 为 §1.6 拼法，与 Connect 标准码 internal 分立）。 */
const FAILURE_WORDS: ReadonlyArray<string> = [
  'failed',
  'captcha_required',
  'captcha_invalid',
  'too_many_requests',
  'too_many_attempts',
  'locked',
  'invalid_request',
  'invalid_credentials',
  'invalid_code',
  'code_expired',
  'method_disabled',
  'step_invalid',
  'token_invalid',
  'token_expired',
  'state_mismatch',
  'user_disabled',
  'user_not_found',
  'password_weak',
  'username_taken',
  'target_taken',
  'signup_disabled',
  'reset_disabled',
  'provider_disabled',
  'file_too_large',
  'file_type_not_allowed',
  'internal_error',
];

/** §1.5 Connect 标准码（8 个，行 184-193；无 detail 时的兜底取值）。 */
const CONNECT_STANDARD_CODES: ReadonlyArray<string> = [
  'invalid_argument',
  'unauthenticated',
  'permission_denied',
  'not_found',
  'already_exists',
  'resource_exhausted',
  'internal',
  'unavailable',
];

/**
 * 位置二期望表：§1.6 失败词（26，动作与位置一同表派生）+ §1.5 Connect 标准码
 * （8，行 273 标准码不进 §1.6 表，动作保守 message / 不可重试），共 34 键；
 * i18nKey 口径 errors.code.<code>。
 */
const EXPECTED_CODE: Readonly<
  Record<string, { retryable: boolean; action: StatusAction; i18nKey: string }>
> = {
  failed: { retryable: false, action: 'message', i18nKey: 'errors.code.failed' },
  captcha_required: { retryable: true, action: 'require_captcha', i18nKey: 'errors.code.captcha_required' },
  captcha_invalid: { retryable: true, action: 'reset_captcha', i18nKey: 'errors.code.captcha_invalid' },
  too_many_requests: { retryable: false, action: 'countdown', i18nKey: 'errors.code.too_many_requests' },
  too_many_attempts: { retryable: false, action: 'message', i18nKey: 'errors.code.too_many_attempts' },
  locked: { retryable: false, action: 'countdown', i18nKey: 'errors.code.locked' },
  invalid_request: { retryable: false, action: 'field_error', i18nKey: 'errors.code.invalid_request' },
  invalid_credentials: { retryable: true, action: 'message', i18nKey: 'errors.code.invalid_credentials' },
  invalid_code: { retryable: true, action: 'message', i18nKey: 'errors.code.invalid_code' },
  code_expired: { retryable: false, action: 'message', i18nKey: 'errors.code.code_expired' },
  method_disabled: { retryable: false, action: 'refresh_methods', i18nKey: 'errors.code.method_disabled' },
  step_invalid: { retryable: false, action: 'restart', i18nKey: 'errors.code.step_invalid' },
  token_invalid: { retryable: false, action: 'restart', i18nKey: 'errors.code.token_invalid' },
  token_expired: { retryable: false, action: 'restart', i18nKey: 'errors.code.token_expired' },
  state_mismatch: { retryable: false, action: 'restart', i18nKey: 'errors.code.state_mismatch' },
  user_disabled: { retryable: false, action: 'message', i18nKey: 'errors.code.user_disabled' },
  user_not_found: { retryable: true, action: 'message', i18nKey: 'errors.code.user_not_found' },
  password_weak: { retryable: true, action: 'field_error', i18nKey: 'errors.code.password_weak' },
  username_taken: { retryable: true, action: 'field_error', i18nKey: 'errors.code.username_taken' },
  target_taken: { retryable: true, action: 'field_error', i18nKey: 'errors.code.target_taken' },
  signup_disabled: { retryable: false, action: 'message', i18nKey: 'errors.code.signup_disabled' },
  reset_disabled: { retryable: false, action: 'message', i18nKey: 'errors.code.reset_disabled' },
  provider_disabled: { retryable: false, action: 'refresh_methods', i18nKey: 'errors.code.provider_disabled' },
  file_too_large: { retryable: true, action: 'message', i18nKey: 'errors.code.file_too_large' },
  file_type_not_allowed: { retryable: true, action: 'message', i18nKey: 'errors.code.file_type_not_allowed' },
  internal_error: { retryable: true, action: 'message', i18nKey: 'errors.code.internal_error' },
  invalid_argument: { retryable: false, action: 'message', i18nKey: 'errors.code.invalid_argument' },
  unauthenticated: { retryable: false, action: 'message', i18nKey: 'errors.code.unauthenticated' },
  permission_denied: { retryable: false, action: 'message', i18nKey: 'errors.code.permission_denied' },
  not_found: { retryable: false, action: 'message', i18nKey: 'errors.code.not_found' },
  already_exists: { retryable: false, action: 'message', i18nKey: 'errors.code.already_exists' },
  resource_exhausted: { retryable: false, action: 'message', i18nKey: 'errors.code.resource_exhausted' },
  internal: { retryable: false, action: 'message', i18nKey: 'errors.code.internal' },
  unavailable: { retryable: false, action: 'message', i18nKey: 'errors.code.unavailable' },
};

describe('shared/api/errors 层①（位置一）：登录流程域顶层 status（§1.6 全表）', () => {
  test('§1.6 全表 33 项表驱动逐项映射（docs/前端架构.md §8.2 A）', () => {
    for (const [status, expected] of Object.entries(EXPECTED_FLOW_STATUS)) {
      expect(resolveFlowStatus(status)).toEqual(expected);
    }
  });

  test('FLOW_STATUS_TABLE 键集与 §1.6 封闭全表一致（33 项，防实现表缺项 / 多项）', () => {
    expect(Object.keys(EXPECTED_FLOW_STATUS)).toHaveLength(33);
    expect(Object.keys(FLOW_STATUS_TABLE).sort()).toEqual(
      Object.keys(EXPECTED_FLOW_STATUS).sort(),
    );
  });

  test('未知流程态走兜底，不暴露内部信息（§1.6 行 272）', () => {
    const resolution = resolveFlowStatus('__no_such_status__');
    expect(resolution.action).toBe('message');
    expect(resolution.retryable).toBe(false);
    expect(resolution.i18nKey).toBe('errors.status.unknown');
    expect(JSON.stringify(resolution)).not.toContain('__no_such_status__');
  });
});

describe('shared/api/errors 层②（位置二）：ErrorInfo.code + Connect 标准码兜底', () => {
  test('34 键逐个映射 {retryable, action, i18nKey}（26 失败词 + 8 标准码，§8.2 A ①②）', () => {
    expect(Object.keys(EXPECTED_CODE)).toHaveLength(34);
    expect(Object.keys(CODE_TABLE).sort()).toEqual(
      Object.keys(EXPECTED_CODE).sort(),
    );
    for (const [code, expected] of Object.entries(EXPECTED_CODE)) {
      expect(
        resolveCode(
          new ApiError({ httpStatus: 400, code, message: 'x', requestId: 'r' }),
        ),
      ).toEqual(expected);
    }
  });

  test('纯流程态不入错误码表：作 error.code 查询走兜底（两个位置不得混用，§1.6 行 267）', () => {
    for (const status of FLOW_ONLY) {
      expect(CODE_TABLE).not.toHaveProperty(status);
      expect(
        resolveCode(
          new ApiError({ httpStatus: 200, code: status, message: 'x', requestId: 'r' }),
        ).i18nKey,
      ).toBe('errors.code.unknown');
    }
  });

  test('两层表分位一致：层① = §1.6 全表 33；层② = 失败词 26 + 标准码 8 = 34；交集恰为失败词', () => {
    const flowKeys = Object.keys(FLOW_STATUS_TABLE);
    const codeKeys = Object.keys(CODE_TABLE);
    expect(flowKeys).toHaveLength(33);
    expect(codeKeys).toHaveLength(34);
    expect(flowKeys.filter((key) => codeKeys.includes(key)).sort()).toEqual(
      [...FAILURE_WORDS].sort(),
    );
    expect(flowKeys.filter((key) => !codeKeys.includes(key)).sort()).toEqual(
      [...FLOW_ONLY].sort(),
    );
    expect(codeKeys.filter((key) => !flowKeys.includes(key)).sort()).toEqual(
      [...CONNECT_STANDARD_CODES].sort(),
    );
  });

  test('失败词的 retryable / action 与层①同表（一套词汇、两个位置，§1.6 行 267）', () => {
    for (const word of FAILURE_WORDS) {
      const code = CODE_TABLE[word as keyof typeof CODE_TABLE];
      const flow = FLOW_STATUS_TABLE[word as FlowStatusKey];
      expect(code.retryable).toBe(flow.retryable);
      expect(code.action).toBe(flow.action);
    }
  });

  test('未知 code 兜底且不透出 error.message 原文（含表外 Connect 码 canceled / data_loss）', () => {
    for (const code of ['__no_such_code__', 'canceled', 'data_loss', 'content_type_mismatch']) {
      const resolution = resolveCode(
        new ApiError({ httpStatus: 500, code, message: 'secret detail', requestId: 'req-1' }),
      );
      expect(resolution.i18nKey).toBe('errors.code.unknown');
      expect(JSON.stringify(resolution)).not.toContain('secret');
    }
  });

  test('isKnownCode：封闭集内 true（34 键），表外 false', () => {
    for (const code of Object.keys(EXPECTED_CODE)) {
      expect(isKnownCode(code)).toBe(true);
    }
    for (const code of ['__no_such_code__', 'canceled', 'deadline_exceeded', 'config_invalid']) {
      expect(isKnownCode(code)).toBe(false);
    }
  });
});

describe('shared/api/errors ApiError（ErrorInfo 归一形态，§1.5 行 213-221）', () => {
  test('携带 httpStatus / code / message / requestId / retryAfter / attemptsLeft，仍是 Error 子类', () => {
    const error = new ApiError({
      httpStatus: 429,
      code: 'too_many_requests',
      message: '冷却中',
      requestId: 'req-1',
      retryAfter: BigInt(60),
      attemptsLeft: BigInt(2),
    });
    expect(error).toBeInstanceOf(Error);
    expect(error.name).toBe('ApiError');
    expect(error.httpStatus).toBe(429);
    expect(error.code).toBe('too_many_requests');
    expect(error.message).toBe('冷却中');
    expect(error.requestId).toBe('req-1');
    expect(error.retryAfter).toBe(BigInt(60));
    expect(error.attemptsLeft).toBe(BigInt(2));
  });

  test('retryAfter / attemptsLeft 零值与缺省均归一为 undefined（protojson 省略零值，§1.1）', () => {
    const zeroed = new ApiError({
      httpStatus: 429,
      code: 'too_many_requests',
      message: '',
      requestId: '',
      retryAfter: BigInt(0),
      attemptsLeft: BigInt(0),
    });
    expect(zeroed.retryAfter).toBeUndefined();
    expect(zeroed.attemptsLeft).toBeUndefined();

    const absent = new ApiError({
      httpStatus: 500,
      code: 'internal',
      message: '',
      requestId: '',
    });
    expect(absent.retryAfter).toBeUndefined();
    expect(absent.attemptsLeft).toBeUndefined();
  });
});

// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径；
// 不调整 tsconfig，仅在测试文件放宽该 import 的类型解析。
// @ts-ignore
import { describe, expect, test } from 'rstack/test';
import {
  ApiError,
  CODE_TABLE,
  FLOW_STATUS_TABLE,
  resolveCode,
  resolveFlowStatus,
  type StatusAction,
} from './errors';

/**
 * 位置一期望表：登录流程域顶层 status = §1.6 封闭全表 33 项
 * （docs/接口文档.md 行 226-257、§1.3 行 129；i18nKey 口径 errors.status.<status>）。
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

/** §1.6 纯流程态（仅位置一）：只在登录流程域顶层 status 出现，不得混入错误码表（§1.0 行 59）。 */
const FLOW_ONLY: ReadonlyArray<string> = [
  'next',
  'mfa_required',
  'binding_required',
  'success',
  'pending',
  'scanned',
  'expired',
];

/** §1.6 失败类词汇（两个位置都可能出现；internal_error 与 §1.5 六元同名同义）。 */
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

/** 位置二期望表：§1.5 六元 + §1.6 失败词（internal_error 重叠，共 31 键；i18nKey 口径 errors.code.<code>）。 */
const EXPECTED_CODE: Readonly<Record<string, string>> = {
  bad_request: 'errors.code.bad_request',
  unauthorized: 'errors.code.unauthorized',
  forbidden: 'errors.code.forbidden',
  not_found: 'errors.code.not_found',
  unsupported_media_type: 'errors.code.unsupported_media_type',
  internal_error: 'errors.code.internal_error',
  failed: 'errors.code.failed',
  captcha_required: 'errors.code.captcha_required',
  captcha_invalid: 'errors.code.captcha_invalid',
  too_many_requests: 'errors.code.too_many_requests',
  too_many_attempts: 'errors.code.too_many_attempts',
  locked: 'errors.code.locked',
  invalid_request: 'errors.code.invalid_request',
  invalid_credentials: 'errors.code.invalid_credentials',
  invalid_code: 'errors.code.invalid_code',
  code_expired: 'errors.code.code_expired',
  method_disabled: 'errors.code.method_disabled',
  step_invalid: 'errors.code.step_invalid',
  token_invalid: 'errors.code.token_invalid',
  token_expired: 'errors.code.token_expired',
  state_mismatch: 'errors.code.state_mismatch',
  user_disabled: 'errors.code.user_disabled',
  user_not_found: 'errors.code.user_not_found',
  password_weak: 'errors.code.password_weak',
  username_taken: 'errors.code.username_taken',
  target_taken: 'errors.code.target_taken',
  signup_disabled: 'errors.code.signup_disabled',
  reset_disabled: 'errors.code.reset_disabled',
  provider_disabled: 'errors.code.provider_disabled',
  file_too_large: 'errors.code.file_too_large',
  file_type_not_allowed: 'errors.code.file_type_not_allowed',
};

describe('shared/api/errors 层①（位置一）：登录流程域顶层 status（§1.6 全表）', () => {
  test('§1.6 全表 33 项表驱动逐项映射（docs/前端架构.md §8.1）', () => {
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

  test('未知流程态走兜底，不暴露内部信息（§1.6 行 259）', () => {
    const resolution = resolveFlowStatus('__no_such_status__');
    expect(resolution.action).toBe('message');
    expect(resolution.retryable).toBe(false);
    expect(resolution.i18nKey).toBe('errors.status.unknown');
    expect(JSON.stringify(resolution)).not.toContain('__no_such_status__');
  });
});

describe('shared/api/errors 层②（位置二）：error.code（§1.6 失败词 + §1.5 六元）', () => {
  test('31 键逐个映射（i18nKey 口径 errors.code.<code>）', () => {
    expect(Object.keys(EXPECTED_CODE)).toHaveLength(31);
    expect(Object.keys(CODE_TABLE).sort()).toEqual(
      Object.keys(EXPECTED_CODE).sort(),
    );
    for (const [code, i18nKey] of Object.entries(EXPECTED_CODE)) {
      expect(
        resolveCode(
          new ApiError({ httpStatus: 400, code, message: 'x', requestId: 'r' }),
        ).i18nKey,
      ).toBe(i18nKey);
    }
  });

  test('纯流程态不入错误码表：作 error.code 查询走兜底（两个位置不得混用，§1.0 行 59）', () => {
    for (const status of FLOW_ONLY) {
      expect(CODE_TABLE).not.toHaveProperty(status);
      expect(
        resolveCode(
          new ApiError({ httpStatus: 200, code: status, message: 'x', requestId: 'r' }),
        ).i18nKey,
      ).toBe('errors.code.unknown');
    }
  });

  test('两层表分位一致：层① = §1.6 全表 33；层② = 六元 + 失败词 31；交集恰为失败词 26', () => {
    const flowKeys = Object.keys(FLOW_STATUS_TABLE);
    const codeKeys = Object.keys(CODE_TABLE);
    expect(flowKeys).toHaveLength(33);
    expect(codeKeys).toHaveLength(31);
    expect(flowKeys.filter((key) => codeKeys.includes(key)).sort()).toEqual(
      [...FAILURE_WORDS].sort(),
    );
    expect(flowKeys.filter((key) => !codeKeys.includes(key)).sort()).toEqual(
      [...FLOW_ONLY].sort(),
    );
  });

  test('未知 code 兜底且不透出 error.message 原文（客户端自造 code 一并兜底）', () => {
    const resolution = resolveCode(
      new ApiError({
        httpStatus: 200,
        code: 'content_type_mismatch',
        message: 'expected application/json but got text/html',
        requestId: 'req-1',
      }),
    );
    expect(resolution.i18nKey).toBe('errors.code.unknown');
    expect(JSON.stringify(resolution)).not.toContain('content_type_mismatch');
    expect(JSON.stringify(resolution)).not.toContain('text/html');
  });
});

describe('shared/api/errors ApiError（自 http.ts 迁入）', () => {
  test('携带 httpStatus / code / message / requestId，仍是 Error 子类', () => {
    const error = new ApiError({
      httpStatus: 401,
      code: 'unauthorized',
      message: 'no session',
      requestId: 'req-1',
    });
    expect(error).toBeInstanceOf(Error);
    expect(error.name).toBe('ApiError');
    expect(error.httpStatus).toBe(401);
    expect(error.code).toBe('unauthorized');
    expect(error.message).toBe('no session');
    expect(error.requestId).toBe('req-1');
  });
});

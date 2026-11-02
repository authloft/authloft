// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径；
// 不调整 tsconfig，仅在测试文件放宽该 import 的类型解析。
// @ts-ignore
import { describe, expect, test } from 'rstack/test';
import {
  ApiError,
  CODE_TABLE,
  STATUS_TABLE,
  resolveCode,
  resolveStatus,
  type StatusAction,
} from './errors';

/** 期望表：逐项对照 docs/接口文档.md §1.6 行 207-238（i18nKey 口径 errors.status.<status>）。 */
const EXPECTED_STATUS: Readonly<
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

describe('shared/api/errors 层①：业务 status（§1.6）', () => {
  test('§1.6 全部 status 表驱动逐项映射（docs/前端架构.md §8.1 行 555）', () => {
    for (const [status, expected] of Object.entries(EXPECTED_STATUS)) {
      expect(resolveStatus(status)).toEqual(expected);
    }
  });

  test('STATUS_TABLE 与 §1.6 封闭集合键集一致（33 项，防实现表缺项 / 多项）', () => {
    expect(Object.keys(EXPECTED_STATUS)).toHaveLength(33);
    expect(Object.keys(STATUS_TABLE).sort()).toEqual(
      Object.keys(EXPECTED_STATUS).sort(),
    );
  });

  test('未知 status 走兜底，不暴露内部信息（§1.6 行 248）', () => {
    const resolution = resolveStatus('__no_such_status__');
    expect(resolution.action).toBe('message');
    expect(resolution.retryable).toBe(false);
    expect(resolution.i18nKey).toBe('errors.status.unknown');
    expect(JSON.stringify(resolution)).not.toContain('__no_such_status__');
  });
});

describe('shared/api/errors 层②：4xx/5xx code（§1.5 封闭集）', () => {
  test('六个 code 逐个映射（§1.5 行 199）', () => {
    const expected: Readonly<Record<string, string>> = {
      bad_request: 'errors.code.bad_request',
      unauthorized: 'errors.code.unauthorized',
      forbidden: 'errors.code.forbidden',
      not_found: 'errors.code.not_found',
      unsupported_media_type: 'errors.code.unsupported_media_type',
      internal_error: 'errors.code.internal_error',
    };
    expect(Object.keys(CODE_TABLE).sort()).toEqual(Object.keys(expected).sort());
    for (const [code, i18nKey] of Object.entries(expected)) {
      expect(
        resolveCode(
          new ApiError({ httpStatus: 400, code, message: 'x', requestId: 'r' }),
        ).i18nKey,
      ).toBe(i18nKey);
    }
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

// requestOptions 集中分派单测（§5.4）。分派判定 classifyRequestError
// 为纯函数；onError 副作用（redirect / showToast / onFieldError）全注入断言
// （闭包计数器，沿 RestartingPage.test.ts 既有模式）。
// tsconfig moduleResolution=node 解析不了 rstack/test 子路径。
// @ts-ignore
import { afterEach, describe, expect, test } from 'rstack/test';
import { ApiError } from '../api/errors';
import {
  classifyRequestError,
  isUnauthenticatedError,
  requestErrorText,
  requestOptions,
} from './requestOptions';

function apiError(code: string, httpStatus = 400): ApiError {
  return new ApiError({ httpStatus, code, message: '', requestId: '' });
}

/** 调用记录器：记录每次调用的第一个参数。 */
function recorder<T>(): { calls: T[]; fn: (arg: T) => void } {
  const calls: T[] = [];
  return { calls, fn: (arg: T) => void calls.push(arg) };
}

afterEach(() => {
  delete (globalThis as { __AUTHLOFT_INIT__?: unknown }).__AUTHLOFT_INIT__;
});

describe('isUnauthenticatedError（401 双条件口径）', () => {
  test('HTTP 401 → true；code unauthenticated → true；其余 → false', () => {
    expect(isUnauthenticatedError(apiError('internal', 401))).toBe(true);
    expect(isUnauthenticatedError(apiError('unauthenticated', 400))).toBe(true);
    expect(isUnauthenticatedError(apiError('internal', 500))).toBe(false);
    expect(isUnauthenticatedError(new Error('x'))).toBe(false);
    expect(isUnauthenticatedError(undefined)).toBe(false);
  });
});

describe('classifyRequestError 分派顺序', () => {
  test('401 优先于字段级与 toast 开关 → redirect', () => {
    expect(
      classifyRequestError(apiError('password_weak', 401), {
        toast: false,
        fieldByCode: { password_weak: 'password' },
        onFieldError: () => {},
      }),
    ).toEqual({ kind: 'redirect' });
  });

  test('字段级错误码命中（且注入 onFieldError）→ field，文案走 i18n', () => {
    const action = classifyRequestError(apiError('password_weak'), {
      fieldByCode: { password_weak: 'adminPassword' },
      onFieldError: () => {},
    });
    expect(action.kind).toBe('field');
    if (action.kind === 'field') {
      expect(action.field).toBe('adminPassword');
      expect(action.message).not.toBe('');
    }
  });

  test('字段级命中但未注入 onFieldError → 回落 toast（行内无处可落）', () => {
    expect(
      classifyRequestError(apiError('password_weak'), {
        fieldByCode: { password_weak: 'password' },
      }).kind,
    ).toBe('toast');
  });

  test('toast:false 仅作用「其余」分支 → silent；字段级不受影响', () => {
    expect(classifyRequestError(apiError('internal', 500), { toast: false })).toEqual({
      kind: 'silent',
    });
    expect(
      classifyRequestError(apiError('password_weak'), {
        toast: false,
        fieldByCode: { password_weak: 'password' },
        onFieldError: () => {},
      }).kind,
    ).toBe('field');
  });

  test('其余 ApiError / 非 ApiError → toast，未知错误兜底文案不透出原文', () => {
    expect(classifyRequestError(apiError('internal', 500), {}).kind).toBe('toast');
    const action = classifyRequestError(new Error('secret internals'), {});
    expect(action).toEqual({ kind: 'toast', message: requestErrorText(new Error('x')) });
  });
});

describe('requestOptions onError 副作用分派', () => {
  test('401 → redirect：loginUrl(alRoot, returnTo(path, search)) 拼装', () => {
    (globalThis as { __AUTHLOFT_INIT__?: unknown }).__AUTHLOFT_INIT__ = {
      al_root: 'https://uc.example.com/',
    };
    const redirect = recorder<string>();
    const showToast = recorder<string>();
    const { onError } = requestOptions({
      redirect: redirect.fn,
      showToast: showToast.fn,
      returnTo: (path, search) => `/admin#${path}${search}`,
    });
    onError(apiError('unauthenticated', 401) as unknown as Error);
    expect(redirect.calls.length).toBe(1);
    expect(
      redirect.calls[0].startsWith('https://uc.example.com/sso/login?returnTo='),
    ).toBe(true);
    expect(redirect.calls[0]).toContain(encodeURIComponent('/admin#'));
    expect(showToast.calls.length).toBe(0);
  });

  test('401 未注入 returnTo → 裸登录地址（node 环境 alRoot 空串）', () => {
    const redirect = recorder<string>();
    requestOptions({ redirect: redirect.fn }).onError(
      apiError('internal', 401) as unknown as Error,
    );
    expect(redirect.calls).toEqual(['/sso/login']);
  });

  test('字段级 → onFieldError 行内，不弹 Toast', () => {
    const fieldCalls: Array<readonly [string, string]> = [];
    const showToast = recorder<string>();
    requestOptions({
      fieldByCode: { password_weak: 'password' },
      onFieldError: (field, message) => void fieldCalls.push([field, message]),
      showToast: showToast.fn,
    }).onError(apiError('password_weak') as unknown as Error);
    expect(fieldCalls.length).toBe(1);
    expect(fieldCalls[0][0]).toBe('password');
    expect(fieldCalls[0][1]).not.toBe('');
    expect(showToast.calls.length).toBe(0);
  });

  test('其余 → showToast；toast:false → 全部副作用零调用', () => {
    const showToast = recorder<string>();
    const redirect = recorder<string>();
    requestOptions({ showToast: showToast.fn, redirect: redirect.fn }).onError(
      apiError('internal', 500) as unknown as Error,
    );
    expect(showToast.calls.length).toBe(1);
    showToast.calls.length = 0;
    requestOptions({ toast: false, showToast: showToast.fn, redirect: redirect.fn }).onError(
      apiError('internal', 500) as unknown as Error,
    );
    expect(showToast.calls.length).toBe(0);
    expect(redirect.calls.length).toBe(0);
  });
});

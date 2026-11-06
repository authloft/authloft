// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化后移除）。
// @ts-ignore
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, rs, test } from 'rstack/test';
import * as React from 'react';
// 本仓 rstest 为 node 环境（无 DOM）：静态渲染走 react-dom/server 的
// renderToStaticMarkup（沿 register-reset.test.tsx 边界惯例），分派编排经
// dispatchCallback（依赖注入）+ msw wire 契约拦截 api 层覆盖；状态帧视图
// （OAuthCallbackView）可注入任意 status 帧（RegisterPageView 同款模式）。
import { renderToStaticMarkup } from 'react-dom/server';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { create } from '@bufbuild/protobuf';
import { clearLoginToken, getLoginToken } from '../loginTokenStore';
import {
  LoginFlowResponseSchema,
  MfaMethodSchema,
  MfaSchema,
  type LoginFlowResponse,
} from '../../gen/proto/api/sso/v1/envelope_pb';
import type { MethodsSnapshot } from '../../shared/types/init';
import { saveOidcContext } from '../oidcContext';

const { createElement } = React;

/**
 * al_root 在 transport（http.ts）模块求值时读 globalThis，故页面 / api 模块
 * 经 beforeAll 动态 import（沿 register-reset.test.tsx 模式）；BASE 与既有
 * 测试文件取同值防跨文件竞争。
 */
const BASE = 'https://uc.test';
(globalThis as { __AUTHLOFT_INIT__?: unknown }).__AUTHLOFT_INIT__ = {
  al_root: `${BASE}/`,
};

const LOGIN_OAUTH_URL = `${BASE}/api.sso.v1.SsoService/LoginOauth`;

const server = setupServer();

let pagesMod: typeof import('./OAuthCallbackPage');
let apiMod: typeof import('../api');

/** 内存版 Storage 桩（oidcContext 落盘目标；沿 api.test.ts）。 */
function fakeStorage(): Storage {
  const map = new Map<string, string>();
  return {
    get length() {
      return map.size;
    },
    clear: () => map.clear(),
    getItem: (key: string) => map.get(key) ?? null,
    key: (index: number) => [...map.keys()][index] ?? null,
    removeItem: (key: string) => {
      map.delete(key);
    },
    setItem: (key: string, value: string) => {
      map.set(key, value);
    },
  };
}

/** stub window（getInit 读 window.__AUTHLOFT_INIT__，两处同源；沿 api.test.ts）。 */
function stubWindow(): void {
  rs.stubGlobal('window', {
    localStorage: fakeStorage(),
    __AUTHLOFT_INIT__: (globalThis as { __AUTHLOFT_INIT__?: unknown })
      .__AUTHLOFT_INIT__,
  });
}

beforeAll(async () => {
  server.listen({ onUnhandledRequest: 'error' });
  pagesMod = await import('./OAuthCallbackPage');
  apiMod = await import('../api');
});

beforeEach(() => {
  // rstest 对 .tsx 走 classic JSX runtime：渲染前 stub 全局 React（仅测试进程）。
  rs.stubGlobal('React', React);
});

afterEach(() => {
  server.resetHandlers();
  rs.unstubAllGlobals();
  clearLoginToken(); // loginTokenStore 模块级变量跨用例复位
});

afterAll(() => {
  server.close();
  (globalThis as { __AUTHLOFT_INIT__?: unknown }).__AUTHLOFT_INIT__ = undefined;
});

// ---------------------------------------------------------------------------
// 测试数据（§1.3 信封 helper）
// ---------------------------------------------------------------------------

function envelope(init: Record<string, unknown>): LoginFlowResponse {
  return create(LoginFlowResponseSchema, init);
}

/**
 * mfa 分支经 LoginContainer 消费快照（完整编排）；其余状态帧不读快照，
 * 取空快照（mfa 分支不渲染 MethodTabs，空 methods 无影响）。
 */
const CALLBACK_SNAPSHOT: MethodsSnapshot = { methods: [] };

function renderView(
  init: { status: string; envelope?: LoginFlowResponse },
): string {
  return renderToStaticMarkup(
    createElement(pagesMod.OAuthCallbackView, {
      snapshot: CALLBACK_SNAPSHOT,
      status: init.status,
      envelope: init.envelope,
      onBackToLogin: () => {},
    }),
  );
}

// ---------------------------------------------------------------------------
// 纯函数：state 分派 / query 组装（§2.7.3 行 604-615）
// ---------------------------------------------------------------------------

describe('callbackDispatch（§2.7.3 行 606-610：l / b / 其他缺失）', () => {
  test('`l` 前缀 → login；`b` 前缀 → bind', () => {
    expect(pagesMod.callbackDispatch('l-abc123')).toBe('login');
    expect(pagesMod.callbackDispatch('b-xyz789')).toBe('bind');
    expect(pagesMod.callbackDispatch('l')).toBe('login');
    expect(pagesMod.callbackDispatch('b')).toBe('bind');
  });

  test('其他前缀 / 空串 → mismatch（视为 state_mismatch 跳登录）', () => {
    expect(pagesMod.callbackDispatch('x-abc')).toBe('mismatch');
    expect(pagesMod.callbackDispatch('L-abc')).toBe('mismatch'); // 大小写敏感
    expect(pagesMod.callbackDispatch('')).toBe('mismatch');
  });
});

describe('callbackQuery / buildLoginOauthInput（§2.7.3 行 604/612-615）', () => {
  test('query 原样解出（含 LoginOauth 未建模的键透传；键重复取首值）', () => {
    expect(pagesMod.callbackQuery('?code=c-1&state=l-s1&extra=e-1')).toEqual({
      code: 'c-1',
      state: 'l-s1',
      extra: 'e-1',
    });
    expect(pagesMod.callbackQuery('?a=1&a=2')).toEqual({ a: '1' });
    expect(pagesMod.callbackQuery('')).toEqual({});
  });

  test('providerKey 路径参数补上，且覆盖 query 同名（「补上路径参数」，行 604）', () => {
    expect(
      pagesMod.buildLoginOauthInput('qq', '?code=c-1&state=l-s1'),
    ).toEqual({ providerKey: 'qq', code: 'c-1', state: 'l-s1' });
    expect(
      pagesMod.buildLoginOauthInput('qq', '?code=c-1&providerKey=hack'),
    ).toEqual({ providerKey: 'qq', code: 'c-1' });
  });
});

// ---------------------------------------------------------------------------
// dispatchCallback 分派编排（§2.7.3 / §10.5 行 1541-1545）
// ---------------------------------------------------------------------------

describe('dispatchCallback 分派编排', () => {
  /** 记录型依赖桩（请求 / 信封 / 传输失败 / 占位 / 跳转逐项落账）。 */
  function recorder(result?: LoginFlowResponse | 'reject') {
    const calls = {
      requests: [] as unknown[],
      envelopes: [] as LoginFlowResponse[],
      transportErrors: 0,
      bindUnavailable: 0,
      navigations: [] as string[],
    };
    const deps = {
      loginOauthRequest: (req: unknown) => {
        calls.requests.push(req);
        if (result === 'reject') {
          return Promise.reject(new Error('transport'));
        }
        return Promise.resolve(result ?? envelope({ status: 'failed' }));
      },
      onEnvelope: (env: LoginFlowResponse) => calls.envelopes.push(env),
      onTransportError: () => {
        calls.transportErrors += 1;
      },
      onBindUnavailable: () => {
        calls.bindUnavailable += 1;
      },
      navigate: (url: string) => calls.navigations.push(url),
    };
    return { calls, deps };
  }

  test('state 非 l/b 前缀（x-1）→ 跳 /sso/login，不发请求不落帧（§2.7.3 行 610）', async () => {
    stubWindow();
    const { calls, deps } = recorder();
    await pagesMod.dispatchCallback(
      { providerKey: 'qq', search: '?code=c-1&state=x-1' },
      deps,
    );
    expect(calls.navigations).toEqual(['https://uc.test/sso/login']);
    expect(calls.requests).toHaveLength(0);
    expect(calls.envelopes).toHaveLength(0);
  });

  test('state 缺失 → 同 mismatch 跳 /sso/login（§2.7.3 行 610「其他 / 缺失」）', async () => {
    stubWindow();
    const { calls, deps } = recorder();
    await pagesMod.dispatchCallback(
      { providerKey: 'qq', search: '?code=c-1' },
      deps,
    );
    expect(calls.navigations).toEqual(['https://uc.test/sso/login']);
    expect(calls.requests).toHaveLength(0);
  });

  test('`b` 前缀 → 占位帧落地，不发请求不跳转（account 卡未交付）', async () => {
    stubWindow();
    const { calls, deps } = recorder();
    await pagesMod.dispatchCallback(
      { providerKey: 'qq', search: '?code=c-1&state=b-1' },
      deps,
    );
    expect(calls.bindUnavailable).toBe(1);
    expect(calls.requests).toHaveLength(0);
    expect(calls.navigations).toHaveLength(0);
  });

  test('`l` 前缀 → LoginOauth 携 query + providerKey；success 落帧后终点跳转', async () => {
    const { calls, deps } = recorder(
      envelope({ status: 'success', redirectTo: 'https://app.test/home' }),
    );
    await pagesMod.dispatchCallback(
      { providerKey: 'qq', search: '?code=c-1&state=l-1' },
      deps,
    );
    expect(calls.requests).toEqual([
      { providerKey: 'qq', code: 'c-1', state: 'l-1' },
    ]);
    expect(calls.envelopes).toHaveLength(1);
    expect(calls.envelopes[0].status).toBe('success');
    expect(calls.navigations).toEqual(['https://app.test/home']);
  });

  test('success 终点 syncCookieUrl 优先（§1.3 行 136）', async () => {
    const { calls, deps } = recorder(
      envelope({
        status: 'success',
        syncCookieUrl: 'https://sync.test/first',
        redirectTo: 'https://app.test/home',
      }),
    );
    await pagesMod.dispatchCallback(
      { providerKey: 'qq', search: '?code=c-1&state=l-1' },
      deps,
    );
    expect(calls.navigations).toEqual(['https://sync.test/first']);
  });

  test('success 双空终点 → 落帧不跳转（flowTerminalUrl 双空 ""）', async () => {
    const { calls, deps } = recorder(envelope({ status: 'success' }));
    await pagesMod.dispatchCallback(
      { providerKey: 'qq', search: '?code=c-1&state=l-1' },
      deps,
    );
    expect(calls.envelopes[0].status).toBe('success');
    expect(calls.navigations).toHaveLength(0);
  });

  test('mfa_required → 落帧不跳转（mfa 编排帧渲染交页面，§1.6 行 233；现为 LoginContainer 完整编排）', async () => {
    const { calls, deps } = recorder(
      envelope({ status: 'mfa_required', loginToken: 'lt-mfa' }),
    );
    await pagesMod.dispatchCallback(
      { providerKey: 'qq', search: '?code=c-1&state=l-1' },
      deps,
    );
    expect(calls.envelopes[0].status).toBe('mfa_required');
    expect(calls.navigations).toHaveLength(0);
  });

  test('传输层异常 → onTransportError（§1.6 行 272 failed 兜底）', async () => {
    const { calls, deps } = recorder('reject');
    await pagesMod.dispatchCallback(
      { providerKey: 'qq', search: '?code=c-1&state=l-1' },
      deps,
    );
    expect(calls.transportErrors).toBe(1);
    expect(calls.envelopes).toHaveLength(0);
    expect(calls.navigations).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// OAuthCallbackView 状态帧渲染（§4.4 行 467）
// ---------------------------------------------------------------------------

describe('OAuthCallbackView 状态帧渲染', () => {
  test('初始 / 请求在途 → 处理中提示（不渲染登录页 / 兜底文案）', () => {
    const markup = renderView({ status: 'idle' });
    expect(markup).toContain('正在处理，请稍候…');
    expect(markup).not.toContain('<h1>');
    expect(markup).toContain('role="status"');
  });

  test('bind 占位帧（b 分支）：提示「绑定功能即将上线」+ 返回登录（§4.4 行 467）', () => {
    const markup = renderView({ status: 'bind' });
    expect(markup).toContain('绑定功能即将上线');
    expect(markup).toContain('返回登录');
  });

  test('success 帧 → 登录成功跳转中文案', () => {
    const markup = renderView({
      status: 'success',
      envelope: envelope({ status: 'success', redirectTo: 'https://app/h' }),
    });
    expect(markup).toContain('登录成功，正在跳转…');
    expect(markup).not.toContain('返回登录');
  });

  test('binding_required 帧 → 原地渲染 BindingPage（§1.6 行 234：身份行 + 创建新账号）', () => {
    const markup = renderView({
      status: 'binding_required',
      envelope: envelope({
        status: 'binding_required',
        binding: { providerKey: 'qq', displayName: 'QQ', allowSignup: true },
      }),
    });
    expect(markup).toContain('QQ'); // BindingChoice 身份行
    expect(markup).toContain('创建新账号'); // BindingChoice 选项（allowSignup=true）
    expect(markup).not.toContain('正在处理');
  });

  test('mfa_required 帧 → LoginContainer 完整编排：MfaSelector 因子按钮 + 未选方式引导（§1.6 行 233「就地渲染、不跳页」）', () => {
    const markup = renderView({
      status: 'mfa_required',
      envelope: envelope({
        status: 'mfa_required',
        loginToken: 'lt-1',
        mfa: create(MfaSchema, {
          methods: [
            create(MfaMethodSchema, {
              method: 'totp',
              steps: ['form'],
            }),
            create(MfaMethodSchema, {
              method: 'otp_sms',
              steps: ['challenge', 'form'],
              maskedTarget: '138****8000',
            }),
          ],
        }),
      }),
    });
    expect(markup).toContain('动态口令'); // factors.totp（MfaSelector 按钮）
    expect(markup).toContain('短信验证码'); // factors.otp_sms
    expect(markup).toContain('请选择二次验证方式'); // login.mfaSelectHint（未选方式引导）
    expect(markup).not.toContain('正在处理'); // 非处理中帧
  });

  test('失败态（state_mismatch 响应）→ ErrorBanner（§1.6 表驱动）+ 返回登录', () => {
    const markup = renderView({
      status: 'state_mismatch',
      envelope: envelope({ status: 'state_mismatch' }),
    });
    expect(markup).toContain('role="alert"');
    expect(markup).toContain('返回登录');
  });

  test('失败态（failed 信封，error 兜底）→ ErrorBanner + 返回登录', () => {
    const markup = renderView({
      status: 'failed',
      envelope: envelope({ status: 'failed', error: { message: '服务异常' } }),
    });
    expect(markup).toContain('role="alert"');
    expect(markup).toContain('返回登录');
  });

  test('传输失败占位（envelope 缺失的 failed）→ ErrorBanner 渲染不炸（零值兜底）', () => {
    const markup = renderView({ status: 'failed' });
    expect(markup).toContain('role="alert"');
    expect(markup).toContain('返回登录');
  });
});

// ---------------------------------------------------------------------------
// 回调 wire 契约（msw 拦截 SsoService/LoginOauth；页面组装 × api 层注入端到端）
// ---------------------------------------------------------------------------

describe('回调 wire 契约（msw 拦截 SsoService/LoginOauth）', () => {
  test('query 原样上送 + providerKey 补上 + oidc 落盘读回即清（§2.7.3/§2.7.2 行 599-600）+ success 终点', async () => {
    stubWindow();
    saveOidcContext({
      client_id: 'cli',
      redirect_uri: 'https://app/cb',
      nonce: 'n-1',
    });
    let raw = '';
    server.use(
      http.post(LOGIN_OAUTH_URL, async ({ request }) => {
        raw = await request.text();
        return HttpResponse.json({
          status: 'success',
          redirectTo: 'https://app.test/home',
        });
      }),
    );

    const navigations: string[] = [];
    const envelopes: LoginFlowResponse[] = [];
    await pagesMod.dispatchCallback(
      { providerKey: 'qq', search: '?code=c-1&state=l-s1&extra=e-1' },
      {
        loginOauthRequest: apiMod.loginOauth,
        onEnvelope: (env) => envelopes.push(env),
        onTransportError: () => {},
        onBindUnavailable: () => {},
        navigate: (url) => navigations.push(url),
      },
    );

    // 请求报文（§2.7.3 行 612-615）：query 原样装进（组装层全量透传）；
    // wire 上 LoginOauthRequest 只序列化 §2.7.4 字段表建模字段，未建模键
    // （extra）由 proto 序列化丢弃（§12.9 proto 唯一真相，报告记裁量）。
    expect(JSON.parse(raw)).toEqual({
      providerKey: 'qq',
      code: 'c-1',
      state: 'l-s1',
      oidc: { client_id: 'cli', redirect_uri: 'https://app/cb', nonce: 'n-1' },
    });
    expect(window.localStorage.getItem('al_oidc_ctx')).toBeNull(); // 读完即清
    expect(envelopes[0].status).toBe('success');
    expect(navigations).toEqual(['https://app.test/home']); // 终点跳转（success）
    expect(getLoginToken()).toBe(''); // success 清空（api 层 applyEnvelope）
  });
});

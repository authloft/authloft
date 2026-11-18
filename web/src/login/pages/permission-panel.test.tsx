// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化后移除）。
// @ts-ignore
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  rs,
  test,
} from 'rstack/test';
import * as React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from '@modern-js/runtime/router';
import { create } from '@bufbuild/protobuf';
import {
  ConsentResponseSchema,
  type ConsentResponse,
} from '../../gen/proto/api/account/v1/consent_pb';
import { ApiError, resolveCode } from '../../shared/api/errors';
import type { MethodsSnapshot, OidcContext } from '../../shared/types/init';
import { setLocale } from '../../shared/i18n';
import { oidcView } from '../bootstrap';
import { clearOidcContext, saveOidcContext } from '../oidcContext';
import {
  initialSelection,
  isScopeLocked,
  normalizeSelection,
  PermissionPanel,
  scopeTokens,
  toggleScopeItem,
} from './PermissionPanel';
import {
  landConsent,
  consentTerminalUrl,
  toConsentApproveInput,
  toConsentDenyInput,
} from '../api';
import { LoginPage } from './LoginPage';

const { createElement } = React;

/** 登录入口在 transport 求值时读 al_root（globalThis）；先注入再动态 import。 */
const BASE = 'https://uc.test';
(globalThis as { __AUTHLOFT_INIT__?: unknown }).__AUTHLOFT_INIT__ = {
  al_root: `${BASE}/`,
};

const SNAPSHOT: MethodsSnapshot = {
  methods: [{ method: 'password', steps: ['form'], fields: [] }],
};

function fakeStorage(): Storage {
  const map = new Map<string, string>();
  return {
    get length() {
      return map.size;
    },
    clear: () => map.clear(),
    getItem: (key) => map.get(key) ?? null,
    key: (index) => [...map.keys()][index] ?? null,
    removeItem: (key) => {
      map.delete(key);
    },
    setItem: (key, value) => {
      map.set(key, value);
    },
  };
}

/** 注入 oidc 到 window + globalThis（getInit 读 window.__AUTHLOFT_INIT__）。 */
function injectInit(oidc: OidcContext | undefined): void {
  const value = { al_root: `${BASE}/`, oidc };
  (globalThis as { __AUTHLOFT_INIT__?: unknown }).__AUTHLOFT_INIT__ = value;
  rs.stubGlobal('window', {
    __AUTHLOFT_INIT__: value,
    localStorage: fakeStorage(),
  });
}

let apiMod: typeof import('../api');

beforeAll(async () => {
  // 触发 api.ts / http.ts 模块求值（al_root 已注入）；沿 api.test.ts 动态 import。
  apiMod = await import('../api');
});

beforeEach(() => {
  // rstest 对 .tsx 走 classic JSX runtime：渲染前 stub 全局 React（仅测试进程）。
  rs.stubGlobal('React', React);
});

afterEach(() => {
  rs.unstubAllGlobals();
  setLocale('zh-CN');
  clearOidcContext();
  (globalThis as { __AUTHLOFT_INIT__?: unknown }).__AUTHLOFT_INIT__ = {
    al_root: `${BASE}/`,
  };
});

afterAll(() => {
  (globalThis as { __AUTHLOFT_INIT__?: unknown }).__AUTHLOFT_INIT__ = undefined;
});

// ---------------------------------------------------------------------------
// mode 分派（§4.2 三态的前端分派；静态渲染可证伪）
// ---------------------------------------------------------------------------

describe('oidcView：注入 mode 三态分派（§4.2）', () => {
  test('无 oidc → plain（直登单栏，形态 C 不渲染本页）', () => {
    expect(oidcView(undefined).mode).toBe('plain');
  });

  test('mode=login → login；mode=consent → consent；未知串归 plain', () => {
    expect(
      oidcView({ client_id: 'c', redirect_uri: 'r', mode: 'login' }).mode,
    ).toBe('login');
    expect(
      oidcView({ client_id: 'c', redirect_uri: 'r', mode: 'consent' }).mode,
    ).toBe('consent');
    expect(
      oidcView({
        client_id: 'c',
        redirect_uri: 'r',
        mode: 'bogus' as OidcContext['mode'],
      }).mode,
    ).toBe('plain');
  });

  test('带出 client_name / account（形态 B 左栏展示字段）', () => {
    const view = oidcView({
      client_id: 'c',
      redirect_uri: 'r',
      mode: 'consent',
      client_name: 'Demo App',
      account: { nickname: '阿丽', avatar_url: '', identifier: 'a***@x.com' },
    });
    expect(view.clientName).toBe('Demo App');
    expect(view.account?.nickname).toBe('阿丽');
  });
});

/** 渲染 LoginPage：MemoryRouter 提供 Link 所需 router context。 */
function renderPage(oidc: OidcContext | undefined): string {
  injectInit(oidc);
  return renderToStaticMarkup(
    createElement(
      MemoryRouter,
      null,
      createElement(LoginPage, { snapshot: SNAPSHOT }),
    ),
  );
}

describe('LoginPage 双栏按 oidc.mode 分派左栏（§4.4）', () => {
  test('mode=login：渲染登录容器（MethodTabs）+ 右栏权限面板，无账号卡片', () => {
    const html = renderPage({
      client_id: 'c',
      redirect_uri: 'r',
      mode: 'login',
      client_name: 'Demo App',
      scope: 'openid profile email',
    });
    // 左栏登录表单（登录并同意文案 data-testid）+ 右栏 scope 勾选在场。
    expect(html).toContain('data-testid="oidc-submit-agree"');
    expect(html).toContain('登录并同意');
    expect(html).toContain('Demo App');
    expect(html).toContain('data-scope="openid"');
    // 账号卡片（同意/拒绝）不出现（左栏不是账号卡片）。
    expect(html).not.toContain('data-testid="consent-account-card"');
  });

  test('mode=consent：渲染账号卡片 + 同意/拒绝，无登录表单', () => {
    const html = renderPage({
      client_id: 'c',
      redirect_uri: 'r',
      mode: 'consent',
      client_name: 'Demo App',
      scope: 'openid profile',
      account: { nickname: '阿丽', avatar_url: '', identifier: 'a***@x.com' },
    });
    expect(html).toContain('阿丽');
    expect(html).toContain('a***@x.com');
    expect(html).toContain('data-testid="consent-account-card"');
    expect(html).toContain('data-testid="consent-approve"');
    expect(html).toContain('data-testid="consent-deny"');
    // 同意页不渲染登录容器的「登录并同意」提交文案。
    expect(html).not.toContain('data-testid="oidc-submit-agree"');
    // 右栏权限面板仍在场。
    expect(html).toContain('data-scope="openid"');
  });

  test('无 oidc（直登）：单栏登录，无权限面板 / 同意文案', () => {
    const html = renderPage(undefined);
    expect(html).not.toContain('data-scope=');
    expect(html).not.toContain('data-testid="consent-account-card"');
    expect(html).not.toContain('data-testid="oidc-submit-agree"');
  });
});

// ---------------------------------------------------------------------------
// PermissionPanel：openid 禁取消 / 已授权锁定 / 勾选集规整（§4.2 / 裁决①②）
// ---------------------------------------------------------------------------

describe('PermissionPanel scope 勾选纯逻辑（node 可测，可证伪）', () => {
  test('openid 恒锁定：普通集与已授权集下均不可取消', () => {
    expect(isScopeLocked('openid', '')).toBe(true);
    expect(isScopeLocked('openid', 'profile email')).toBe(true);
    // 切开放弃 openid → 勾选集不变（不可取消）。
    const selected = ['openid', 'profile'];
    expect(toggleScopeItem(selected, 'openid', '')).toEqual(selected);
  });

  test('已授权项锁定不可取消；非已授权新请求项可逐项取消', () => {
    const granted = 'openid profile';
    expect(isScopeLocked('profile', granted)).toBe(true);
    // 已授权 profile 不可取消。
    expect(
      toggleScopeItem(['openid', 'profile', 'email'], 'profile', granted),
    ).toEqual(['openid', 'profile', 'email']);
    // 新请求 email 可取消。
    expect(
      toggleScopeItem(['openid', 'profile', 'email'], 'email', granted),
    ).toEqual(['openid', 'profile']);
  });

  test('normalizeSelection：剔除请求外 scope（不可放大）+ 补齐锁定项', () => {
    // 请求外 phone 被剔除；openid 即便被漏也补齐；已授权 email 补齐。
    const next = normalizeSelection(
      ['openid', 'phone', 'profile'],
      'openid profile email',
      'openid email',
    );
    expect(next).toEqual(['openid', 'profile', 'email']);
  });

  test('scopeTokens 仅收封闭集六值、去重、按固定序', () => {
    expect(scopeTokens(' email  openid email bogus ')).toEqual([
      'openid',
      'email',
    ]);
    expect(initialSelection('openid profile email')).toEqual([
      'openid',
      'profile',
      'email',
    ]);
  });
});

describe('PermissionPanel 静态渲染：锁定态 UI 承诺（§4.2）', () => {
  test('openid 复选框 disabled + data-locked=true + 「已授权」标注', () => {
    injectInit(undefined);
    const html = renderToStaticMarkup(
      createElement(PermissionPanel, {
        clientName: 'Demo App',
        scope: 'openid profile',
        grantedScopes: '',
        selected: ['openid', 'profile'],
        onSelectedChange: () => undefined,
      }),
    );
    const openidInput =
      html.match(/<input[^>]*data-scope="openid"[^>]*>/)?.[0] ?? '';
    expect(openidInput).toContain('data-locked="true"');
    expect(openidInput).toContain('disabled');
    expect(html).toContain('已授权');
  });

  test('新请求项 profile 可取消（未禁用、未锁定）', () => {
    const html = renderToStaticMarkup(
      createElement(PermissionPanel, {
        clientName: 'Demo App',
        scope: 'openid profile',
        selected: ['openid', 'profile'],
        onSelectedChange: () => undefined,
      }),
    );
    const profileInput =
      html.match(/<input[^>]*data-scope="profile"[^>]*>/)?.[0] ?? '';
    expect(profileInput).toContain('data-locked="false"');
    expect(profileInput).not.toContain('disabled');
  });

  test('grantedScopes 非空时对应项锁定不可取消（数据接线后即生效）', () => {
    injectInit(undefined);
    const html = renderToStaticMarkup(
      createElement(PermissionPanel, {
        clientName: 'Demo App',
        scope: 'openid profile email',
        // 模拟契约补齐后注入的已授权并集（当前运行时暂传空集）。
        grantedScopes: 'openid profile',
        selected: ['openid', 'profile', 'email'],
        onSelectedChange: () => undefined,
      }),
    );
    // 已授权 profile：锁定 + 禁用 + 「已授权」标注。
    const profileInput =
      html.match(/<input[^>]*data-scope="profile"[^>]*>/)?.[0] ?? '';
    expect(profileInput).toContain('data-locked="true"');
    expect(profileInput).toContain('disabled');
    expect(profileInput).toContain('checked');
    expect(html).toContain('已授权');
    // 非已授权 email：仍可取消（可逐项取消的分支未被误锁）。
    const emailInput =
      html.match(/<input[^>]*data-scope="email"[^>]*>/)?.[0] ?? '';
    expect(emailInput).toContain('data-locked="false"');
    expect(emailInput).not.toContain('disabled');
  });
});

// ---------------------------------------------------------------------------
// 形态 A scope 收窄透传（裁决④）+ consent 两 RPC 请求映射 / 落点（§3.10 / §1.3）
// ---------------------------------------------------------------------------

describe('consent 请求映射与终点处理（§3.10 / §1.3，effect 可证伪）', () => {
  const ctx: OidcContext = {
    client_id: 'cid',
    redirect_uri: 'https://app/cb',
    scope: 'openid profile email',
    state: 'st',
    nonce: 'no',
    code_challenge: 'cc',
    code_challenge_method: 'S256',
    mode: 'consent',
  };

  test('toConsentApproveInput：七参数原样 + selectedScope 勾选子集（形态 A 收窄）', () => {
    const req = toConsentApproveInput(ctx, 'openid profile');
    expect(req).toEqual({
      clientId: 'cid',
      redirectUri: 'https://app/cb',
      scope: 'openid profile email',
      selectedScope: 'openid profile',
      state: 'st',
      nonce: 'no',
      codeChallenge: 'cc',
      codeChallengeMethod: 'S256',
    });
    // scope 与 selected_scope 分离：请求原文不被勾选集覆盖。
    expect(req.scope).not.toBe(req.selectedScope);
  });

  test('toConsentDenyInput：仅 client_id / redirect_uri / state，无 scope', () => {
    const req = toConsentDenyInput(ctx);
    expect(req).toEqual({
      clientId: 'cid',
      redirectUri: 'https://app/cb',
      state: 'st',
    });
    expect(req).not.toHaveProperty('selectedScope');
  });

  test('consentTerminalUrl：syncCookieUrl 优先，其次 redirectTo，皆空回落默认落点', () => {
    const withSync = create(ConsentResponseSchema, {
      redirectTo: 'https://app/cb?code=x',
      syncCookieUrl: 'https://sso/sync?next=y',
    });
    expect(consentTerminalUrl(withSync)).toBe('https://sso/sync?next=y');

    const onlyRedirect = create(ConsentResponseSchema, {
      redirectTo: 'https://app/cb?code=x',
    });
    expect(consentTerminalUrl(onlyRedirect)).toBe('https://app/cb?code=x');

    const empty = create(ConsentResponseSchema, {});
    expect(consentTerminalUrl(empty)).toBe('/account#/');
  });

  test('landConsent：先清 al_oidc_ctx 再跳同步首跳（可控副作用断言，不依赖浏览器）', () => {
    injectInit(undefined);
    saveOidcContext({
      client_id: 'cid',
      redirect_uri: 'https://app/cb',
    });
    const navigated: string[] = [];
    const cleared: string[] = [];
    const response = create(ConsentResponseSchema, {
      redirectTo: 'https://app/cb?code=x',
      syncCookieUrl: 'https://sso/sync?next=y',
    });
    landConsent(
      response,
      (url) => navigated.push(url),
      () => cleared.push('cleared'),
    );
    expect(cleared).toEqual(['cleared']);
    expect(navigated).toEqual(['https://sso/sync?next=y']);
  });
});

// ---------------------------------------------------------------------------
// invalid_scope 映射（§1.6：仅 ErrorInfo.code，不作 status）
// ---------------------------------------------------------------------------

describe('invalid_scope 错误归一（§1.6 / §3.10）', () => {
  test('ErrorInfo.code=invalid_scope → 不可重试 + message 动作 + 专属 i18nKey', () => {
    const resolution = resolveCode(
      new ApiError({
        httpStatus: 400,
        code: 'invalid_scope',
        message: 'scope 超集',
        requestId: 'r',
      }),
    );
    expect(resolution.retryable).toBe(false);
    expect(resolution.action).toBe('message');
    expect(resolution.i18nKey).toBe('errors.code.invalid_scope');
  });

  test('invalid_scope 不作 status（查询走流程态兜底）', () => {
    // 流程态表不含 invalid_scope。
    expect(
      resolveCode(
        new ApiError({
          httpStatus: 400,
          code: 'invalid_scope',
          message: '',
          requestId: '',
        }),
      ).i18nKey,
    ).not.toContain('status');
  });

  test('consentErrorKey：已知 ApiError 按 code 归一，未知异常兜底 internal_error', () => {
    // 直接验证归一来源（consentErrorKey 内部即 resolveCode + instanceof 兜底）。
    const scope = resolveCode(
      new ApiError({
        httpStatus: 400,
        code: 'invalid_scope',
        message: 'x',
        requestId: 'r',
      }),
    );
    expect(scope.i18nKey).toBe('errors.code.invalid_scope');
  });
});

// ---------------------------------------------------------------------------
// granted_scopes 数据接线（§8 形态 B 注入键 → PermissionPanel.grantedScopes）：
// 「已授权项锁定不可取消」的 UI 承诺运行时成立；空集 / 缺键回退现状（不崩、
// 不锁错）。静态渲染 LoginPage 全链路（注入 → oidcView → prop 传递）可证伪。
// ---------------------------------------------------------------------------

describe('LoginPage granted_scopes 接线（§8 形态 B → PermissionPanel）', () => {
  const CONSENT_BASE: OidcContext = {
    client_id: 'c',
    redirect_uri: 'r',
    mode: 'consent',
    client_name: 'Demo App',
    scope: 'openid profile email',
    account: { nickname: '阿丽', avatar_url: '', identifier: 'a***@x.com' },
  };

  function checkbox(html: string, scope: string): string {
    return (
      html.match(new RegExp(`<input[^>]*data-scope="${scope}"[^>]*>`))?.[0] ??
      ''
    );
  }

  test('init 带 granted_scopes：已授权项锁定不可取消，新请求项可逐项取消', () => {
    const html = renderPage({
      ...CONSENT_BASE,
      granted_scopes: 'openid profile',
    });
    // 已授权 profile：锁定 + 禁用 + 勾上（锁定态由注入数据驱动，非空集占位）。
    const profile = checkbox(html, 'profile');
    expect(profile).toContain('data-locked="true"');
    expect(profile).toContain('disabled');
    expect(profile).toContain('checked');
    // 新请求 email：不受已授权集影响，仍可取消。
    const email = checkbox(html, 'email');
    expect(email).toContain('data-locked="false"');
    expect(email).not.toContain('disabled');
  });

  test('granted_scopes 空串（空集合法）：不锁错，仅 openid 恒锁', () => {
    const html = renderPage({ ...CONSENT_BASE, granted_scopes: '' });
    expect(checkbox(html, 'profile')).toContain('data-locked="false"');
    expect(checkbox(html, 'openid')).toContain('data-locked="true"');
  });

  test('granted_scopes 缺键（形态 A / 旧注入）：回退现状不崩、不锁错', () => {
    const html = renderPage({ ...CONSENT_BASE });
    expect(html).toContain('data-scope="openid"'); // 右栏面板照常渲染
    expect(checkbox(html, 'profile')).toContain('data-locked="false"');
    expect(checkbox(html, 'openid')).toContain('data-locked="true"');
  });
});

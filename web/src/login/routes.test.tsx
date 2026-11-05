// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化后移除）。
// @ts-ignore
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, rs, test } from 'rstack/test';
import * as React from 'react';
// 本仓 rstest 为 node 环境（无 DOM）：静态渲染走 react-dom/server 的
// renderToStaticMarkup（沿 login-container.test.tsx 边界惯例），路由
// / flags 可见性均为纯渲染断言，交互在容器层测试覆盖。
import { renderToStaticMarkup } from 'react-dom/server';
import type { MethodsSnapshot } from '../shared/types/init';

const { createElement } = React;

/**
 * al_root 在 transport（http.ts）模块求值时读 globalThis，故 ./routes
 *（→ LoginPage → LoginContainer → api → shared/api/http 链）经 beforeAll
 * 动态 import（沿 login-container.test.tsx 模式）；注入快照（methods /
 * oidc）由 getInit 读 window.__AUTHLOFT_INIT__（shared/types/init.ts），
 * 用例内 stub window 提供变体；两处同源。
 */
const BASE = 'https://uc.test';
(globalThis as { __AUTHLOFT_INIT__?: unknown }).__AUTHLOFT_INIT__ = {
  al_root: `${BASE}/`,
};

let routesMod: typeof import('./routes');
let bootstrapMod: typeof import('./bootstrap');
let pagesMod: typeof import('./pages/LoginPage');

beforeAll(async () => {
  routesMod = await import('./routes');
  bootstrapMod = await import('./bootstrap');
  pagesMod = await import('./pages/LoginPage');
});

beforeEach(() => {
  // rstest 对 .tsx 走 classic JSX runtime：渲染前 stub 全局 React（仅测试进程）。
  rs.stubGlobal('React', React);
});

afterEach(() => {
  rs.unstubAllGlobals();
});

afterAll(() => {
  (globalThis as { __AUTHLOFT_INIT__?: unknown }).__AUTHLOFT_INIT__ = undefined;
});

// ---------------------------------------------------------------------------
// 测试数据（§2.1 行 382-388 注入结构的最小形状）
// ---------------------------------------------------------------------------

const PASSWORD_METHOD = {
  method: 'password',
  usage: ['primary'],
  steps: ['form'],
  fields: [
    {
      name: 'username',
      label: '用户名/邮箱/手机号',
      type: 'text',
      required: true,
    },
    { name: 'password', label: '密码', type: 'password', required: true },
  ],
};

function makeSnapshot(
  flags?: { passwordReset?: boolean; registration?: boolean },
): MethodsSnapshot {
  return { flags, methods: [PASSWORD_METHOD] };
}

/** stub window（路由 pathname + 注入块；§8 白名单字段）。 */
function stubWindow(pathname: string, init: unknown): void {
  rs.stubGlobal('window', {
    location: { pathname },
    __AUTHLOFT_INIT__: init,
  });
}

function renderLoginApp(pathname: string, init: unknown): string {
  stubWindow(pathname, init);
  return renderToStaticMarkup(createElement(routesMod.LoginApp));
}

// ---------------------------------------------------------------------------
// bootstrap：loadLoginBootstrap / normalizeStaticBase（§4.1 行 375 / §1.5 行 99）
// ---------------------------------------------------------------------------

describe('bootstrap（§4.1 行 375 / §1.5 行 98-99）', () => {
  test('注入块未下发 → ok:false（§8：methods 必填，无回退接口）', () => {
    stubWindow('/sso/login', undefined);
    expect(bootstrapMod.loadLoginBootstrap()).toEqual({ ok: false });
  });

  test('注入块无 methods 键 → ok:false（缺失即服务端故障）', () => {
    stubWindow('/sso/login', { al_root: BASE, static_base: '/assets/' });
    expect(bootstrapMod.loadLoginBootstrap()).toEqual({ ok: false });
  });

  test('methods 存在、无 oidc → ok:true 且不带 oidc（§8：oidc 可选）', () => {
    const snapshot = makeSnapshot();
    stubWindow('/sso/login', {
      al_root: BASE,
      static_base: '/assets/',
      methods: snapshot,
    });
    expect(bootstrapMod.loadLoginBootstrap()).toEqual({
      ok: true,
      snapshot,
    });
  });

  test('methods + oidc 均存在 → ok:true 且 oidc 原样带出（§8：/auth/authorize 渲染时注入）', () => {
    const snapshot = makeSnapshot();
    const oidc = {
      client_id: 'cli',
      redirect_uri: 'https://app.test/cb',
      state: 's0',
    };
    stubWindow('/auth/authorize', {
      al_root: BASE,
      static_base: '/assets/',
      methods: snapshot,
      oidc,
    });
    expect(bootstrapMod.loadLoginBootstrap()).toEqual({
      ok: true,
      snapshot,
      oidc,
    });
  });

  test('normalizeStaticBase：缺省 / 空白 → /assets/（§1.5 行 99 缺省值）', () => {
    expect(bootstrapMod.normalizeStaticBase(undefined)).toBe('/assets/');
    expect(bootstrapMod.normalizeStaticBase('')).toBe('/assets/');
    expect(bootstrapMod.normalizeStaticBase('   ')).toBe('/assets/');
  });

  test('normalizeStaticBase：补尾斜杠；CDN 绝对地址同口径（§1.5 行 99）', () => {
    expect(bootstrapMod.normalizeStaticBase('/assets')).toBe('/assets/');
    expect(bootstrapMod.normalizeStaticBase('/assets/')).toBe('/assets/');
    expect(bootstrapMod.normalizeStaticBase('https://cdn.example.com/static')).toBe(
      'https://cdn.example.com/static/',
    );
  });
});

// ---------------------------------------------------------------------------
// routes：methods 缺失错误态 + 路由分派（§4.1 行 376 / §1.4 行 81）
// ---------------------------------------------------------------------------

describe('LoginApp：bootstrap 错误态与路由分派（§4.1 行 374-376）', () => {
  test('methods 缺失 → 渲染错误态并提示刷新（§1.5 行 98：无回退接口）', () => {
    const html = renderLoginApp('/sso/login', {
      al_root: BASE,
      static_base: '/assets/',
    });
    expect(html).toContain('初始化数据缺失，请刷新重试');
    expect(html).not.toContain('<h1>');
  });

  test('/sso/login → LoginPage：组装 LoginContainer（含 MethodTabs 的方式列表）', () => {
    const html = renderLoginApp('/sso/login', {
      al_root: BASE,
      static_base: '/assets/',
      methods: makeSnapshot({ passwordReset: false, registration: false }),
    });
    expect(html).toContain('<h1>登录</h1>');
    // 容器视图（LoginFlowView）内嵌 MethodTabs 的方式名（factors.password）。
    expect(html).toContain('密码登录');
    // flags 全 false → 入口不渲染（§2.1 行 407）。
    expect(html).not.toContain('忘记密码');
    expect(html).not.toContain('注册');
  });

  test('/auth/authorize → 同一 LoginPage（§4.4 行 447：OIDC 授权页即登录页）', () => {
    const html = renderLoginApp('/auth/authorize', {
      al_root: BASE,
      static_base: '/assets/',
      methods: makeSnapshot({ passwordReset: true, registration: true }),
      oidc: { client_id: 'cli', redirect_uri: 'https://app.test/cb' },
    });
    expect(html).toContain('<h1>登录</h1>');
    expect(html).toContain('密码登录');
    // flags 驱动入口可见（含禁用占位，不实现跳转）。
    expect(html).toContain('忘记密码');
    expect(html).toContain('注册');
  });

  test('尾斜杠归一：/sso/login/ 与 /sso/login 同页', () => {
    const html = renderLoginApp('/sso/login/', {
      al_root: BASE,
      static_base: '/assets/',
      methods: makeSnapshot(),
    });
    expect(html).toContain('<h1>登录</h1>');
  });

  test('未注册路由（/sso/unknown）→ 兜底提示，不渲染登录页', () => {
    const html = renderLoginApp('/sso/unknown', {
      al_root: BASE,
      static_base: '/assets/',
      methods: makeSnapshot(),
    });
    expect(html).toContain('页面不存在');
    expect(html).not.toContain('<h1>登录</h1>');
  });

  test('/sso/oauth/callback/qq → OAuthCallbackPage 处理中首帧（静态渲染不跑分派副作用）', () => {
    const html = renderLoginApp('/sso/oauth/callback/qq', {
      al_root: BASE,
      static_base: '/assets/',
      methods: makeSnapshot(),
    });
    expect(html).toContain('正在处理，请稍候…');
    expect(html).not.toContain('<h1>登录</h1>');
    expect(html).not.toContain('页面不存在');
  });

  test('尾斜杠归一：/sso/oauth/callback/qq/ 同回调页', () => {
    const html = renderLoginApp('/sso/oauth/callback/qq/', {
      al_root: BASE,
      static_base: '/assets/',
      methods: makeSnapshot(),
    });
    expect(html).toContain('正在处理，请稍候…');
  });

  test('缺 provider_key（/sso/oauth/callback）→ 兜底提示，不渲染回调页', () => {
    const html = renderLoginApp('/sso/oauth/callback', {
      al_root: BASE,
      static_base: '/assets/',
      methods: makeSnapshot(),
    });
    expect(html).toContain('页面不存在');
    expect(html).not.toContain('正在处理');
  });

  test('多段路径（/sso/oauth/callback/qq/extra）→ 不匹配，兜底提示', () => {
    const html = renderLoginApp('/sso/oauth/callback/qq/extra', {
      al_root: BASE,
      static_base: '/assets/',
      methods: makeSnapshot(),
    });
    expect(html).toContain('页面不存在');
  });
});

// ---------------------------------------------------------------------------
// LoginPage：flags 驱动入口可见性（§4.4 行 447 / 接口文档 §2.1 行 374-377）
// ---------------------------------------------------------------------------

describe('LoginPage：flags 驱动「忘记密码」「注册」入口可见性（§2.1）', () => {
  function renderPage(
    flags?: { passwordReset?: boolean; registration?: boolean },
  ): string {
    // LoginPage 纯组装（不读 window），直接渲染。
    stubWindow('/sso/login', undefined);
    return renderToStaticMarkup(
      createElement(pagesMod.LoginPage, { snapshot: makeSnapshot(flags) }),
    );
  }

  test('flags 缺省（零值兜底）→ 两入口均不渲染', () => {
    const html = renderPage(undefined);
    expect(html).not.toContain('忘记密码');
    expect(html).not.toContain('注册');
  });

  test('passwordReset=true / registration=false → 仅「忘记密码」', () => {
    const html = renderPage({ passwordReset: true, registration: false });
    expect(html).toContain('忘记密码');
    expect(html).not.toContain('注册');
  });

  test('passwordReset=false / registration=true → 仅「注册」', () => {
    const html = renderPage({ passwordReset: false, registration: true });
    expect(html).not.toContain('忘记密码');
    expect(html).toContain('注册');
  });

  test('两 flag 均 true → 两入口为真链接（window 未注入 → 同源根路径）', () => {
    const html = renderPage({ passwordReset: true, registration: true });
    expect(html).toContain('忘记密码');
    expect(html).toContain('注册');
    // 入口是 <a href>（原禁用占位按钮已激活，§4.4 行 463）。
    expect(html).toContain('href="/sso/reset"');
    expect(html).toContain('href="/sso/register"');
  });
});

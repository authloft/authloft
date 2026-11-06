// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化落地后移除）。
// @ts-ignore
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, rs, test } from 'rstack/test';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { clearLoginToken, getLoginToken, setLoginToken } from './loginTokenStore';
import { saveOidcContext } from './oidcContext';

/**
 * 在模块求值前注入 al_root + oidc 快照（transport 与 api.ts 的 oidc 源都在
 * 模块加载时 / 运行时读取），故 ./api 经 beforeAll 动态 import（沿
 * shared/api http.test.ts 与 setup/api.test.ts 模式）；单测环境为 node，
 * BASE 与既有两文件取同值防跨文件竞争。
 */
const BASE = 'https://uc.test';
(globalThis as { __AUTHLOFT_INIT__?: unknown }).__AUTHLOFT_INIT__ = {
  al_root: `${BASE}/`,
  oidc: { client_id: 'cid', redirect_uri: 'https://app/cb', state: 'st' },
};

const SSO = `${BASE}/api.sso.v1.SsoService`;
const LOGIN_DEFAULT = `${SSO}/LoginDefault`;
const REGISTER = `${SSO}/Register`;
const RESET_PASSWORD = `${SSO}/ResetPassword`;
const LOGIN_OAUTH = `${SSO}/LoginOauth`;
const AUTHORIZE = `${SSO}/Authorize`;
const QRCODE = `${SSO}/CreateQrcode`;
const LOGIN_TICKET = `${SSO}/GetLoginTicket`;

const server = setupServer();

let mod: typeof import('./api');

/** 内存版 Storage 桩（oidcContext 落盘目标）。 */
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

beforeAll(async () => {
  server.listen({ onUnhandledRequest: 'error' });
  mod = await import('./api');
});

beforeEach(() => {
  // stub window 时保留 __AUTHLOFT_INIT__（getInit 读 window.__AUTHLOFT_INIT__，
  // shared/types/init.ts；transport baseUrl 读 globalThis——两处同源）。
  rs.stubGlobal('window', {
    localStorage: fakeStorage(),
    __AUTHLOFT_INIT__: (globalThis as { __AUTHLOFT_INIT__?: unknown })
      .__AUTHLOFT_INIT__,
  });
});

afterEach(() => {
  server.resetHandlers();
  rs.unstubAllGlobals();
  clearLoginToken(); // 模块级变量跨用例复位
});

afterAll(() => {
  server.close();
  (globalThis as { __AUTHLOFT_INIT__?: unknown }).__AUTHLOFT_INIT__ = undefined;
});

describe('loginDefault（§2.2）loginToken / oidc 注入与信封后处理（§1.8 / §1.3 行 145）', () => {
  test('首次请求（无 token）：请求体零值省略 loginToken，注入快照 oidc（§2.2 行 425）', async () => {
    let raw = '';
    server.use(
      http.post(LOGIN_DEFAULT, async ({ request }) => {
        raw = await request.text();
        return HttpResponse.json({ status: 'next' });
      }),
    );

    const response = await mod.loginDefault({
      method: 'password',
      step: 'verify',
      payload: { username: 'alice', password: 'pw' },
    });

    expect(response.status).toBe('next');
    expect(JSON.parse(raw)).toEqual({
      method: 'password',
      step: 'verify',
      payload: { username: 'alice', password: 'pw' },
      oidc: { client_id: 'cid', redirect_uri: 'https://app/cb', state: 'st' },
    }); // loginToken 零值 '' → protojson 省略（§1.1）
  });

  test('已有 token：loginToken 顶层注入，不再带 oidc（仅首次请求回传，§2.2 行 425）', async () => {
    setLoginToken('tok-1');
    let raw = '';
    server.use(
      http.post(LOGIN_DEFAULT, async ({ request }) => {
        raw = await request.text();
        return HttpResponse.json({ status: 'next', loginToken: 'tok-2' });
      }),
    );

    await mod.loginDefault({
      method: 'otp_email',
      step: 'challenge',
      payload: { email: 'a@b.com' },
    });

    expect(JSON.parse(raw)).toEqual({
      loginToken: 'tok-1',
      method: 'otp_email',
      step: 'challenge',
      payload: { email: 'a@b.com' },
    });
  });

  test('响应含 loginToken 无条件覆盖内存变量（五条之 2），后续请求带新值', async () => {
    server.use(
      http.post(LOGIN_DEFAULT, () =>
        HttpResponse.json({ status: 'next', loginToken: 'tok-2' }),
      ),
    );
    await mod.loginDefault({ method: 'password', step: 'verify', payload: {} });
    expect(getLoginToken()).toBe('tok-2'); // 覆盖

    let raw = '';
    server.use(
      http.post(LOGIN_DEFAULT, async ({ request }) => {
        raw = await request.text();
        return HttpResponse.json({ status: 'next' });
      }),
    );
    await mod.loginDefault({ method: 'password', step: 'verify', payload: {} });
    expect(JSON.parse(raw)).toHaveProperty('loginToken', 'tok-2');
  });

  test('status=success → 清空内存变量（五条之 3；§1.3 行 108 success 不再返回）', async () => {
    setLoginToken('tok-1');
    server.use(
      http.post(LOGIN_DEFAULT, () =>
        HttpResponse.json({ status: 'success', redirectTo: '/home' }),
      ),
    );
    const response = await mod.loginDefault({
      method: 'password',
      step: 'verify',
      payload: {},
    });
    expect(response.status).toBe('success');
    expect(getLoginToken()).toBe('');
  });
});

describe('register / resetPassword（§2.3 / §2.4，与 §2.2 同构）', () => {
  test('register：注入 loginToken + 响应后处理', async () => {
    setLoginToken('tok-r1');
    let raw = '';
    server.use(
      http.post(REGISTER, async ({ request }) => {
        raw = await request.text();
        return HttpResponse.json({ status: 'success' });
      }),
    );
    const response = await mod.register({
      step: 'set_password',
      payload: { username: 'alice', password: 'pw' },
    });
    expect(JSON.parse(raw)).toEqual({
      loginToken: 'tok-r1',
      step: 'set_password',
      payload: { username: 'alice', password: 'pw' },
    });
    expect(response.status).toBe('success');
    expect(getLoginToken()).toBe(''); // success 清空
  });

  test('resetPassword：首次请求注入快照 oidc', async () => {
    let raw = '';
    server.use(
      http.post(RESET_PASSWORD, async ({ request }) => {
        raw = await request.text();
        return HttpResponse.json({ status: 'next', loginToken: 'tok-p1' });
      }),
    );
    await mod.resetPassword({
      step: 'challenge',
      payload: { email: 'a@b.com' },
    });
    expect(JSON.parse(raw)).toEqual({
      step: 'challenge',
      payload: { email: 'a@b.com' },
      oidc: { client_id: 'cid', redirect_uri: 'https://app/cb', state: 'st' },
    });
    expect(getLoginToken()).toBe('tok-p1');
  });
});

describe('loginOauth（§2.7.4）：oidc 取自 al_oidc_ctx（§2.7.2 行 599-600，读出即清）', () => {
  test('首次请求注入落盘 oidc 并读完即清', async () => {
    saveOidcContext({
      client_id: 'cid',
      redirect_uri: 'https://app/cb',
      nonce: 'n-1',
    });
    let raw = '';
    server.use(
      http.post(LOGIN_OAUTH, async ({ request }) => {
        raw = await request.text();
        return HttpResponse.json({ status: 'binding_required' });
      }),
    );

    const response = await mod.loginOauth({
      providerKey: 'qq',
      code: 'c-1',
      state: 'l-state',
    });

    expect(response.status).toBe('binding_required');
    expect(JSON.parse(raw)).toEqual({
      providerKey: 'qq',
      code: 'c-1',
      state: 'l-state',
      oidc: { client_id: 'cid', redirect_uri: 'https://app/cb', nonce: 'n-1' },
    });
    expect(window.localStorage.getItem('al_oidc_ctx')).toBeNull(); // 读完即清
  });

  test('响应含 loginToken 同样覆盖（§1.3 行 104：LoginOauth 共用信封）', async () => {
    server.use(
      http.post(LOGIN_OAUTH, () =>
        HttpResponse.json({ status: 'mfa_required', loginToken: 'tok-o1' }),
      ),
    );
    await mod.loginOauth({ providerKey: 'qq', code: 'c-1', state: 'l-state' });
    expect(getLoginToken()).toBe('tok-o1');
  });
});

describe('非信封方法（直通薄封装，无 loginToken 注入）', () => {
  test('authorize（§2.7.2）：请求体直传，响应 authorizeUrl', async () => {
    let raw = '';
    server.use(
      http.post(AUTHORIZE, async ({ request }) => {
        raw = await request.text();
        return HttpResponse.json({ authorizeUrl: 'https://qq.example/auth?state=l-x' });
      }),
    );
    const response = await mod.authorize({ provider: 'qq' });
    expect(JSON.parse(raw)).toEqual({ provider: 'qq' });
    expect(response.authorizeUrl).toBe('https://qq.example/auth?state=l-x');
  });

  test('createQrcode（§2.8 行 688）：captcha 必带（§2.5），响应直传', async () => {
    let raw = '';
    server.use(
      http.post(QRCODE, async ({ request }) => {
        raw = await request.text();
        return HttpResponse.json({
          ticket: 't-1',
          ticketId: 'c7Kx9',
          qrcodeUrl: 'https://cdn/q.jpg',
          expiresIn: '600',
        });
      }),
    );
    const response = await mod.createQrcode({
      providerKey: 'wechat_mp_scan',
      scene: 'login',
      captcha: { providerKey: 'cf_turnstile', token: '0.xxx' },
    });
    expect(JSON.parse(raw)).toEqual({
      providerKey: 'wechat_mp_scan',
      scene: 'login',
      captcha: { providerKey: 'cf_turnstile', token: '0.xxx' },
    });
    expect(response.ticketId).toBe('c7Kx9');
  });
});

describe('getLoginTicket（§2.8 行 710）：poll 秒数与信封后处理', () => {
  test('请求体 ticket + poll（int64 十进制字符串，§1.12）；响应后处理同信封', async () => {
    let raw = '';
    server.use(
      http.post(LOGIN_TICKET, async ({ request }) => {
        raw = await request.text();
        return HttpResponse.json({
          status: 'pending',
          ticket: { status: 'pending', ticketId: 'c7Kx9' },
        });
      }),
    );
    const response = await mod.getLoginTicket('t-1', 10);
    expect(JSON.parse(raw)).toEqual({ ticket: 't-1', poll: '10' });
    expect(response.status).toBe('pending');
    expect(response.ticket?.ticketId).toBe('c7Kx9');
    expect(getLoginToken()).toBe('');
  });

  test('轮询命中 success：login 信封内层透传；success 时 login_token 已清空（§2.8 行 725 / §1.3 行 108 success 不再返回）', async () => {
    server.use(
      http.post(LOGIN_TICKET, () =>
        HttpResponse.json({
          status: 'success',
          ticket: { status: 'success', ticketId: 'c7Kx9' },
          login: { status: 'success', redirectTo: '/home' },
        }),
      ),
    );
    const response = await mod.getLoginTicket('t-1');
    expect(response.login?.status).toBe('success');
    expect(response.login?.redirectTo).toBe('/home');
    expect(getLoginToken()).toBe(''); // 五条之 3
  });

  // 双层信封 loginToken 托管归内层（外层 success 是票据终态、不是登录终点）。
  test('轮询命中 binding：内层 loginToken 托管（§1.3 行 145 无条件覆盖）——外层 success 不误清（免密建号续接依赖）', async () => {
    server.use(
      http.post(LOGIN_TICKET, () =>
        HttpResponse.json({
          status: 'success',
          ticket: { status: 'success', ticketId: 'c7Kx9' },
          login: {
            status: 'binding_required',
            loginToken: 'lt-bind',
            binding: {
              providerKey: 'scan',
              displayName: '微信扫码',
              allowSignup: true,
            },
          },
        }),
      ),
    );
    const response = await mod.getLoginTicket('t-1');
    expect(response.login?.status).toBe('binding_required');
    expect(getLoginToken()).toBe('lt-bind'); // 内层信封托管（BindingPage 建号续接）
  });
});

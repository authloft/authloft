// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化后移除）。
// @ts-ignore
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, rs, test } from 'rstack/test';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { ApiError } from '../shared/api/errors';

/**
 * account 底座测试。覆盖边界（既定口径「覆盖路由渲染 + api 封装 msw」
 * 的当前可运行子集）：
 * - bootstrap：注入变量读取 / 归一 / loginUrl / logoutUrl（§5 行 478 / §8）；
 * - api.getProfile：msw 走真实 transport 归一链（§3.2 行 819）；
 * - isUnauthenticatedError：401 判定纯函数（§5 行 480）。
 *
 * 【Blocker】routes / AppLayout / ProfilePageView 的渲染测试在本工具链下
 * 无法落地：@douyinfe/semi-ui 的 lib/es 内部为无扩展名 import，node 原生
 * ESM 无法加载，rstest 0.12.5 对其 externalize（rs.mock / __mocks__ 均为
 * 运行时机制，拦不住编译图对 external 包的链接期加载）→ 任何模块图含
 * semi import 的测试文件都在加载期崩（实测：rs.mock 全组件 /
 * __mocks__ 目录 / 子路径 import 三路都试过）。唯一工具级解法是
 * rstack.config.mts 的 define.test 配置（Rstest deps inline），该文件本次
 * 不改。渲染测试待工具链修复后补齐。
 *
 * msw 请求链沿 login/api.test.ts 模式；al_root 在 transport（http.ts）模块
 * 求值时读 globalThis，故被测模块经 beforeAll 动态 import；单测环境为
 * node，BASE 与既有测试文件取同值防跨文件竞争。account 注入白名单仅
 * al_root / static_base（接口文档 §8：methods 是 login 必填项，account 无）。
 */
const BASE = 'https://uc.test';
(globalThis as { __AUTHLOFT_INIT__?: unknown }).__AUTHLOFT_INIT__ = {
  al_root: `${BASE}/`,
  static_base: '/assets/',
};

const PROFILE_URL = `${BASE}/api.account.v1.AccountService/GetProfile`;

const server = setupServer();

let bootstrapMod: typeof import('./bootstrap');
let apiMod: typeof import('./api');

beforeAll(async () => {
  server.listen({ onUnhandledRequest: 'error' });
  bootstrapMod = await import('./bootstrap');
  apiMod = await import('./api');
});

beforeEach(() => {
  // routes / AppLayout 渲染不可测（见文件头 Blocker），本文件无 JSX 渲染；
  // stub window 供 getInit（shared/types/init.ts）读取注入块。
  rs.stubGlobal('window', {
    location: { pathname: '/account/profile' },
    __AUTHLOFT_INIT__: (globalThis as { __AUTHLOFT_INIT__?: unknown })
      .__AUTHLOFT_INIT__,
  });
});

afterEach(() => {
  server.resetHandlers();
  rs.unstubAllGlobals();
});

afterAll(() => {
  server.close();
  (globalThis as { __AUTHLOFT_INIT__?: unknown }).__AUTHLOFT_INIT__ = undefined;
});

// ---------------------------------------------------------------------------
// bootstrap（§5 行 478 / §8 白名单 al_root + static_base）
// ---------------------------------------------------------------------------

describe('bootstrap（§5 行 478 / §8）', () => {
  test('normalizeStaticBase：空 / 缺省回落 /assets/，缺尾斜杠补齐', () => {
    expect(bootstrapMod.normalizeStaticBase(undefined)).toBe('/assets/');
    expect(bootstrapMod.normalizeStaticBase('')).toBe('/assets/');
    expect(bootstrapMod.normalizeStaticBase('  ')).toBe('/assets/');
    expect(bootstrapMod.normalizeStaticBase('/cdn-base')).toBe('/cdn-base/');
    expect(bootstrapMod.normalizeStaticBase('/assets/')).toBe('/assets/');
  });

  test('loadAccountBootstrap：注入块完整 → al_root 去尾斜杠 + static_base 归一（无 methods 必需校验）', () => {
    expect(bootstrapMod.loadAccountBootstrap()).toEqual({
      ok: true,
      alRoot: BASE,
      staticBase: '/assets/',
    });
  });

  test('loadAccountBootstrap：注入块未下发 → 缺省归一（§8 行 1428 默认 /assets；node 无 location → 空串）', () => {
    rs.stubGlobal('window', {
      location: { pathname: '/account/profile' },
      __AUTHLOFT_INIT__: undefined,
    });
    expect(bootstrapMod.loadAccountBootstrap()).toEqual({
      ok: true,
      alRoot: '',
      staticBase: '/assets/',
    });
  });

  test('loginUrl / logoutUrl：{al_root} 前缀拼接（§5 行 480 / §8 行 1418/1420）', () => {
    expect(bootstrapMod.loginUrl(BASE)).toBe(`${BASE}/sso/login`);
    expect(bootstrapMod.logoutUrl(BASE)).toBe(`${BASE}/sso/logout`);
  });
});

// ---------------------------------------------------------------------------
// api.getProfile（§3.2 行 819）：msw 走真实 transport 归一链
// ---------------------------------------------------------------------------

describe('api.getProfile（§3.2 行 819）', () => {
  test('Connect 协议 POST GetProfile → ProfileResponse 解码（protojson：int64 十进制字符串 → bigint）', async () => {
    let called = false;
    server.use(
      http.post(PROFILE_URL, () => {
        called = true;
        return HttpResponse.json({
          id: '10086',
          username: 'zhang_san',
          nickname: '张三',
          avatarUrl: 'https://cdn.test/a.jpg',
          phone: '138****8000',
          phoneVerified: '1',
          email: 'a***@example.com',
          emailVerified: '1',
          userStatus: '1',
          mfaRequired: '0',
          epoch: '3',
          lastLoginAt: '1761800000',
          createdAt: '1761700000',
          updatedAt: '1761800000',
        });
      }),
    );

    const res = await apiMod.getProfile();

    expect(called).toBe(true);
    expect(res.username).toBe('zhang_san');
    expect(res.nickname).toBe('张三');
    expect(res.id).toBe(BigInt(10086));
    expect(res.avatarUrl).toBe('https://cdn.test/a.jpg');
  });

  test('401 → transport 归一 ApiError → isUnauthenticatedError 为真（§5 行 480 401 判定）', async () => {
    server.use(
      http.post(PROFILE_URL, () => new HttpResponse(null, { status: 401 })),
    );

    let caught: unknown;
    try {
      await apiMod.getProfile();
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(ApiError);
    expect((caught as ApiError).httpStatus).toBe(401);
    expect(apiMod.isUnauthenticatedError(caught)).toBe(true);
  });

  test('非 401 错误不误判（§5 行 480：仅 401 触发跳登录）', async () => {
    server.use(
      http.post(PROFILE_URL, () => new HttpResponse(null, { status: 500 })),
    );

    let caught: unknown;
    try {
      await apiMod.getProfile();
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(ApiError);
    expect(apiMod.isUnauthenticatedError(caught)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// isUnauthenticatedError（§5 行 480 判定纯函数）
// ---------------------------------------------------------------------------

describe('isUnauthenticatedError（§5 行 480 判定纯函数）', () => {
  test('HTTP 401 或 Connect 标准码 unauthenticated → true', () => {
    expect(
      apiMod.isUnauthenticatedError(
        new ApiError({ httpStatus: 401, code: 'unauthenticated', message: '', requestId: '' }),
      ),
    ).toBe(true);
    expect(
      apiMod.isUnauthenticatedError(
        new ApiError({ httpStatus: 401, code: 'session_required', message: '', requestId: '' }),
      ),
    ).toBe(true);
    expect(
      apiMod.isUnauthenticatedError(
        new ApiError({ httpStatus: 403, code: 'unauthenticated', message: '', requestId: '' }),
      ),
    ).toBe(true);
  });

  test('其他 ApiError / 非错误对象 → false', () => {
    expect(
      apiMod.isUnauthenticatedError(
        new ApiError({ httpStatus: 403, code: 'permission_denied', message: '', requestId: '' }),
      ),
    ).toBe(false);
    expect(apiMod.isUnauthenticatedError(new Error('x'))).toBe(false);
    expect(apiMod.isUnauthenticatedError(undefined)).toBe(false);
  });
});

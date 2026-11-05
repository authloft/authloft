// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化后移除）。
// @ts-ignore
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, rs, test } from 'rstack/test';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { create } from '@bufbuild/protobuf';
import { MeResponseSchema } from '../gen/proto/api/admin/v1/admin_pb';
import { ApiError } from '../shared/api/errors';

/**
 * admin entry 底座测试。覆盖边界（既定口径「覆盖 bootstrap 装配 +
 * api 封装 msw + 401/404 分流判定纯逻辑」）：
 * - bootstrap：注入变量读取 / 归一 / loginUrl / logoutUrl（§6 行 501/505 / §8）；
 * - api.getMe：msw 走真实 transport 归一链（§5.1 行 1159）——成功解码
 *   （protojson：int64 十进制字符串 → bigint）+ 401 / 404 掩护 / 500 三路
 *   ConnectError → ApiError 归一（§6 行 501）；
 * - 401/404 分流判定纯函数（§6 行 501，本实现关键语义）：
 *   isUnauthenticatedError（401 → 跳登录）、isAdminNotFoundError（404 掩护）、
 *   adminMeFailureAction（401 → redirect_login；404 / 其余 → show_error 不跳登录）；
 * - adminDisplayName / apiErrorText 展示纯函数（零值兜底 §9 第 18 条；
 *   404 掩护文案走 errors.code.not_found 通用文案）。
 *
 * 【Blocker】routes / AdminLayout / entry 的渲染测试在本工具链下无法落地
 *（@douyinfe/semi-ui lib/es 无扩展名 import → rstest 0.12.5 externalize 下
 * node ESM 模块图崩，实测，见 account.test.tsx 头注）——渲染逻辑因此
 * 最小化为「分流纯函数 + 分支渲染」，可测部分全部落 api.ts / bootstrap.ts。
 *
 * msw 请求链沿 account.test.tsx 模式；al_root 在 transport（http.ts）模块
 * 求值时读 globalThis，故被测模块经 beforeAll 动态 import；单测环境为
 * node，BASE 与既有测试文件取同值防跨文件竞争。admin 注入白名单仅
 * al_root / static_base（接口文档 §8：methods 是 login 必填项，admin 无）。
 */
const BASE = 'https://uc.test';
(globalThis as { __AUTHLOFT_INIT__?: unknown }).__AUTHLOFT_INIT__ = {
  al_root: `${BASE}/`,
  static_base: '/assets/',
};

const GET_ME_URL = `${BASE}/api.admin.v1.AdminService/GetMe`;

const server = setupServer();

let bootstrapMod: typeof import('./bootstrap');
let apiMod: typeof import('./api');

beforeAll(async () => {
  server.listen({ onUnhandledRequest: 'error' });
  bootstrapMod = await import('./bootstrap');
  apiMod = await import('./api');
});

beforeEach(() => {
  // routes / AdminLayout 渲染不可测（见文件头 Blocker），本文件无 JSX 渲染；
  // stub window 供 getInit（shared/types/init.ts）读取注入块。
  rs.stubGlobal('window', {
    location: { pathname: '/admin' },
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
// bootstrap（§6 行 501/505 / §8 白名单 al_root + static_base）
// ---------------------------------------------------------------------------

describe('bootstrap（§6 行 505 / §8）', () => {
  test('normalizeStaticBase：空 / 缺省回落 /assets/，缺尾斜杠补齐', () => {
    expect(bootstrapMod.normalizeStaticBase(undefined)).toBe('/assets/');
    expect(bootstrapMod.normalizeStaticBase('')).toBe('/assets/');
    expect(bootstrapMod.normalizeStaticBase('  ')).toBe('/assets/');
    expect(bootstrapMod.normalizeStaticBase('/cdn-base')).toBe('/cdn-base/');
    expect(bootstrapMod.normalizeStaticBase('/assets/')).toBe('/assets/');
  });

  test('loadAdminBootstrap：注入块完整 → al_root 去尾斜杠 + static_base 归一（无 methods 必需校验）', () => {
    expect(bootstrapMod.loadAdminBootstrap()).toEqual({
      ok: true,
      alRoot: BASE,
      staticBase: '/assets/',
    });
  });

  test('loadAdminBootstrap：注入块未下发 → 缺省归一（§8 行 1428 默认 /assets；node 无 location → 空串）', () => {
    rs.stubGlobal('window', {
      location: { pathname: '/admin' },
      __AUTHLOFT_INIT__: undefined,
    });
    expect(bootstrapMod.loadAdminBootstrap()).toEqual({
      ok: true,
      alRoot: '',
      staticBase: '/assets/',
    });
  });

  test('loginUrl / logoutUrl：{al_root} 前缀拼接（§6 行 501 复用 SSO 登录登出 / §8 行 1418/1420）', () => {
    expect(bootstrapMod.loginUrl(BASE)).toBe(`${BASE}/sso/login`);
    expect(bootstrapMod.logoutUrl(BASE)).toBe(`${BASE}/sso/logout`);
  });
});

// ---------------------------------------------------------------------------
// api.getMe（§5.1 行 1159）：msw 走真实 transport 归一链 + §6 行 501 三路分流
// ---------------------------------------------------------------------------

describe('api.getMe（§5.1 行 1159）', () => {
  test('Connect 协议 POST GetMe → MeResponse 解码（protojson：int64 十进制字符串 → bigint）', async () => {
    let called = false;
    server.use(
      http.post(GET_ME_URL, () => {
        called = true;
        return HttpResponse.json({
          id: '1',
          username: 'admin',
          nickname: '管理员甲',
          avatarUrl: 'https://cdn.test/a.jpg',
          isAdmin: true,
        });
      }),
    );

    const res = await apiMod.getMe();

    expect(called).toBe(true);
    expect(res.id).toBe(BigInt(1));
    expect(res.username).toBe('admin');
    expect(res.nickname).toBe('管理员甲');
    expect(res.avatarUrl).toBe('https://cdn.test/a.jpg');
    expect(res.isAdmin).toBe(true);
  });

  test('401 → transport 归一 ApiError → isUnauthenticatedError 真 + 分流 redirect_login（§6 行 501 跳登录）', async () => {
    server.use(
      http.post(GET_ME_URL, () => new HttpResponse(null, { status: 401 })),
    );

    let caught: unknown;
    try {
      await apiMod.getMe();
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(ApiError);
    expect((caught as ApiError).httpStatus).toBe(401);
    expect((caught as ApiError).code).toBe('unauthenticated');
    expect(apiMod.isUnauthenticatedError(caught)).toBe(true);
    expect(apiMod.adminMeFailureAction(caught)).toBe('redirect_login');
  });

  test('404 掩护（会话有效但非管理员）→ 归一 ApiError 走统一错误处理，分流 show_error 不跳登录（§6 行 501）', async () => {
    // connect-go 拦截器的真实 wire 形态：HTTP 404 + Connect 错误 JSON 体
    //（空体会被 connect-web 按协议状态兜底表映射 Unimplemented，非后端行为）。
    server.use(
      http.post(GET_ME_URL, () =>
        new HttpResponse(JSON.stringify({ code: 'not_found', message: 'not found' }), {
          status: 404,
          headers: { 'content-type': 'application/json' },
        }),
      ),
    );

    let caught: unknown;
    try {
      await apiMod.getMe();
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(ApiError);
    expect((caught as ApiError).httpStatus).toBe(404);
    expect((caught as ApiError).code).toBe('not_found');
    expect(apiMod.isAdminNotFoundError(caught)).toBe(true);
    // 关键语义：404 不触发跳登录（跳登录即泄露管理面存在）。
    expect(apiMod.adminMeFailureAction(caught)).toBe('show_error');
    expect(apiMod.apiErrorText(caught)).toBe('资源不存在');
  });

  test('500 → 归一 ApiError，分流 show_error（§6 行 501 其余错误走统一错误态）', async () => {
    server.use(
      http.post(GET_ME_URL, () => new HttpResponse(null, { status: 500 })),
    );

    let caught: unknown;
    try {
      await apiMod.getMe();
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(ApiError);
    expect((caught as ApiError).httpStatus).toBe(500);
    expect(apiMod.isUnauthenticatedError(caught)).toBe(false);
    expect(apiMod.adminMeFailureAction(caught)).toBe('show_error');
  });
});

// ---------------------------------------------------------------------------
// 401/404 分流判定纯函数（§6 行 501；双条件口径与 account isUnauthenticatedError 对称）
// ---------------------------------------------------------------------------

describe('isUnauthenticatedError（§6 行 501 判定纯函数）', () => {
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
    expect(
      apiMod.isUnauthenticatedError(
        new ApiError({ httpStatus: 404, code: 'not_found', message: '', requestId: '' }),
      ),
    ).toBe(false);
    expect(apiMod.isUnauthenticatedError(new Error('x'))).toBe(false);
    expect(apiMod.isUnauthenticatedError(undefined)).toBe(false);
  });
});

describe('isAdminNotFoundError（§6 行 501 / 接口文档 §5 行 1149 掩护判定）', () => {
  test('HTTP 404 或 Connect 标准码 not_found → true', () => {
    expect(
      apiMod.isAdminNotFoundError(
        new ApiError({ httpStatus: 404, code: 'not_found', message: '', requestId: '' }),
      ),
    ).toBe(true);
    expect(
      apiMod.isAdminNotFoundError(
        new ApiError({ httpStatus: 200, code: 'not_found', message: '', requestId: '' }),
      ),
    ).toBe(true);
  });

  test('401 / 500 / 非 ApiError → false（404 掩护与 401 语义互斥）', () => {
    expect(
      apiMod.isAdminNotFoundError(
        new ApiError({ httpStatus: 401, code: 'unauthenticated', message: '', requestId: '' }),
      ),
    ).toBe(false);
    expect(
      apiMod.isAdminNotFoundError(
        new ApiError({ httpStatus: 500, code: 'internal', message: '', requestId: '' }),
      ),
    ).toBe(false);
    expect(apiMod.isAdminNotFoundError(new Error('x'))).toBe(false);
  });
});

describe('adminMeFailureAction（§6 行 501 分流判定）', () => {
  test('401 → redirect_login；404 掩护 / 500 / 非 ApiError → show_error（不跳登录）', () => {
    expect(
      apiMod.adminMeFailureAction(
        new ApiError({ httpStatus: 401, code: 'unauthenticated', message: '', requestId: '' }),
      ),
    ).toBe('redirect_login');
    expect(
      apiMod.adminMeFailureAction(
        new ApiError({ httpStatus: 404, code: 'not_found', message: '', requestId: '' }),
      ),
    ).toBe('show_error');
    expect(
      apiMod.adminMeFailureAction(
        new ApiError({ httpStatus: 500, code: 'internal', message: '', requestId: '' }),
      ),
    ).toBe('show_error');
    expect(apiMod.adminMeFailureAction(new Error('x'))).toBe('show_error');
    expect(apiMod.adminMeFailureAction(undefined)).toBe('show_error');
  });
});

// ---------------------------------------------------------------------------
// 展示纯函数（§9 第 18 条零值兜底；AdminLayout 顶栏消费，node 可测）
// ---------------------------------------------------------------------------

describe('adminDisplayName（§5.1 行 1159 + 零值兜底）', () => {
  test('昵称优先 → username 回落 → 「管理员」占位', () => {
    expect(
      apiMod.adminDisplayName(
        create(MeResponseSchema, {
          id: BigInt(1),
          username: 'admin',
          nickname: '管理员甲',
          avatarUrl: '',
          isAdmin: true,
        }),
      ),
    ).toBe('管理员甲');
    expect(
      apiMod.adminDisplayName(
        create(MeResponseSchema, {
          id: BigInt(1),
          username: 'admin',
          nickname: '',
          avatarUrl: '',
          isAdmin: true,
        }),
      ),
    ).toBe('admin');
    expect(
      apiMod.adminDisplayName(
        create(MeResponseSchema, {
          id: BigInt(1),
          username: '',
          nickname: '',
          avatarUrl: '',
          isAdmin: true,
        }),
      ),
    ).toBe('管理员');
  });
});

describe('apiErrorText（§1.5 行 202 i18n 优先；404 掩护走通用文案）', () => {
  test('ApiError → errors.code.<code> 字典文案；未知异常 → 兜底不透出内部信息', () => {
    expect(
      apiMod.apiErrorText(
        new ApiError({ httpStatus: 404, code: 'not_found', message: 'admin surface', requestId: '' }),
      ),
    ).toBe('资源不存在');
    expect(
      apiMod.apiErrorText(
        new ApiError({ httpStatus: 401, code: 'unauthenticated', message: '', requestId: '' }),
      ),
    ).toBe('请先登录');
    expect(apiMod.apiErrorText(new Error('boom'))).toBe('操作失败，请稍后重试');
    expect(apiMod.apiErrorText(undefined)).toBe('操作失败，请稍后重试');
  });
});

// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化后移除）。
// @ts-ignore
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, rs, test } from 'rstack/test';
import * as React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { create } from '@bufbuild/protobuf';
import { MeResponseSchema } from '../gen/proto/api/admin/v1/admin_pb';
import {
  ProviderSchema,
  SetProviderEnabledRequestSchema,
} from '../gen/proto/api/admin/v1/provider_pb';
import { ApiError } from '../shared/api/errors';
import { moveItem, SortableList } from './components/SortableList';
import {
  ProviderCallbackHint,
  isOidcProviderType,
  providerCallbackUrl,
} from './components/ProviderCallbackHint';

/**
 * admin entry 底座测试 + Provider 列表族测试。底座覆盖边界（既定口径
 * 「覆盖 bootstrap 装配 + api 封装 msw + 401/404 分流判定纯逻辑」）：
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
 * Provider 列表族追加（接口文档 §5.2 行 1164-1177）：
 * - api Provider 三方法 msw 真实 transport 链：ListProviders 读路径解码
 *   （含 protojson 零值省略 → false）+ SetProviderEnabled / SortProviders
 *   请求体 wire 校验（int64 → 十进制字符串、bool false 零值省略）；
 * - buildListProvidersRequest / buildSortProvidersRequest 请求构造纯函数；
 * - policyTags 策略标签展示纯函数（落位 api.ts，adminDisplayName 同口径）；
 * - SortableList.moveItem 重排纯函数 + 组件静态渲染（零 Semi 依赖，经
 *   react-dom/server renderToStaticMarkup，components.test.ts 同模式）；
 * - ProviderCallbackHint：providerCallbackUrl / isOidcProviderType 纯函数 +
 *   模板 / 具体 / OIDC 注记三形态静态渲染。
 *
 * 【Blocker】routes / AdminLayout / entry / ProvidersPage / StatusSwitch 的
 * 渲染测试在本工具链下无法落地（@douyinfe/semi-ui lib/es 无扩展名 import →
 * rstest 0.12.5 externalize 下 node ESM 模块图崩，实测，见
 * account.test.tsx 头注）——渲染逻辑因此最小化为「纯函数 + 分支渲染」，
 * 可测部分全部落 api.ts / bootstrap.ts / 零 Semi 组件；StatusSwitch 的
 * 乐观更新 / 回滚编排已收口在 shared/app-ui/dataTableLogic（已有测试覆盖）。
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
const LIST_PROVIDERS_URL = `${BASE}/api.admin.v1.AdminService/ListProviders`;
const SET_PROVIDER_ENABLED_URL = `${BASE}/api.admin.v1.AdminService/SetProviderEnabled`;
const SORT_PROVIDERS_URL = `${BASE}/api.admin.v1.AdminService/SortProviders`;

// rstest 对 .tsx 采用 classic JSX runtime，本文件渲染断言经 createElement
// 显式引用（不走 JSX 字面量，免全局 React stub；components.test.ts 头注口径）。
const { createElement } = React;

const server = setupServer();

let bootstrapMod: typeof import('./bootstrap');
let apiMod: typeof import('./api');

beforeAll(async () => {
  server.listen({ onUnhandledRequest: 'error' });
  bootstrapMod = await import('./bootstrap');
  apiMod = await import('./api');
});

beforeEach(() => {
  // classic JSX runtime（components.test.ts 头注口径）：源码组件不 import
  // React（构建期 automatic runtime），测试链 JSX 编译产物引用全局 React——
  // 渲染断言（SortableList / ProviderCallbackHint 静态渲染）前 stub；afterEach
  // 的 unstubAllGlobals 会移除，故每测试重置（与 window stub 同生命周期）。
  rs.stubGlobal('React', React);
  // routes / AdminLayout 渲染不可测（见文件头 Blocker）；stub window 供
  // getInit（shared/types/init.ts）读取注入块。
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

// ---------------------------------------------------------------------------
// api Provider 三方法 msw（§5.2 行 1164-1177；读路径真调语义 → msw
// 走真实 transport 归一链，写路径启停 / 排序同链校验请求体 wire 形态）
// ---------------------------------------------------------------------------

describe('api.listProviders（§5.2 行 1165：读路径真调 + protojson 解码）', () => {
  test('Connect 协议 POST → ProviderListResponse 解码（int64 十进制字符串 → bigint；零值省略 → false）+ 全量取数请求体', async () => {
    let requestBody: unknown;
    server.use(
      http.post(LIST_PROVIDERS_URL, async ({ request }) => {
        requestBody = await request.json();
        return HttpResponse.json({
          items: [
            {
              providerKey: 'qq',
              displayName: 'QQ',
              category: 'oauth',
              type: 'qq',
              isEnabled: true,
              enableSignin: true,
              enableSignup: true,
              sortOrder: '10',
            },
            {
              // sms / email 类策略开关全零值省略（protojson）→ 解码 false。
              providerKey: 'eml_main',
              displayName: '邮件主通道',
              category: 'email',
              type: 'smtp',
              sortOrder: '20',
            },
          ],
          total: '2',
          page: '1',
          pageSize: '100',
        });
      }),
    );

    const res = await apiMod.listProviders(apiMod.buildListProvidersRequest());

    // 全量取数请求体：第 1 页 × 100（§1.7 行 277 上限；int64 → 十进制字符串）。
    expect(requestBody).toEqual({ page: '1', pageSize: '100' });
    expect(res.total).toBe(BigInt(2));
    expect(res.items).toHaveLength(2);
    expect(res.items[0].providerKey).toBe('qq');
    expect(res.items[0].sortOrder).toBe(BigInt(10));
    expect(res.items[0].isEnabled).toBe(true);
    expect(res.items[0].autoBind).toBe(false);
    expect(res.items[1].displayName).toBe('邮件主通道');
    expect(res.items[1].isEnabled).toBe(false);
    expect(res.items[1].enableSignin).toBe(false);
    expect(res.items[1].autoBind).toBe(false);
  });

  test('500 → ApiError 归一（非 401：页面错误态，不跳登录）', async () => {
    server.use(
      http.post(LIST_PROVIDERS_URL, () => new HttpResponse(null, { status: 500 })),
    );
    let caught: unknown;
    try {
      await apiMod.listProviders(apiMod.buildListProvidersRequest());
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(ApiError);
    expect((caught as ApiError).httpStatus).toBe(500);
    expect(apiMod.isUnauthenticatedError(caught)).toBe(false);
  });
});

describe('api.setProviderEnabled（§5.2 行 1173 行内启停 → OkResponse）', () => {
  test('请求体 wire 校验（isEnabled=false 零值省略）+ 成功解码 OkResponse', async () => {
    let requestBody: unknown;
    server.use(
      http.post(SET_PROVIDER_ENABLED_URL, async ({ request }) => {
        requestBody = await request.json();
        return HttpResponse.json({});
      }),
    );
    const res = await apiMod.setProviderEnabled(
      create(SetProviderEnabledRequestSchema, { providerKey: 'qq', isEnabled: false }),
    );
    // protojson：非 optional 的 bool false 为零值 → 省略不下发（§1.0 零值缺省）。
    expect(requestBody).toEqual({ providerKey: 'qq' });
    expect(res.$typeName).toBe('api.admin.v1.OkResponse');
  });

  test('500 reject → ApiError（StatusSwitch 回滚触发链：消费方 catch 展示后 rethrow）', async () => {
    server.use(
      http.post(SET_PROVIDER_ENABLED_URL, () => new HttpResponse(null, { status: 500 })),
    );
    let caught: unknown;
    try {
      await apiMod.setProviderEnabled(
        create(SetProviderEnabledRequestSchema, { providerKey: 'qq', isEnabled: true }),
      );
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(ApiError);
    expect((caught as ApiError).httpStatus).toBe(500);
  });
});

describe('api.sortProviders（§5.2 行 1174 拖拽排序 → OkResponse）', () => {
  test('请求体 items[{providerKey, sortOrder}] wire 校验（int64 → 十进制字符串）', async () => {
    let requestBody: unknown;
    server.use(
      http.post(SORT_PROVIDERS_URL, async ({ request }) => {
        requestBody = await request.json();
        return HttpResponse.json({});
      }),
    );
    const rows = [
      create(ProviderSchema, { providerKey: 'wechat_mp', sortOrder: BigInt(30) }),
      create(ProviderSchema, { providerKey: 'qq', sortOrder: BigInt(10) }),
    ];
    const res = await apiMod.sortProviders(apiMod.buildSortProvidersRequest(rows));
    expect(requestBody).toEqual({
      items: [
        { providerKey: 'wechat_mp', sortOrder: '1' },
        { providerKey: 'qq', sortOrder: '2' },
      ],
    });
    expect(res.$typeName).toBe('api.admin.v1.OkResponse');
  });
});

// ---------------------------------------------------------------------------
// 请求构造 / 展示纯函数（落位 api.ts，adminDisplayName 同口径）
// ---------------------------------------------------------------------------

describe('buildListProvidersRequest / buildSortProvidersRequest（请求构造纯函数）', () => {
  test('buildListProvidersRequest：第 1 页 × pageSize 100（§1.7 行 277 上限；拖拽排序需全量行集）', () => {
    const req = apiMod.buildListProvidersRequest();
    expect(req.page).toBe(BigInt(1));
    expect(req.pageSize).toBe(BigInt(100));
  });

  test('buildSortProvidersRequest：新数组序整体重排（1..n）+ 键保持 + 入参不可变', () => {
    const rows = [
      create(ProviderSchema, { providerKey: 'wechat_mp', sortOrder: BigInt(30) }),
      create(ProviderSchema, { providerKey: 'qq', sortOrder: BigInt(10) }),
      create(ProviderSchema, { providerKey: 'eml_main', sortOrder: BigInt(20) }),
    ];
    const req = apiMod.buildSortProvidersRequest(rows);
    expect(req.items.map((item) => item.providerKey)).toEqual([
      'wechat_mp',
      'qq',
      'eml_main',
    ]);
    expect(req.items.map((item) => item.sortOrder)).toEqual([BigInt(1), BigInt(2), BigInt(3)]);
    // 原行集序与原 sort_order 不变（不可变构造）。
    expect(rows.map((row) => row.providerKey)).toEqual(['wechat_mp', 'qq', 'eml_main']);
    expect(rows[0].sortOrder).toBe(BigInt(30));
  });
});

describe('policyTags（§5.2 行 1165「策略标签」展示纯函数）', () => {
  test('enableSignin / enableSignup / autoBind → 对应标签；全 false → 空数组（消费方渲染占位）', () => {
    expect(
      apiMod.policyTags(
        create(ProviderSchema, { enableSignin: true, enableSignup: true, autoBind: true }),
      ),
    ).toEqual(['允许登录', '允许注册', '自动绑定']);
    expect(apiMod.policyTags(create(ProviderSchema, { autoBind: true }))).toEqual([
      '自动绑定',
    ]);
    expect(apiMod.policyTags(create(ProviderSchema, {}))).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// SortableList（拖拽排序，零 Semi 依赖 → moveItem 纯函数 + 静态渲染）
// ---------------------------------------------------------------------------

describe('moveItem（SortableList 顺序重排纯函数）', () => {
  test('中段 → 首位 / 首位 → 尾位：不可变重排', () => {
    const items = ['a', 'b', 'c'];
    expect(moveItem(items, 1, 0)).toEqual(['b', 'a', 'c']);
    expect(moveItem(items, 0, 2)).toEqual(['b', 'c', 'a']);
    expect(items).toEqual(['a', 'b', 'c']); // 原数组不变
  });

  test('同位 / 越界 → 原引用返回（无变更即无新引用，失败回滚语义依赖）', () => {
    const items = ['a', 'b'];
    expect(moveItem(items, 1, 1)).toBe(items);
    expect(moveItem(items, -1, 0)).toBe(items);
    expect(moveItem(items, 0, 5)).toBe(items);
    expect(moveItem([], 0, 0)).toEqual([]);
  });
});

describe('SortableList（静态渲染：数组序即渲染序 + 手柄 aria 标签 + disabled）', () => {
  test('items 按序渲染；disabled 不带 draggable', () => {
    const enabled = renderToStaticMarkup(
      createElement(SortableList<string>, {
        items: ['a', 'b'],
        itemKey: (item) => item,
        renderItem: (item) => createElement('span', null, item),
        onSort: () => {},
      }),
    );
    expect(enabled).toContain('a');
    expect(enabled).toContain('b');
    // 数组序即渲染序。
    expect(enabled.indexOf('a')).toBeLessThan(enabled.indexOf('b'));
    expect(enabled).toContain('draggable="true"');
    expect(enabled).toContain('拖拽排序');

    const disabled = renderToStaticMarkup(
      createElement(SortableList<string>, {
        items: ['a'],
        itemKey: (item) => item,
        renderItem: (item) => createElement('span', null, item),
        onSort: () => {},
        disabled: true,
      }),
    );
    expect(disabled).not.toContain('draggable="true"');
  });
});

// ---------------------------------------------------------------------------
// ProviderCallbackHint（§2.7.3 行 602 / §5.3 行 1193；零 Semi 依赖）
// ---------------------------------------------------------------------------

describe('providerCallbackUrl / isOidcProviderType（纯函数）', () => {
  test('providerCallbackUrl：{alRoot}/sso/oauth/callback/{providerKey}；providerKey 缺省 → 字面模板', () => {
    expect(providerCallbackUrl('https://uc.test', 'qq')).toBe(
      'https://uc.test/sso/oauth/callback/qq',
    );
    expect(providerCallbackUrl('https://uc.test')).toBe(
      'https://uc.test/sso/oauth/callback/{provider_key}',
    );
    // node 环境 alRoot 归一为空串 → 相对路径形态（bootstrap 同口径）。
    expect(providerCallbackUrl('', 'qq')).toBe('/sso/oauth/callback/qq');
  });

  test('isOidcProviderType：oidc_ 前缀判定（既定口径）', () => {
    expect(isOidcProviderType('oidc_generic')).toBe(true);
    expect(isOidcProviderType('qq')).toBe(false);
    expect(isOidcProviderType('')).toBe(false);
    expect(isOidcProviderType(undefined)).toBe(false);
  });
});

describe('ProviderCallbackHint（静态渲染：模板 / 具体 / OIDC 注记三形态）', () => {
  test('列表页顶部模板形态：字面 {provider_key} + 复制按钮，无 OIDC 注记', () => {
    const markup = renderToStaticMarkup(
      createElement(ProviderCallbackHint, { alRoot: 'https://uc.test' }),
    );
    expect(markup).toContain('https://uc.test/sso/oauth/callback/{provider_key}');
    expect(markup).toContain('复制'); // CopyButton（t('common.copy')）
    expect(markup).not.toContain('精确匹配');
  });

  test('具体 providerKey：具体回调地址；oidc_ 前缀另提示「回调需精确匹配」', () => {
    const oidc = renderToStaticMarkup(
      createElement(ProviderCallbackHint, {
        alRoot: 'https://uc.test',
        providerKey: 'qq',
        type: 'oidc_generic',
      }),
    );
    expect(oidc).toContain('https://uc.test/sso/oauth/callback/qq');
    expect(oidc).toContain('精确匹配');

    const nonOidc = renderToStaticMarkup(
      createElement(ProviderCallbackHint, {
        alRoot: 'https://uc.test',
        providerKey: 'qq',
        type: 'qq',
      }),
    );
    expect(nonOidc).toContain('https://uc.test/sso/oauth/callback/qq');
    expect(nonOidc).not.toContain('精确匹配');
  });
});

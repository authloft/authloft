// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化后移除）。
// @ts-ignore
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, rs, test } from 'rstack/test';
import * as React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { create, fromJson, type JsonObject } from '@bufbuild/protobuf';
import { MeResponseSchema } from '../gen/proto/api/admin/v1/admin_pb';
import {
  AdminProviderSchema,
  GetProviderRequestSchema,
  ProviderSchema,
  SetProviderEnabledRequestSchema,
  TestProviderRequestSchema,
} from '../gen/proto/api/admin/v1/provider_pb';
import {
  GetProviderSchemaRequestSchema,
  SchemaFieldSchema,
  SchemaResponseSchema,
  type SchemaField,
} from '../gen/proto/api/admin/v1/schema_pb';
import { MfaResponseSchema } from '../gen/proto/api/account/v1/mfa_pb';
import {
  initialTableQuery,
  type TableQueryState,
} from '../shared/app-ui/dataTableLogic';
import { ApiError } from '../shared/api/errors';
import { moveItem, SortableList } from './components/SortableList';
import {
  ProviderCallbackHint,
  isOidcProviderType,
  providerCallbackUrl,
} from './components/ProviderCallbackHint';
import { JsonEditor } from './components/JsonEditor';
import {
  SECTION_ORDER,
  adminProviderToValues,
  applySchemaDefaults,
  buildProviderStruct,
  groupFieldsBySection,
  initialCreateValues,
  isProviderKeyTaken,
  validateSchemaValues,
} from './schema/schemaLogic';

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
 *   模板 / 具体 / OIDC 注记三形态静态渲染（OIDC 判定 type=oidc｜oauth2，
 *   接口文档 §9 行 1461）。
 *
 * Provider 编辑族追加（接口文档 §5.2 行 1169-1177 + §5.3 行 1181-1243）：
 * - schemaLogic 纯函数全集：五区块分组（section 缺失 / 非法即 throw）/
 *   默认值应用 / 详情回填（表列 typed 映射 + Ext 合成 + json stringify）/
 *   提交前校验（required / pattern / number / json）/ 提交体构造
 *   （type 顶层恒带 + json parse + 空 json 省略）/ provider_key 唯一性预检；
 * - api Provider 编辑族 msw 真实 transport 链：GetProviderTypes /
 *   GetProviderSchema / GetProvider 读路径解码（Struct / Value protojson
 *   形态）+ Create / Update / TestProvider 请求体 wire 校验（Struct 平铺）；
 * - JsonEditor 静态渲染（零 Semi 依赖）。
 *
 * 用户管理族追加（接口文档 §5.4 行 1249-1255；后端已实装，
 * 读路径真调语义 → msw 走真实 transport 归一链）：
 * - api 七方法 msw：ListUsers / GetUser / GetUserEvents 读路径解码
 *   （AdminUser / 凭证 / 绑定 / mfa 嵌套 / EventItem）+ 404 带 Connect JSON
 *   体口径 + UpdateUserStatus / ResetUserPassword / UnbindUserThirdparty /
 *   UnlockUser 请求体 wire 校验（含 userStatus 零值省略语义）；
 * - 请求构造纯函数：buildListUsersRequest（q 去空白 / userStatus 单选
 *   映射 / 排序仅 order 非空下发）/ buildGetUserEventsRequest / 其余
 *   buildXxxRequest；
 * - 展示纯函数：userStatusLabel / credentialKindLabel / mfaFactorLabel /
 *   boundMfaFactors（mfa 缺省防御）/ formatUnixTime（时区无关断言）。
 * UsersPage / UserDetailPage 渲染不可测（同上 Blocker），DataTable 分页 /
 * 排序 / 筛选 / 行内开关编排已由 shared/app-ui 四约束测试覆盖。
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
const GET_PROVIDER_TYPES_URL = `${BASE}/api.admin.v1.AdminService/GetProviderTypes`;
const GET_PROVIDER_SCHEMA_URL = `${BASE}/api.admin.v1.AdminService/GetProviderSchema`;
const GET_PROVIDER_URL = `${BASE}/api.admin.v1.AdminService/GetProvider`;
const CREATE_PROVIDER_URL = `${BASE}/api.admin.v1.AdminService/CreateProvider`;
const UPDATE_PROVIDER_URL = `${BASE}/api.admin.v1.AdminService/UpdateProvider`;
const TEST_PROVIDER_URL = `${BASE}/api.admin.v1.AdminService/TestProvider`;
const LIST_USERS_URL = `${BASE}/api.admin.v1.AdminService/ListUsers`;
const GET_USER_URL = `${BASE}/api.admin.v1.AdminService/GetUser`;
const UPDATE_USER_STATUS_URL = `${BASE}/api.admin.v1.AdminService/UpdateUserStatus`;
const RESET_USER_PASSWORD_URL = `${BASE}/api.admin.v1.AdminService/ResetUserPassword`;
const UNBIND_USER_THIRDPARTY_URL = `${BASE}/api.admin.v1.AdminService/UnbindUserThirdparty`;
const UNLOCK_USER_URL = `${BASE}/api.admin.v1.AdminService/UnlockUser`;
const GET_USER_EVENTS_URL = `${BASE}/api.admin.v1.AdminService/GetUserEvents`;

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

  test('isOidcProviderType：type=oidc｜oauth2 判定（接口文档 §9 行 1461）', () => {
    expect(isOidcProviderType('oidc')).toBe(true);
    expect(isOidcProviderType('oauth2')).toBe(true);
    // 原 oidc_ 前缀口径与后端注册表不符（oauth 域仅 wechat_mp，无前缀类型）。
    expect(isOidcProviderType('oidc_generic')).toBe(false);
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

  test('具体 providerKey：具体回调地址；OIDC 兜底类（type=oidc）另提示「回调需精确匹配」', () => {
    const oidc = renderToStaticMarkup(
      createElement(ProviderCallbackHint, {
        alRoot: 'https://uc.test',
        providerKey: 'oidc_main',
        type: 'oidc',
      }),
    );
    expect(oidc).toContain('https://uc.test/sso/oauth/callback/oidc_main');
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

// ---------------------------------------------------------------------------
// schemaLogic 纯函数（§5.3 行 1181-1243；零 Semi 依赖，node 可测）
// ---------------------------------------------------------------------------

/** SchemaField 测试工厂（protojson 形态 → fromJson 造 default 的 Value）。 */
function schemaField(init: JsonObject): SchemaField {
  return fromJson(SchemaFieldSchema, init);
}

/**
 * 测试字段集（§5.3 行 1187-1226 wechat_mp 示例的简化覆盖：五区块 ×
 * 六类型中的 text / secret / select / number / json / checkbox + required /
 * pattern / default / advanced 修饰）。
 */
const SCHEMA_FIELDS = [
  schemaField({ key: 'provider_key', label: '唯一标识', type: 'text', section: 'basic', required: true, pattern: '^[a-z0-9_]+$', help: '创建后不可修改' }),
  schemaField({ key: 'display_name', label: '显示名称', type: 'text', section: 'basic', required: true }),
  schemaField({ key: 'category', label: '类别', type: 'select', section: 'basic', required: true, options: ['oauth'] }),
  schemaField({ key: 'union_provider', label: '联合登录归属', type: 'select', section: 'basic', options: [] }),
  schemaField({ key: 'client_id', label: 'AppID', type: 'text', section: 'credential', required: true }),
  schemaField({ key: 'client_secret', label: 'AppSecret', type: 'secret', section: 'credential', required: true }),
  schemaField({ key: 'port', label: '端口', type: 'number', section: 'endpoint' }),
  schemaField({ key: 'user_mapping', label: '字段映射', type: 'json', section: 'endpoint', advanced: true }),
  schemaField({ key: 'icon_url', label: '图标 URL', type: 'text', section: 'display', pattern: '^https?://' }),
  schemaField({ key: 'ui_group', label: '展示分组', type: 'select', section: 'display', default: 'social' }),
  schemaField({ key: 'sort_order', label: '排序', type: 'number', section: 'display', default: 0 }),
  schemaField({ key: 'is_enabled', label: '启用', type: 'checkbox', section: 'policy', default: true }),
];

describe('groupFieldsBySection（§5.3 行 1185：五区块分组 + 数组序 + section 缺失即报错）', () => {
  test('按 SECTION_ORDER 分组，区块内保持 fields[] 数组序；空区块为空数组', () => {
    const groups = groupFieldsBySection(SCHEMA_FIELDS);
    expect(SECTION_ORDER).toEqual(['basic', 'credential', 'endpoint', 'display', 'policy']);
    expect(groups).toHaveLength(5);
    expect(groups[0].map((f) => f.key)).toEqual(['provider_key', 'display_name', 'category', 'union_provider']);
    expect(groups[1].map((f) => f.key)).toEqual(['client_id', 'client_secret']);
    expect(groups[2].map((f) => f.key)).toEqual(['port', 'user_mapping']);
    expect(groups[3].map((f) => f.key)).toEqual(['icon_url', 'ui_group', 'sort_order']);
    expect(groups[4].map((f) => f.key)).toEqual(['is_enabled']);
  });

  test('section 缺失（protojson 零值省略 → 空串）即 throw（§6 行 508 不维护映射表）', () => {
    const missing = [schemaField({ key: 'x', label: 'X', type: 'text', section: 'basic' }), schemaField({ key: 'y', label: 'Y', type: 'text' })];
    expect(() => groupFieldsBySection(missing)).toThrow(/section/);
  });

  test('section 非法值即 throw（五区块封闭值域）', () => {
    const illegal = [schemaField({ key: 'x', label: 'X', type: 'text', section: 'unknown' })];
    expect(() => groupFieldsBySection(illegal)).toThrow(/section/);
  });
});

describe('applySchemaDefaults（§5.3 行 1183 default 修饰 + 类型零值）', () => {
  test('default 有值按 default（string / number / bool）；未下发按类型零值', () => {
    const values = applySchemaDefaults(SCHEMA_FIELDS);
    expect(values.provider_key).toBe('');
    expect(values.category).toBe('');
    expect(values.port).toBe(0);
    expect(values.user_mapping).toBe('');
    expect(values.ui_group).toBe('social');
    expect(values.sort_order).toBe(0);
    expect(values.is_enabled).toBe(true);
  });
});

describe('initialCreateValues（新建 category 预填注册表权威值，死锁修正）', () => {
  test('category 取 SchemaResponse 顶层 category（§5.3 行 1183/1195）；其余字段沿用 default / 零值', () => {
    const schema = create(SchemaResponseSchema, {
      type: 'wechat_mp',
      category: 'oauth',
      fields: SCHEMA_FIELDS,
    });
    const values = initialCreateValues(schema);
    // R1 核心：category 不再是零值 ''（applySchemaDefaults 死锁源）。
    expect(values.category).toBe('oauth');
    expect(values.provider_key).toBe('');
    expect(values.ui_group).toBe('social');
    expect(values.is_enabled).toBe(true);
  });

  test('R1 死锁回归锚点：预填值经 validateSchemaValues 后 category 键无 issue（required 通过）', () => {
    const schema = create(SchemaResponseSchema, {
      type: 'wechat_mp',
      category: 'oauth',
      fields: SCHEMA_FIELDS,
    });
    const issues = validateSchemaValues(SCHEMA_FIELDS, initialCreateValues(schema));
    expect(issues.category).toBeUndefined();
    // 对照：required 拦截对其他未填字段照常生效（修正未绕过校验）。
    expect(issues.provider_key).toBe('此项为必填');
  });
});

describe('adminProviderToValues（编辑回填：表列 typed 映射 + Ext 合成 + json stringify）', () => {
  test('表列取 typed 属性（int64 sortOrder → number）；Ext 键取 ext JsonObject；json 对象 stringify；缺失键零值', () => {
    const provider = create(AdminProviderSchema, {
      providerKey: 'wx1',
      displayName: '微信',
      category: 'oauth',
      type: 'wechat_mp',
      enableSignin: true,
      sortOrder: BigInt(3),
      iconUrl: 'https://cdn.test/wx.png',
      ext: {
        client_id: 'wx-123',
        client_secret: 'secret-456',
        port: 443,
        user_mapping: { nickname: '$.name' },
      },
    });
    const values = adminProviderToValues(SCHEMA_FIELDS, provider);
    expect(values.provider_key).toBe('wx1');
    expect(values.display_name).toBe('微信');
    expect(values.category).toBe('oauth');
    expect(values.union_provider).toBe('');
    expect(values.sort_order).toBe(3);
    expect(values.icon_url).toBe('https://cdn.test/wx.png');
    expect(values.client_id).toBe('wx-123');
    expect(values.client_secret).toBe('secret-456');
    expect(values.port).toBe(443);
    // json 字段编辑文本态（格式化 JSON 文本）。
    expect(values.user_mapping).toBe(JSON.stringify({ nickname: '$.name' }, null, 2));
    // 表列零值（protojson 省略 → false）+ Ext 缺失键零值。
    expect(values.is_enabled).toBe(false);
    expect(values.ui_group).toBe('');
  });

  test('ext 缺省（JsonObject undefined）→ 全部 Ext 字段零值', () => {
    const provider = create(AdminProviderSchema, {
      providerKey: 'wx1',
    });
    const values = adminProviderToValues(SCHEMA_FIELDS, provider);
    expect(values.client_id).toBe('');
    expect(values.user_mapping).toBe('');
  });
});

describe('validateSchemaValues（§5.3 修饰 required / pattern + 类型合法性）', () => {
  test('required 空值 / pattern 不匹配 / json 非法 → 对应键文案；合法值 → 空', () => {
    const invalid = validateSchemaValues(SCHEMA_FIELDS, {
      provider_key: 'Bad Key', // pattern ^[a-z0-9_]+$ 不匹配。
      display_name: '', // required 空。
      category: 'oauth',
      client_id: '',
      client_secret: 's',
      port: 0,
      user_mapping: '{oops', // 非法 JSON。
      icon_url: 'ftp://cdn.test/x.png', // pattern ^https?:// 不匹配。
      ui_group: 'social',
      sort_order: 0,
      is_enabled: true,
    });
    expect(invalid.provider_key).toBe('格式不正确');
    expect(invalid.display_name).toBe('此项为必填');
    expect(invalid.client_id).toBe('此项为必填');
    expect(invalid.user_mapping).toBe('不是合法的 JSON');
    expect(invalid.icon_url).toBe('格式不正确');
    expect(Object.keys(invalid).sort()).toEqual(
      ['client_id', 'display_name', 'icon_url', 'provider_key', 'user_mapping'].sort(),
    );

    const valid = validateSchemaValues(SCHEMA_FIELDS, {
      provider_key: 'wx_new',
      display_name: '新微信',
      category: 'oauth',
      client_id: 'wx-123',
      client_secret: 's',
      port: 443,
      user_mapping: '{"nickname": "$.name"}',
      icon_url: '', // 非必填空值放行（§5.3 行 1213 留空渲染占位）。
      ui_group: 'social',
      sort_order: 0,
      is_enabled: false, // checkbox false 是合法值（required 不适用）。
    });
    expect(valid).toEqual({});
  });

  test('number 类型非 number → 文案（受控态兜底）', () => {
    const issues = validateSchemaValues([schemaField({ key: 'port', label: '端口', type: 'number', section: 'endpoint' })], { port: '443' });
    expect(issues.port).toBe('必须是数字');
  });
});

describe('buildProviderStruct（§5.3 行 1183 提交体 {"<key>": <value>} + type 顶层恒带）', () => {
  test('type 顶层 + 全键平铺；json 文本 parse 回对象；checkbox false / number 0 原样保留', () => {
    const struct = buildProviderStruct('wechat_mp', SCHEMA_FIELDS, {
      provider_key: 'wx_new',
      display_name: '新微信',
      category: 'oauth',
      union_provider: '',
      client_id: 'wx-123',
      client_secret: 'secret',
      port: 443,
      user_mapping: '{"nickname": "$.name"}',
      icon_url: '',
      ui_group: 'social',
      sort_order: 0,
      is_enabled: false,
    });
    expect(struct).toEqual({
      type: 'wechat_mp',
      provider_key: 'wx_new',
      display_name: '新微信',
      category: 'oauth',
      union_provider: '',
      client_id: 'wx-123',
      client_secret: 'secret',
      port: 443,
      user_mapping: { nickname: '$.name' },
      icon_url: '',
      ui_group: 'social',
      sort_order: 0,
      is_enabled: false,
    });
  });

  test('空 json 文本省略键（未设置）；非 json 空串原样提交（显式空值）', () => {
    const struct = buildProviderStruct('smtp', [
      schemaField({ key: 'host', label: '服务地址', type: 'text', section: 'endpoint' }),
      schemaField({ key: 'metadata', label: '长尾键值', type: 'json', section: 'basic' }),
    ], {
      host: '',
      metadata: '',
    });
    expect(struct).toEqual({ type: 'smtp', host: '' });
    expect('metadata' in struct).toBe(false);
  });
});

describe('isProviderKeyTaken（§6 行 516 provider_key 唯一性预检）', () => {
  test('列表行集存在同 key → true；空 key / 无冲突 → false', () => {
    const rows = [
      create(ProviderSchema, { providerKey: 'wechat_mp' }),
      create(ProviderSchema, { providerKey: 'qq' }),
    ];
    expect(isProviderKeyTaken('wechat_mp', rows)).toBe(true);
    expect(isProviderKeyTaken('wx_new', rows)).toBe(false);
    expect(isProviderKeyTaken('', rows)).toBe(false);
    expect(isProviderKeyTaken('wechat_mp', [])).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// JsonEditor 静态渲染（零 Semi 依赖 → renderToStaticMarkup）
// ---------------------------------------------------------------------------

describe('JsonEditor（静态渲染：受控文本域 + 无障碍标签 + 禁用）', () => {
  test('渲染 value 文本 + aria-label；disabled 输出 disabled 属性', () => {
    const markup = renderToStaticMarkup(
      createElement(JsonEditor, {
        value: '{"nickname": "$.name"}',
        onChange: () => {},
        disabled: false,
        ariaLabel: '字段映射',
      }),
    );
    expect(markup).toContain('{&quot;nickname&quot;: &quot;$.name&quot;}');
    expect(markup).toContain('aria-label="字段映射"');
    expect(markup).not.toContain('disabled');

    const disabled = renderToStaticMarkup(
      createElement(JsonEditor, {
        value: '',
        onChange: () => {},
        disabled: true,
        ariaLabel: '长尾键值',
      }),
    );
    expect(disabled).toContain('disabled');
  });
});

// ---------------------------------------------------------------------------
// api Provider 编辑族 msw（§5.2 行 1169-1177；读路径真调 + 写路径
// 请求体 wire 校验，msw 走真实 transport 归一链）
// ---------------------------------------------------------------------------

describe('api.getProviderTypes（§5.2 行 1175：type 下拉数据源）', () => {
  test('Connect 协议 POST → ProviderTypesResponse 解码（displayName camelCase）', async () => {
    server.use(
      http.post(GET_PROVIDER_TYPES_URL, () =>
        HttpResponse.json({
          items: [
            { type: 'wechat_mp', category: 'oauth', displayName: '微信小程序' },
            { type: 'smtp', category: 'email', displayName: 'SMTP' },
          ],
        }),
      ),
    );
    const res = await apiMod.getProviderTypes();
    expect(res.items).toHaveLength(2);
    expect(res.items[0].type).toBe('wechat_mp');
    expect(res.items[0].category).toBe('oauth');
    expect(res.items[0].displayName).toBe('微信小程序');
    expect(res.items[1].displayName).toBe('SMTP');
  });
});

describe('api.getProviderSchema（§5.2 行 1176 / §5.3：动态表单 schema）', () => {
  test('{type} 请求体 wire + SchemaResponse 解码（fields / default Value / options）', async () => {
    let requestBody: unknown;
    server.use(
      http.post(GET_PROVIDER_SCHEMA_URL, async ({ request }) => {
        requestBody = await request.json();
        return HttpResponse.json({
          type: 'wechat_mp',
          category: 'oauth',
          fields: [
            { key: 'provider_key', label: '唯一标识', type: 'text', section: 'basic', required: true, pattern: '^[a-z0-9_]+$' },
            { key: 'ui_group', label: '展示分组', type: 'select', section: 'display', options: ['social', 'enterprise', 'dev', 'other'], default: 'social' },
            { key: 'is_enabled', label: '启用', type: 'checkbox', section: 'policy', default: true },
            { key: 'user_mapping', label: '字段映射', type: 'json', section: 'endpoint', advanced: true },
          ],
        });
      }),
    );
    const res = await apiMod.getProviderSchema(
      create(GetProviderSchemaRequestSchema, { type: 'wechat_mp' }),
    );
    expect(requestBody).toEqual({ type: 'wechat_mp' });
    expect(res.type).toBe('wechat_mp');
    expect(res.category).toBe('oauth');
    expect(res.fields).toHaveLength(4);
    expect(res.fields[0].required).toBe(true);
    expect(res.fields[0].pattern).toBe('^[a-z0-9_]+$');
    expect(res.fields[1].options).toEqual(['social', 'enterprise', 'dev', 'other']);
    // default = google.protobuf.Value（protojson → kind oneof）。
    expect(res.fields[1].default?.kind.case).toBe('stringValue');
    expect(res.fields[1].default?.kind.value).toBe('social');
    expect(res.fields[2].default?.kind.case).toBe('boolValue');
    expect(res.fields[2].default?.kind.value).toBe(true);
    expect(res.fields[3].advanced).toBe(true);
    // 修饰零值省略（protojson）：advanced=false 解码为 false。
    expect(res.fields[0].advanced).toBe(false);
  });
});

describe('api.getProvider（§5.2 行 1170：详情返回明文凭证）', () => {
  test('AdminProvider 解码（int64 十进制字符串 → bigint + ext Struct → JsonObject）', async () => {
    let requestBody: unknown;
    server.use(
      http.post(GET_PROVIDER_URL, async ({ request }) => {
        requestBody = await request.json();
        return HttpResponse.json({
          providerKey: 'wx1',
          displayName: '微信',
          category: 'oauth',
          type: 'wechat_mp',
          enableSignin: true,
          sortOrder: '3',
          ext: { client_id: 'wx-123', user_mapping: { nickname: '$.name' } },
        });
      }),
    );
    const res = await apiMod.getProvider(
      create(GetProviderRequestSchema, { providerKey: 'wx1' }),
    );
    expect(requestBody).toEqual({ providerKey: 'wx1' });
    expect(res.providerKey).toBe('wx1');
    expect(res.sortOrder).toBe(BigInt(3));
    expect(res.ext?.client_id).toBe('wx-123');
    expect(res.ext?.user_mapping).toEqual({ nickname: '$.name' });
    // protojson 零值省略 → false。
    expect(res.isEnabled).toBe(false);
  });
});

describe('api.createProvider / updateProvider（§5.2 行 1169/1171：Struct 平铺提交体）', () => {
  test('JsonObject → Struct wire 平铺（type 顶层 + json 对象）→ OkResponse', async () => {
    let createBody: unknown;
    server.use(
      http.post(CREATE_PROVIDER_URL, async ({ request }) => {
        createBody = await request.json();
        return HttpResponse.json({});
      }),
    );
    const res = await apiMod.createProvider({
      type: 'wechat_mp',
      provider_key: 'wx_new',
      display_name: '新微信',
      client_id: 'wx-123',
      user_mapping: { nickname: '$.name' },
      is_enabled: false,
    });
    expect(createBody).toEqual({
      type: 'wechat_mp',
      provider_key: 'wx_new',
      display_name: '新微信',
      client_id: 'wx-123',
      user_mapping: { nickname: '$.name' },
      // Struct JSON 表示保留显式 false（非 proto message 零值省略）。
      is_enabled: false,
    });
    expect(res.$typeName).toBe('api.admin.v1.OkResponse');
  });

  test('updateProvider：同一 Struct 形态（提交体平铺含 provider_key 定位）', async () => {
    let updateBody: unknown;
    server.use(
      http.post(UPDATE_PROVIDER_URL, async ({ request }) => {
        updateBody = await request.json();
        return HttpResponse.json({});
      }),
    );
    const res = await apiMod.updateProvider({
      type: 'smtp',
      provider_key: 'eml_main',
      display_name: '邮件主通道',
      host: 'smtp.example.com',
    });
    expect(updateBody).toEqual({
      type: 'smtp',
      provider_key: 'eml_main',
      display_name: '邮件主通道',
      host: 'smtp.example.com',
    });
    expect(res.$typeName).toBe('api.admin.v1.OkResponse');
  });
});

describe('api.testProvider（§5.2 行 1177：发送测试 {providerKey, target}）', () => {
  test('请求体 wire 校验 → OkResponse；500 reject → ApiError', async () => {
    let requestBody: unknown;
    server.use(
      http.post(TEST_PROVIDER_URL, async ({ request }) => {
        requestBody = await request.json();
        return HttpResponse.json({});
      }),
    );
    const res = await apiMod.testProvider(
      create(TestProviderRequestSchema, { providerKey: 'sms_main', target: '13800000000' }),
    );
    expect(requestBody).toEqual({ providerKey: 'sms_main', target: '13800000000' });
    expect(res.$typeName).toBe('api.admin.v1.OkResponse');

    server.use(
      http.post(TEST_PROVIDER_URL, () => new HttpResponse(null, { status: 500 })),
    );
    let caught: unknown;
    try {
      await apiMod.testProvider(
        create(TestProviderRequestSchema, { providerKey: 'sms_main', target: 'x' }),
      );
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(ApiError);
    expect((caught as ApiError).httpStatus).toBe(500);
  });
});

// ---------------------------------------------------------------------------
// api 用户管理族 msw（§5.4 行 1249-1255；后端已实装，读路径
// 真调语义 → msw 走真实 transport 归一链；写路径校验请求体 wire 形态）
// ---------------------------------------------------------------------------

describe('api.listUsers（§5.4 行 1249：筛选 {q, userStatus} + 分页 §1.7）', () => {
  test('请求体 wire（q + userStatus 单选 + 分页/排序）→ UserListResponse 解码（AdminUser int64 → bigint；零值省略 → 零值）', async () => {
    let requestBody: unknown;
    server.use(
      http.post(LIST_USERS_URL, async ({ request }) => {
        requestBody = await request.json();
        return HttpResponse.json({
          items: [
            {
              id: '2',
              username: 'zhang',
              nickname: '张三',
              phone: '13800000000',
              email: 'zhang@test.dev',
              phoneVerified: '1',
              emailVerified: '1',
              userStatus: '1',
              mfaRequired: '0',
              lastLoginAt: '1730000000',
              createdAt: '1720000000',
            },
            {
              // 禁用用户：字符串 / 计数零值省略（protojson）→ 解码零值。
              id: '3',
              username: 'li',
              userStatus: '0',
            },
          ],
          total: '2',
          page: '1',
          pageSize: '20',
        });
      }),
    );

    const query: TableQueryState = {
      ...initialTableQuery(),
      sort: 'created_at',
      order: 'desc',
      filters: { user_status: ['1'] },
    };
    const res = await apiMod.listUsers(apiMod.buildListUsersRequest('张', query));

    // 请求体：optional 字段显式下发（int64 → 十进制字符串）。
    expect(requestBody).toEqual({
      q: '张',
      userStatus: '1',
      page: '1',
      pageSize: '20',
      sort: 'created_at',
      order: 'desc',
    });
    expect(res.total).toBe(BigInt(2));
    expect(res.items).toHaveLength(2);
    expect(res.items[0].id).toBe(BigInt(2));
    expect(res.items[0].userStatus).toBe(BigInt(1));
    expect(res.items[0].lastLoginAt).toBe(BigInt(1730000000));
    expect(res.items[1].userStatus).toBe(BigInt(0));
    expect(res.items[1].nickname).toBe('');
    expect(res.items[1].emailVerified).toBe(BigInt(0));
  });

  test('500 → ApiError 归一（非 401：页面错误态，不跳登录）', async () => {
    server.use(
      http.post(LIST_USERS_URL, () => new HttpResponse(null, { status: 500 })),
    );
    let caught: unknown;
    try {
      await apiMod.listUsers(apiMod.buildListUsersRequest('', initialTableQuery()));
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(ApiError);
    expect((caught as ApiError).httpStatus).toBe(500);
    expect(apiMod.isUnauthenticatedError(caught)).toBe(false);
  });
});

describe('api.getUser（§5.4 行 1250：{id} 详情含凭证概览 / 绑定 / MFA 状态）', () => {
  test('请求体 {id} + UserDetailResponse 解码（嵌套 AdminUser / credentials / bindings / 跨包 mfa）', async () => {
    let requestBody: unknown;
    server.use(
      http.post(GET_USER_URL, async ({ request }) => {
        requestBody = await request.json();
        return HttpResponse.json({
          user: {
            id: '2',
            username: 'zhang',
            nickname: '张三',
            userStatus: '1',
            mfaRequired: '1',
            createdAt: '1720000000',
          },
          credentials: [
            { id: '10', kind: 'password', label: '', isEnabled: true, createdAt: '1720000000' },
            { id: '11', kind: 'totp', label: '主手机', isEnabled: false },
          ],
          bindings: [
            {
              id: '20',
              providerKey: 'wechat_mp',
              openId: 'oX-123',
              unionId: 'u-1',
              nickname: '微信张三',
              createdAt: '1720000100',
            },
          ],
          mfa: {
            factors: [
              { factor: 'totp', bound: true, boundAt: '1720000200' },
              { factor: 'otp_sms', bound: false },
            ],
          },
        });
      }),
    );

    const res = await apiMod.getUser(apiMod.buildGetUserRequest(BigInt(2)));

    expect(requestBody).toEqual({ id: '2' });
    expect(res.user?.id).toBe(BigInt(2));
    expect(res.user?.username).toBe('zhang');
    expect(res.user?.mfaRequired).toBe(BigInt(1));
    expect(res.credentials).toHaveLength(2);
    expect(res.credentials[0].kind).toBe('password');
    expect(res.credentials[0].isEnabled).toBe(true);
    expect(res.credentials[1].isEnabled).toBe(false);
    expect(res.credentials[1].createdAt).toBe(BigInt(0)); // 零值省略 → 0n
    expect(res.bindings).toHaveLength(1);
    expect(res.bindings[0].providerKey).toBe('wechat_mp');
    expect(res.bindings[0].createdAt).toBe(BigInt(1720000100));
    expect(res.mfa?.factors).toHaveLength(2);
    expect(res.mfa?.factors[0].bound).toBe(true);
    expect(res.mfa?.factors[0].boundAt).toBe(BigInt(1720000200));
    expect(res.mfa?.factors[1].bound).toBe(false);
  });

  test('404（带 Connect JSON 体，msw 既有口径）→ ApiError not_found → 通用文案（不暴露管理面语义）', async () => {
    // connect-go 拦截器真实 wire 形态：HTTP 404 + Connect 错误 JSON 体
    //（空 body 会被 connect-web 按协议状态兜底表映射 Unimplemented）。
    server.use(
      http.post(GET_USER_URL, () =>
        new HttpResponse(JSON.stringify({ code: 'not_found', message: 'user not found' }), {
          status: 404,
          headers: { 'content-type': 'application/json' },
        }),
      ),
    );

    let caught: unknown;
    try {
      await apiMod.getUser(apiMod.buildGetUserRequest(BigInt(999)));
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(ApiError);
    expect((caught as ApiError).httpStatus).toBe(404);
    expect((caught as ApiError).code).toBe('not_found');
    expect(apiMod.apiErrorText(caught)).toBe('资源不存在');
  });
});

describe('api.updateUserStatus（§5.4 行 1251：{id, userStatus: 0 或 1} → OkResponse）', () => {
  test('启用 → wire {id, userStatus:"1"}；禁用 → userStatus 零值省略（wire 无键，后端读零值即禁用）', async () => {
    const bodies: unknown[] = [];
    server.use(
      http.post(UPDATE_USER_STATUS_URL, async ({ request }) => {
        bodies.push(await request.json());
        return HttpResponse.json({});
      }),
    );

    const enable = await apiMod.updateUserStatus(
      apiMod.buildUpdateUserStatusRequest(BigInt(2), true),
    );
    const disable = await apiMod.updateUserStatus(
      apiMod.buildUpdateUserStatusRequest(BigInt(3), false),
    );

    expect(bodies[0]).toEqual({ id: '2', userStatus: '1' });
    // 非 optional int64 零值省略（§1.0 零值缺省）——语义即禁用（值域 0|1）。
    expect(bodies[1]).toEqual({ id: '3' });
    expect(enable.$typeName).toBe('api.admin.v1.OkResponse');
    expect(disable.$typeName).toBe('api.admin.v1.OkResponse');
  });

  test('500 reject → ApiError（DataTable 行内开关回滚触发链：消费方 catch 展示后 rethrow）', async () => {
    server.use(
      http.post(UPDATE_USER_STATUS_URL, () => new HttpResponse(null, { status: 500 })),
    );
    let caught: unknown;
    try {
      await apiMod.updateUserStatus(
        apiMod.buildUpdateUserStatusRequest(BigInt(2), true),
      );
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(ApiError);
    expect((caught as ApiError).httpStatus).toBe(500);
  });
});

describe('api.resetUserPassword（§5.4 行 1252：{id, password} → OkResponse 仅成功，无新密码返回）', () => {
  test('请求体 wire 校验 → OkResponse；500 reject → ApiError（password_weak 等策略错误由服务端权威判定）', async () => {
    let requestBody: unknown;
    server.use(
      http.post(RESET_USER_PASSWORD_URL, async ({ request }) => {
        requestBody = await request.json();
        return HttpResponse.json({});
      }),
    );
    const res = await apiMod.resetUserPassword(
      apiMod.buildResetUserPasswordRequest(BigInt(2), 'NewPass!23'),
    );
    expect(requestBody).toEqual({ id: '2', password: 'NewPass!23' });
    expect(res.$typeName).toBe('api.admin.v1.OkResponse');

    server.use(
      http.post(RESET_USER_PASSWORD_URL, () => new HttpResponse(null, { status: 500 })),
    );
    let caught: unknown;
    try {
      await apiMod.resetUserPassword(
        apiMod.buildResetUserPasswordRequest(BigInt(2), 'weak'),
      );
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(ApiError);
    expect((caught as ApiError).httpStatus).toBe(500);
  });
});

describe('api.unbindUserThirdparty（§5.4 行 1253：{id, providerKey}）', () => {
  test('请求体 wire 校验 → OkResponse；500 reject → ApiError（Union 行不可单独解绑由服务端 invalid_request 兜底）', async () => {
    let requestBody: unknown;
    server.use(
      http.post(UNBIND_USER_THIRDPARTY_URL, async ({ request }) => {
        requestBody = await request.json();
        return HttpResponse.json({});
      }),
    );
    const res = await apiMod.unbindUserThirdparty(
      apiMod.buildUnbindUserThirdpartyRequest(BigInt(2), 'wechat_mp'),
    );
    expect(requestBody).toEqual({ id: '2', providerKey: 'wechat_mp' });
    expect(res.$typeName).toBe('api.admin.v1.OkResponse');

    server.use(
      http.post(UNBIND_USER_THIRDPARTY_URL, () => new HttpResponse(null, { status: 500 })),
    );
    let caught: unknown;
    try {
      await apiMod.unbindUserThirdparty(
        apiMod.buildUnbindUserThirdpartyRequest(BigInt(2), 'x'),
      );
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(ApiError);
    expect((caught as ApiError).httpStatus).toBe(500);
  });
});

describe('api.unlockUser（§5.4 行 1254：{id} 解除登录限制）', () => {
  test('请求体 wire 校验 → OkResponse', async () => {
    let requestBody: unknown;
    server.use(
      http.post(UNLOCK_USER_URL, async ({ request }) => {
        requestBody = await request.json();
        return HttpResponse.json({});
      }),
    );
    const res = await apiMod.unlockUser(apiMod.buildUnlockUserRequest(BigInt(2)));
    expect(requestBody).toEqual({ id: '2' });
    expect(res.$typeName).toBe('api.admin.v1.OkResponse');
  });
});

describe('api.getUserEvents（§5.4 行 1255：{id} + 分页 §1.7）', () => {
  test('请求体 wire（id + 分页/排序）→ UserEventsResponse 解码（EventItem 含 Struct detail）', async () => {
    let requestBody: unknown;
    server.use(
      http.post(GET_USER_EVENTS_URL, async ({ request }) => {
        requestBody = await request.json();
        return HttpResponse.json({
          items: [
            {
              id: '30',
              event: 'login_success',
              actorType: 'user',
              actorId: '2',
              userId: '2',
              amr: 'pwd',
              ip: '203.0.113.1',
              ua: 'Mozilla/5.0',
              detail: { client: 'web' },
              createdAt: '1730000100',
            },
          ],
          total: '1',
          page: '1',
          pageSize: '20',
        });
      }),
    );

    const query: TableQueryState = {
      ...initialTableQuery(),
      sort: 'created_at',
      order: 'desc',
    };
    const res = await apiMod.getUserEvents(apiMod.buildGetUserEventsRequest(BigInt(2), query));

    expect(requestBody).toEqual({
      id: '2',
      page: '1',
      pageSize: '20',
      sort: 'created_at',
      order: 'desc',
    });
    expect(res.total).toBe(BigInt(1));
    expect(res.items).toHaveLength(1);
    expect(res.items[0].id).toBe(BigInt(30));
    expect(res.items[0].event).toBe('login_success');
    expect(res.items[0].createdAt).toBe(BigInt(1730000100));
    expect(res.items[0].detail?.client).toBe('web');
  });
});

// ---------------------------------------------------------------------------
// 请求构造纯函数（落位 api.ts，adminDisplayName 同口径）
// ---------------------------------------------------------------------------

describe('buildListUsersRequest（§5.4 行 1249 + §1.7 行 275-278）', () => {
  test('q 去首尾空白、空即省略；userStatus 筛选恰好单选才下发；分页直映射', () => {
    const base = initialTableQuery();

    // 空 q + 无筛选：仅分页。
    const plain = apiMod.buildListUsersRequest('   ', base);
    expect(plain.q).toBeUndefined();
    expect(plain.userStatus).toBeUndefined();
    expect(plain.page).toBe(BigInt(1));
    expect(plain.pageSize).toBe(BigInt(20));
    expect(plain.sort).toBeUndefined();
    expect(plain.order).toBeUndefined();

    // q 去空白 + 禁用筛选（'0' 显式下发：optional 字段零值保留 presence）。
    const disabled = apiMod.buildListUsersRequest('  张  ', {
      ...base,
      filters: { user_status: ['0'] },
    });
    expect(disabled.q).toBe('张');
    expect(disabled.userStatus).toBe(BigInt(0));

    // 筛选多选（等价全集）/ 未选 → 不过滤。
    expect(
      apiMod.buildListUsersRequest('', { ...base, filters: { user_status: ['0', '1'] } })
        .userStatus,
    ).toBeUndefined();
    expect(
      apiMod.buildListUsersRequest('', { ...base, filters: { user_status: [] } }).userStatus,
    ).toBeUndefined();
  });

  test('排序仅 order 非空时下发（dataTableLogic：清除排序后 order=""，sort 保留但不下发）', () => {
    const sorted = apiMod.buildListUsersRequest('', {
      ...initialTableQuery(),
      sort: 'last_login_at',
      order: 'desc',
    });
    expect(sorted.sort).toBe('last_login_at');
    expect(sorted.order).toBe('desc');

    const cleared = apiMod.buildListUsersRequest('', {
      ...initialTableQuery(),
      sort: 'last_login_at',
      order: '',
    });
    expect(cleared.sort).toBeUndefined();
    expect(cleared.order).toBeUndefined();
  });
});

describe('buildGetUserEventsRequest / buildGetUserRequest / 其余 buildXxxRequest（请求构造纯函数）', () => {
  test('buildGetUserEventsRequest：id + 分页直映射 + 排序口径同 ListUsers', () => {
    const req = apiMod.buildGetUserEventsRequest(BigInt(7), {
      ...initialTableQuery(),
      sort: 'created_at',
      order: 'desc',
    });
    expect(req.id).toBe(BigInt(7));
    expect(req.page).toBe(BigInt(1));
    expect(req.pageSize).toBe(BigInt(20));
    expect(req.sort).toBe('created_at');
    expect(req.order).toBe('desc');

    const unsorted = apiMod.buildGetUserEventsRequest(BigInt(7), initialTableQuery());
    expect(unsorted.sort).toBeUndefined();
    expect(unsorted.order).toBeUndefined();
  });

  test('buildUpdateUserStatusRequest：true → 1n / false → 0n（wire 零值省略语义见 msw 用例）', () => {
    expect(apiMod.buildUpdateUserStatusRequest(BigInt(2), true).userStatus).toBe(BigInt(1));
    expect(apiMod.buildUpdateUserStatusRequest(BigInt(2), false).userStatus).toBe(BigInt(0));
  });

  test('buildGetUserRequest / buildResetUserPasswordRequest / buildUnbindUserThirdpartyRequest / buildUnlockUserRequest：字段直映射', () => {
    expect(apiMod.buildGetUserRequest(BigInt(9)).id).toBe(BigInt(9));
    const reset = apiMod.buildResetUserPasswordRequest(BigInt(9), 'p@ss');
    expect(reset.id).toBe(BigInt(9));
    expect(reset.password).toBe('p@ss');
    const unbind = apiMod.buildUnbindUserThirdpartyRequest(BigInt(9), 'qq');
    expect(unbind.id).toBe(BigInt(9));
    expect(unbind.providerKey).toBe('qq');
    expect(apiMod.buildUnlockUserRequest(BigInt(9)).id).toBe(BigInt(9));
  });
});

// ---------------------------------------------------------------------------
// 展示纯函数（§9 第 18 条零值兜底；node 可测）
// ---------------------------------------------------------------------------

describe('userStatusLabel / USER_STATUS_FILTERS（§5.4 行 1251 值域 1/0）', () => {
  test('1n → 正常；0n → 禁用；筛选值与文案对齐', () => {
    expect(apiMod.userStatusLabel(BigInt(1))).toBe('正常');
    expect(apiMod.userStatusLabel(BigInt(0))).toBe('禁用');
    expect(apiMod.USER_STATUS_FILTERS).toEqual([
      { value: '1', text: '正常' },
      { value: '0', text: '禁用' },
    ]);
  });
});

describe('credentialKindLabel / mfaFactorLabel（kind / factor 值域 + 新增值原样兜底）', () => {
  test('已知 kind → 文案；未知值原样返回（跨版本新增，§12.9 行 1754）', () => {
    expect(apiMod.credentialKindLabel('password')).toBe('密码');
    expect(apiMod.credentialKindLabel('totp')).toBe('TOTP 动态码');
    expect(apiMod.credentialKindLabel('webauthn')).toBe('通行密钥');
    expect(apiMod.credentialKindLabel('recovery_code')).toBe('恢复码');
    // §4.3 行 669 五值域第五值：GetUser 凭证概览含 mfa_setting 行。
    expect(apiMod.credentialKindLabel('mfa_setting')).toBe('MFA 开关');
    expect(apiMod.credentialKindLabel('passkey_v2')).toBe('passkey_v2');
  });

  test('已知 factor → 文案；未知值原样返回', () => {
    expect(apiMod.mfaFactorLabel('totp')).toBe('TOTP 动态码');
    expect(apiMod.mfaFactorLabel('otp_sms')).toBe('短信验证码');
    expect(apiMod.mfaFactorLabel('otp_email')).toBe('邮箱验证码');
    expect(apiMod.mfaFactorLabel('webauthn')).toBe('通行密钥');
    expect(apiMod.mfaFactorLabel('recovery_code')).toBe('恢复码');
    expect(apiMod.mfaFactorLabel('future_kind')).toBe('future_kind');
  });
});

describe('boundMfaFactors（§5.4 行 1250「MFA 状态」：已绑定因子文案列表）', () => {
  test('只取 bound=true 的因子文案；mfa 缺省 / 无绑定 → 空数组', () => {
    const mfa = create(MfaResponseSchema, {
      factors: [
        { factor: 'totp', bound: true },
        { factor: 'otp_sms', bound: false },
        { factor: 'webauthn', bound: true },
        { factor: 'future_kind', bound: true },
      ],
    });
    expect(apiMod.boundMfaFactors(mfa)).toEqual(['TOTP 动态码', '通行密钥', 'future_kind']);
    expect(apiMod.boundMfaFactors(undefined)).toEqual([]);
    expect(apiMod.boundMfaFactors(create(MfaResponseSchema, {}))).toEqual([]);
  });
});

describe('formatUnixTime（§9 第 18 条零值兜底；时区无关断言）', () => {
  test('零值 / 负值 → 占位符；正值 → YYYY-MM-DD HH:mm 本地时间', () => {
    expect(apiMod.formatUnixTime(BigInt(0))).toBe('—');
    expect(apiMod.formatUnixTime(BigInt(-1))).toBe('—');
    const formatted = apiMod.formatUnixTime(BigInt(1730000000));
    expect(formatted).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$/);
    // 与 Date 本地渲染年份一致（跨时区稳定断言）。
    const d = new Date(1730000000 * 1000);
    expect(formatted.startsWith(`${d.getFullYear()}-`)).toBe(true);
  });
});

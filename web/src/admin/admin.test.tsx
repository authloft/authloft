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
import { setLocale, t } from '../shared/i18n';
import { moveItem, SortableList } from './components/SortableList';
import {
  ProviderCallbackHint,
  isOidcProviderType,
  providerCallbackUrl,
} from './components/ProviderCallbackHint';
import { JsonEditor } from './components/JsonEditor';
import {
  StringListEditor,
  appendListItem,
  removeListItem,
  replaceListItem,
} from './components/StringListEditor';
import {
  SECTION_ORDER,
  SECTION_TITLES,
  adminProviderToValues,
  applySchemaDefaults,
  buildProviderStruct,
  groupFieldsBySection,
  initialCreateValues,
  isProviderKeyTaken,
  validateSchemaValues,
} from './schema/schemaLogic';
import { SettingsResponseSchema } from '../gen/proto/api/admin/v1/settings_pb';
import {
  DEFAULT_SETTINGS,
  getHttpsDeploymentOptions,
  getLoginMethodOptions,
  getMfaMethodOptions,
  getSettingsSections,
  draftFromSettings,
  settingsDraftIssue,
} from './settingsLogic';

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
 * 客户端管理族追加（接口文档 §5.5 行 1257-1268；后端已
 * 实装，读路径真调语义 → msw 走真实 transport 归一链）：
 * - api 十方法 msw：List / Get 读路径解码（SsoClient / OidcClient：明文
 *   secret + redirectUris / scopes + TTL int64 → bigint）+ Create / Update /
 *   Delete 请求体 wire 校验（clientId 空串省略=服务端生成、clientSecret
 *   Create 不下发 / Update 留空省略=保留、PATCH 空组 / 空串省略=保留原值、
 *   OIDC TTL 0 省略=库端默认 / 保留原值）+ 404 带 Connect JSON 体口径；
 * - 请求构造纯函数：buildListXxxClientsRequest（排序仅 order 非空下发）/
 *   buildCreate / Update / DeleteXxxClientRequest；
 * - 校验 / 展示纯函数：cleanStringList / redirectUrisIssue / scopesIssue /
 *   parseTtlField（条目规则与 TTL 值域）/ summarizeList /
 *   humanizeTtlSeconds / tokenTtlSummary / ttlDetailText；
 * - StringListEditor：静态渲染（零 Semi 依赖）+ replace/remove/appendListItem
 *   不可变编排纯函数（moveItem 同口径）。
 * SsoClientsPage / OidcClientsPage 渲染不可测（同上 Blocker）。
 *
 * 追加 settings 族测试（接口文档 §5.6 行 1287-1363 settings 族；后端已实装
 * 全量投影 / 全量替换，读路径真调语义 → msw 走真实 transport 归一链）：
 * - api.getSettings msw：SettingsResponse 读路径解码（int64 十进制字符串 →
 *   bigint + repeated + protojson 零值省略 → proto 零值）+ 500 → ApiError；
 * - api.setSettings msw：请求体 wire 校验——**全量替换语义**（36 键整体提交、
 *   不能只提交改动字段；零值键 wire 省略 = 服务端读零值 = 写入零值，与
 *   后端实装语义等价）；
 * - settingsLogic 纯函数全集：DEFAULT_SETTINGS 默认值对 §5.6 四张表逐字 /
 *   getSettingsSections 36 键全覆盖无重复 / draftFromSettings 全键映射与
 *   零值即真值（全量替换对称面）/ settingsDraftIssue 交叉校验（行 1363
 *   前端自律：非负整数 / 字符类数 1-3 / min ≤ max ≤ 64 / https_deployment
 *   三态行 1361）；
 * - buildSetSettingsRequest 全量构造：文本 trim / 列表清洗 / number → bigint。
 * SettingsPage 渲染不可测（同上 Blocker）。
 * ⚠️ https_deployment（=36）双端 proto / 生成物已先行落地，
 * 与文档定稿一致 → 随本实现建键；行 1361 非三态 → invalid_request
 * 由 settingsDraftIssue 前端自律拦截（缺该键的全量提交会置空该键被后端拒收）。
 *
 * 追加工具三页族测试（接口文档 §5.6 行 1288-1290；后端已实装）：
 * - api 三方法 msw：ListEvents（login_records 预设强制 event=login_success +
 *   六筛选 wire + EventItem 全字段解码含零值省略）/ DecodeToken（{token,
 *   purpose} wire + Struct 载荷解码 + 400 Connect 错误体 → ApiError
 *   invalid_argument）/ GetStatus（int64 十进制 → bigint + 零值省略 → 0n）；
 * - 请求构造纯函数：buildListEventsRequest（预设强制 / 缺省全省略 / 排序仅
 *   order 非空下发）/ buildDecodeTokenRequest（token 去首尾空白）；
 * - 展示纯函数：eventTypeLabel / actorTypeLabel / actorText（system 不附
 *   actor_id=0）/ bigIdText / eventDetailText / decodePayloadText +
 *   EVENT_TYPE_FILTERS 值域锚定《后端架构》§4.6（event 列 16 常量 + 行 809
 *   oidc_authorize_no_state，共 17 项；跨版本新增经 fallback 兜底不进下拉）。
 * ⚠️「敏感操作」预设曾暂缓（事件类型集合未定义封闭集）——先按需求
 *   §4.6 行 260 定稿口径落地三类，后扩为 2026-11-06 定稿五类封闭集
 *   （改密 / 重置密码 / 解绑 / 启用/停用两步验证，
 *   admin_reset_password 不入集）；ListEvents 的 event 系 optional string
 *   单值（events.proto）→ 预设为前端组装概念：SENSITIVE_RECORDS_EVENTS
 *   值域锚定 + 进预设出集默认 change_password（eventTypeFilterOptions /
 *   resolveEventFilterOnPreset 预设映射收口 ./api，渲染不可测同上 Blocker）；
 *   构造函数零改动（sensitive_records 与 all 同分支，wire 单值见
 *   下文 describe）。
 * AuditPage / StatusPage / DecodePage 渲染不可测（同上 Blocker）。
 *
 * 追加（admin 增强收尾）：四项筛选 UI 已暴露（上段「归后续
 * 增强」销账）——AuditPage 内联换算（idInputToFilter：^\d+$ → BigInt；
 * dateToUnixFilter：Date → Unix 秒）紧贴 Semi 控件值形态落页面文件，渲染
 * 不可测（同上 Blocker）；本文件锚定 UI 换算产物形态的请求链：
 * - listEvents msw：all 预设 × actorId/userId/from/to → wire 十进制字符串
 *   （§1.12，超 2^53 ID 逐字符保真）；
 * - buildListEventsRequest：login_records 预设 × 四项叠加照常下发
 *   （event 让位、四项不让位 → UI 预设下不禁用）；
 * - getMe avatarUrl 零值省略 → 解码空串（AdminLayout 空串回退文字头像
 *   的数据面；携带 avatarUrl 的解码已在既有用例断言）。
 * AdminLayout / AuditPage 渲染不可测（同上 Blocker）。
 *
 * 【Blocker·已解除】routes / AdminLayout / entry / ProvidersPage / StatusSwitch 的
 * 渲染测试曾无法落地（@douyinfe/semi-ui-19 lib/es 无扩展名 import →
 * rstest 0.12.5 externalize 下 node ESM 模块图崩，实测，见
 * account.test.tsx 头注）——**测试链已修复**（define.test
 * bundleDependencies + ProvidePlugin），路由兜底真渲染断言见文末 routes
 * describe；可测逻辑最小化收口 api.ts / bootstrap.ts / 零 Semi 组件的
 * 口径不变；StatusSwitch 的乐观更新 / 回滚编排在 shared/app-ui/
 * dataTableLogic（已有测试覆盖）。
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
const LIST_SSO_CLIENTS_URL = `${BASE}/api.admin.v1.AdminService/ListSsoClients`;
const CREATE_SSO_CLIENT_URL = `${BASE}/api.admin.v1.AdminService/CreateSsoClient`;
const GET_SSO_CLIENT_URL = `${BASE}/api.admin.v1.AdminService/GetSsoClient`;
const UPDATE_SSO_CLIENT_URL = `${BASE}/api.admin.v1.AdminService/UpdateSsoClient`;
const DELETE_SSO_CLIENT_URL = `${BASE}/api.admin.v1.AdminService/DeleteSsoClient`;
const LIST_OIDC_CLIENTS_URL = `${BASE}/api.admin.v1.AdminService/ListOidcClients`;
const CREATE_OIDC_CLIENT_URL = `${BASE}/api.admin.v1.AdminService/CreateOidcClient`;
const GET_OIDC_CLIENT_URL = `${BASE}/api.admin.v1.AdminService/GetOidcClient`;
const UPDATE_OIDC_CLIENT_URL = `${BASE}/api.admin.v1.AdminService/UpdateOidcClient`;
const DELETE_OIDC_CLIENT_URL = `${BASE}/api.admin.v1.AdminService/DeleteOidcClient`;
const GET_SETTINGS_URL = `${BASE}/api.admin.v1.AdminService/GetSettings`;
const SET_SETTINGS_URL = `${BASE}/api.admin.v1.AdminService/SetSettings`;
const LIST_EVENTS_URL = `${BASE}/api.admin.v1.AdminService/ListEvents`;
const DECODE_TOKEN_URL = `${BASE}/api.admin.v1.AdminService/DecodeToken`;
const GET_STATUS_URL = `${BASE}/api.admin.v1.AdminService/GetStatus`;

// rstest 对 .tsx 采用 classic JSX runtime，本文件渲染断言经 createElement
// 显式引用（不走 JSX 字面量，免全局 React stub；components.test.ts 头注口径）。
const { createElement } = React;

const server = setupServer();

let bootstrapMod: typeof import('./bootstrap');
let apiMod: typeof import('./api');
let routesMod: typeof import('./routes');

// routes 兜底渲染断言（文末 describe）专用：AdminLayout 的 GetMe 数据门
// （F-067 加载态 Spin）在 renderToStaticMarkup 下恒落于 loading 分支（effects
// 不执行、useRequest 无数据），children 永不到达——故对「路由分派 + 兜底
// 内容」断言时把 AdminLayout 换成透明壳。仅桩布局壳，Semi Empty 等为真实渲染。
// rstest 仅支持同步工厂且工厂内不可引外部 import（hoisting）——函数组件直接
// 返回 children 即合法 ReactNode（React 19），数组首元素字符串充「经布局
// 挂载」标记，用于区分带布局 / 裸兜底两分支形态。
rs.mock('./layout/AdminLayout', () => ({
  AdminLayout: (props: { readonly children?: unknown }) => [
    '__ADMIN_LAYOUT_STUB__',
    props.children,
  ],
}));

beforeAll(async () => {
  server.listen({ onUnhandledRequest: 'error' });
  bootstrapMod = await import('./bootstrap');
  apiMod = await import('./api');
  routesMod = await import('./routes');
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

  test('loadAdminBootstrap：注入 al_root 空串 / 纯空白 → location.origin 兜底（壳注入空串合规，前端回落同源）', () => {
    const FALLBACK_ORIGIN = 'https://admin-fallback.test';
    // normalizeAlRoot 读全局 location（非 window.location）；node 单测环境
    // 经 stubGlobal 模拟浏览器站点源，afterEach 的 unstubAllGlobals 自动恢复。
    rs.stubGlobal('location', { origin: FALLBACK_ORIGIN });
    // beforeEach 已按顶层注入 stub window（BASE 非空），此处覆盖为空串注入。
    rs.stubGlobal('window', {
      location: { pathname: '/admin' },
      __AUTHLOFT_INIT__: { al_root: '' },
    });
    expect(bootstrapMod.loadAdminBootstrap()).toEqual({
      ok: true,
      alRoot: FALLBACK_ORIGIN,
      staticBase: '/assets/',
    });
    // 纯空白：trim 后归一为空，仍回落站点源（与 setup/bootstrap.ts 同口径）。
    rs.stubGlobal('window', {
      location: { pathname: '/admin' },
      __AUTHLOFT_INIT__: { al_root: '   ' },
    });
    expect(bootstrapMod.loadAdminBootstrap()).toEqual({
      ok: true,
      alRoot: FALLBACK_ORIGIN,
      staticBase: '/assets/',
    });
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

  test('avatarUrl 零值省略 → 解码空串（AdminLayout 空串回退文字头像的数据面）', async () => {
    server.use(
      http.post(GET_ME_URL, () =>
        // protojson 省略零值字段（§1.1）：avatarUrl / nickname 未下发。
        HttpResponse.json({ id: '1', username: 'admin', nickname: '', isAdmin: true }),
      ),
    );

    const res = await apiMod.getMe();

    // §9 第 18 条零值兜底：未下发 → ''；AdminLayout 空串分支 → 文字头像。
    expect(res.avatarUrl).toBe('');
    // 展示链不变：昵称缺省 → username 回落（adminDisplayName 既有语义）。
    expect(apiMod.adminDisplayName(res)).toBe('admin');
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
  test('1n → 正常；0n → 禁用；筛选值与文案对齐（textKey 形态）', () => {
    expect(apiMod.userStatusLabel(BigInt(1))).toBe('正常');
    expect(apiMod.userStatusLabel(BigInt(0))).toBe('禁用');
    expect(apiMod.USER_STATUS_FILTERS).toEqual([
      { value: '1', textKey: 'admin.userStatusEnabled' },
      { value: '0', textKey: 'admin.userStatusDisabled' },
    ]);
    // 渲染口径（消费方 map 同式）：textKey 经 t() 得当前语言文案。
    expect(apiMod.USER_STATUS_FILTERS.map(({ value, textKey }) => ({ value, text: t(textKey) }))).toEqual([
      { value: '1', text: '正常' },
      { value: '0', text: '禁用' },
    ]);
  });
});

describe('credentialKindLabel / mfaFactorLabel（kind / factor 值域 + 新增值原样兜底）', () => {
  test('已知 kind → 文案；未知值原样返回（跨版本新增，§12.9 行 1885）', () => {
    // 因子名复用 factors.* 既有键（'密码登录' / '动态口令'）。
    expect(apiMod.credentialKindLabel('password')).toBe('密码登录');
    expect(apiMod.credentialKindLabel('totp')).toBe('动态口令');
    expect(apiMod.credentialKindLabel('webauthn')).toBe('通行密钥');
    expect(apiMod.credentialKindLabel('recovery_code')).toBe('恢复码');
    // §4.3 行 669 五值域第五值：GetUser 凭证概览含 mfa_setting 行。
    expect(apiMod.credentialKindLabel('mfa_setting')).toBe('MFA 开关');
    expect(apiMod.credentialKindLabel('passkey_v2')).toBe('passkey_v2');
  });

  test('已知 factor → 文案；未知值原样返回', () => {
    expect(apiMod.mfaFactorLabel('totp')).toBe('动态口令');
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
    expect(apiMod.boundMfaFactors(mfa)).toEqual(['动态口令', '通行密钥', 'future_kind']);
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

// ---------------------------------------------------------------------------
// api 客户端管理族 msw（§5.5 行 1257-1268；后端已实装，读
// 路径真调语义 → msw 走真实 transport 归一链；写路径校验请求体 wire 形态）
// ---------------------------------------------------------------------------

describe('api.listSsoClients（§5.5 行 1261：分页 / 排序 §1.7）', () => {
  test('请求体 wire（排序仅 order 非空下发）→ SsoClientListResponse 解码（int64 → bigint + redirectUris 数组）', async () => {
    const bodies: unknown[] = [];
    server.use(
      http.post(LIST_SSO_CLIENTS_URL, async ({ request }) => {
        bodies.push(await request.json());
        return HttpResponse.json({
          items: [
            {
              id: '1',
              clientId: 'portal',
              clientSecret: 's-plaintext',
              name: '门户站',
              redirectUris: ['https://portal.test/cb', '*'],
              createdAt: '1720000000',
              updatedAt: '1720000100',
            },
          ],
          total: '1',
          page: '1',
          pageSize: '20',
        });
      }),
    );

    const sorted: TableQueryState = {
      ...initialTableQuery(),
      sort: 'created_at',
      order: 'desc',
    };
    const res = await apiMod.listSsoClients(apiMod.buildListSsoClientsRequest(sorted));
    expect(bodies[0]).toEqual({
      page: '1',
      pageSize: '20',
      sort: 'created_at',
      order: 'desc',
    });
    expect(res.total).toBe(BigInt(1));
    expect(res.items).toHaveLength(1);
    expect(res.items[0].id).toBe(BigInt(1));
    expect(res.items[0].clientId).toBe('portal');
    // 明文 secret 随列表行透出（后端投影口径）。
    expect(res.items[0].clientSecret).toBe('s-plaintext');
    expect(res.items[0].redirectUris).toEqual(['https://portal.test/cb', '*']);
    expect(res.items[0].createdAt).toBe(BigInt(1720000000));

    // 清除排序（order=''）→ sort / order 不下发（dataTableLogic 受控口径）。
    await apiMod.listSsoClients(apiMod.buildListSsoClientsRequest(initialTableQuery()));
    expect(bodies[1]).toEqual({ page: '1', pageSize: '20' });
  });

  test('500 → ApiError 归一（非 401：页面错误态，不跳登录）', async () => {
    server.use(
      http.post(LIST_SSO_CLIENTS_URL, () => new HttpResponse(null, { status: 500 })),
    );
    let caught: unknown;
    try {
      await apiMod.listSsoClients(apiMod.buildListSsoClientsRequest(initialTableQuery()));
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(ApiError);
    expect((caught as ApiError).httpStatus).toBe(500);
    expect(apiMod.isUnauthenticatedError(caught)).toBe(false);
  });
});

describe('api.getSsoClient（§5.5 行 1262：{id} → SsoClient 明文密钥）', () => {
  test('{id} 请求体 + SsoClient 解码（clientSecret 明文 = 全站唯一明文出口）', async () => {
    let requestBody: unknown;
    server.use(
      http.post(GET_SSO_CLIENT_URL, async ({ request }) => {
        requestBody = await request.json();
        return HttpResponse.json({
          id: '2',
          clientId: 'portal',
          clientSecret: 'secret-64-chars',
          name: '门户站',
          redirectUris: ['https://portal.test/cb'],
          createdAt: '1720000000',
          updatedAt: '1720000000',
        });
      }),
    );

    const res = await apiMod.getSsoClient(apiMod.buildGetSsoClientRequest(BigInt(2)));
    expect(requestBody).toEqual({ id: '2' });
    expect(res.$typeName).toBe('api.admin.v1.SsoClient');
    expect(res.clientId).toBe('portal');
    expect(res.clientSecret).toBe('secret-64-chars');
    expect(res.redirectUris).toEqual(['https://portal.test/cb']);
  });

  test('404（带 Connect JSON 体，msw 既有口径）→ ApiError not_found → 通用文案', async () => {
    server.use(
      http.post(GET_SSO_CLIENT_URL, () =>
        new HttpResponse(JSON.stringify({ code: 'not_found', message: 'client not found' }), {
          status: 404,
          headers: { 'content-type': 'application/json' },
        }),
      ),
    );
    let caught: unknown;
    try {
      await apiMod.getSsoClient(apiMod.buildGetSsoClientRequest(BigInt(999)));
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(ApiError);
    expect((caught as ApiError).httpStatus).toBe(404);
    expect((caught as ApiError).code).toBe('not_found');
    expect(apiMod.apiErrorText(caught)).toBe('资源不存在');
  });
});

describe('api.createSsoClient（§5.5 行 1261 → OkResponse；密钥服务端生成）', () => {
  test('clientId 空串省略（服务端生成）/ name 去空白 / redirectUris 清洗后整组；clientSecret 键不下发；500 reject → ApiError', async () => {
    let requestBody: unknown;
    server.use(
      http.post(CREATE_SSO_CLIENT_URL, async ({ request }) => {
        requestBody = await request.json();
        return HttpResponse.json({});
      }),
    );

    const res = await apiMod.createSsoClient(
      apiMod.buildCreateSsoClientRequest({
        clientId: '   ', // trim 后空 → protojson 省略 → 后端读零值生成
        name: ' 门户站 ',
        redirectUris: [' https://a.test/cb ', '', '*'],
      }),
    );
    // clientSecret 由服务端生成：请求体无该键（后端忽略同名字段）。
    expect(requestBody).toEqual({
      name: '门户站',
      redirectUris: ['https://a.test/cb', '*'],
    });
    expect(res.$typeName).toBe('api.admin.v1.OkResponse');

    server.use(
      http.post(CREATE_SSO_CLIENT_URL, () => new HttpResponse(null, { status: 500 })),
    );
    let caught: unknown;
    try {
      await apiMod.createSsoClient(
        apiMod.buildCreateSsoClientRequest({
          clientId: 'portal',
          name: '门户站',
          redirectUris: [],
        }),
      );
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(ApiError);
    expect((caught as ApiError).httpStatus).toBe(500);
  });
});

describe('api.updateSsoClient（§5.5 行 1262：PATCH 缺省保留）', () => {
  test('clientId 不下发（创建后不可改）；clientSecret 留空省略=保留 / 非空下发=轮换；name 空串 / 空组省略=保留', async () => {
    const bodies: unknown[] = [];
    server.use(
      http.post(UPDATE_SSO_CLIENT_URL, async ({ request }) => {
        bodies.push(await request.json());
        return HttpResponse.json({});
      }),
    );

    const keep = await apiMod.updateSsoClient(
      apiMod.buildUpdateSsoClientRequest(BigInt(1), {
        newSecret: '',
        name: '门户站 v2',
        redirectUris: ['https://portal.test/cb'],
      }),
    );
    expect(bodies[0]).toEqual({
      id: '1',
      name: '门户站 v2',
      redirectUris: ['https://portal.test/cb'],
    });
    expect(keep.$typeName).toBe('api.admin.v1.OkResponse');

    // 轮换：newSecret trim 后非空 → wire 下发 clientSecret；name / uris 空即省略（保留原值）。
    const rotate = await apiMod.updateSsoClient(
      apiMod.buildUpdateSsoClientRequest(BigInt(2), {
        newSecret: ' new-secret ',
        name: '',
        redirectUris: [],
      }),
    );
    expect(bodies[1]).toEqual({ id: '2', clientSecret: 'new-secret' });
    expect(rotate.$typeName).toBe('api.admin.v1.OkResponse');
  });
});

describe('api.deleteSsoClient（§5.5 行 1262：{id} 硬删 → OkResponse）', () => {
  test('请求体 {id} → OkResponse', async () => {
    let requestBody: unknown;
    server.use(
      http.post(DELETE_SSO_CLIENT_URL, async ({ request }) => {
        requestBody = await request.json();
        return HttpResponse.json({});
      }),
    );
    const res = await apiMod.deleteSsoClient(apiMod.buildDeleteSsoClientRequest(BigInt(3)));
    expect(requestBody).toEqual({ id: '3' });
    expect(res.$typeName).toBe('api.admin.v1.OkResponse');
  });
});

describe('api.listOidcClients（§5.5 行 1263：SSO 基线 + scopes / TTL）', () => {
  test('→ OidcClientListResponse 解码（scopes 数组 + TTL int64 → bigint）', async () => {
    server.use(
      http.post(LIST_OIDC_CLIENTS_URL, () =>
        HttpResponse.json({
          items: [
            {
              id: '5',
              clientId: 'oidc-portal',
              name: 'OIDC 门户',
              redirectUris: ['https://oidc.test/cb'],
              scopes: ['openid', 'profile', 'email'],
              accessTokenTtl: '3600',
              refreshTokenTtl: '2592000',
              createdAt: '1720000000',
              updatedAt: '1720000000',
            },
          ],
          total: '1',
          page: '1',
          pageSize: '20',
        }),
      ),
    );

    const res = await apiMod.listOidcClients(
      apiMod.buildListOidcClientsRequest(initialTableQuery()),
    );
    expect(res.total).toBe(BigInt(1));
    expect(res.items[0].scopes).toEqual(['openid', 'profile', 'email']);
    expect(res.items[0].accessTokenTtl).toBe(BigInt(3600));
    expect(res.items[0].refreshTokenTtl).toBe(BigInt(2592000));
  });
});

describe('api.getOidcClient / api.createOidcClient / api.updateOidcClient / api.deleteOidcClient（§5.5 行 1263-1264）', () => {
  test('getOidcClient：{id} → OidcClient 解码（明文 secret + scopes）', async () => {
    server.use(
      http.post(GET_OIDC_CLIENT_URL, () =>
        HttpResponse.json({
          id: '5',
          clientId: 'oidc-portal',
          clientSecret: 'oidc-secret',
          name: 'OIDC 门户',
          redirectUris: ['https://oidc.test/cb'],
          scopes: ['openid'],
          accessTokenTtl: '3600',
          refreshTokenTtl: '2592000',
        }),
      ),
    );
    const res = await apiMod.getOidcClient(apiMod.buildGetOidcClientRequest(BigInt(5)));
    expect(res.$typeName).toBe('api.admin.v1.OidcClient');
    expect(res.clientSecret).toBe('oidc-secret');
    expect(res.scopes).toEqual(['openid']);
  });

  test('createOidcClient：scopes 整组 + TTL 0 省略（落库端默认）/ 值下发十进制字符串', async () => {
    let requestBody: unknown;
    server.use(
      http.post(CREATE_OIDC_CLIENT_URL, async ({ request }) => {
        requestBody = await request.json();
        return HttpResponse.json({});
      }),
    );
    const res = await apiMod.createOidcClient(
      apiMod.buildCreateOidcClientRequest({
        clientId: 'oidc-portal',
        name: 'OIDC 门户',
        redirectUris: ['https://oidc.test/cb'],
        scopes: ['openid', 'profile'],
        accessTokenTtl: 0, // 未提交 → protojson 省略 → 后端落 DDL 默认 3600
        refreshTokenTtl: 2592000,
      }),
    );
    expect(requestBody).toEqual({
      clientId: 'oidc-portal',
      name: 'OIDC 门户',
      redirectUris: ['https://oidc.test/cb'],
      scopes: ['openid', 'profile'],
      refreshTokenTtl: '2592000',
    });
    expect(res.$typeName).toBe('api.admin.v1.OkResponse');
  });

  test('updateOidcClient：PATCH 保留语义 + scopes 覆盖 + TTL 下发 + 密钥轮换', async () => {
    const bodies: unknown[] = [];
    server.use(
      http.post(UPDATE_OIDC_CLIENT_URL, async ({ request }) => {
        bodies.push(await request.json());
        return HttpResponse.json({});
      }),
    );
    await apiMod.updateOidcClient(
      apiMod.buildUpdateOidcClientRequest(BigInt(5), {
        newSecret: 'rotated',
        name: 'OIDC 门户 v2',
        redirectUris: ['https://oidc.test/cb'],
        scopes: ['openid'],
        accessTokenTtl: 7200,
        refreshTokenTtl: 0, // 保留原值 → 省略
      }),
    );
    expect(bodies[0]).toEqual({
      id: '5',
      clientSecret: 'rotated',
      name: 'OIDC 门户 v2',
      redirectUris: ['https://oidc.test/cb'],
      scopes: ['openid'],
      accessTokenTtl: '7200',
    });
  });

  test('deleteOidcClient：{id} → OkResponse；500 reject → ApiError', async () => {
    let requestBody: unknown;
    server.use(
      http.post(DELETE_OIDC_CLIENT_URL, async ({ request }) => {
        requestBody = await request.json();
        return HttpResponse.json({});
      }),
    );
    const res = await apiMod.deleteOidcClient(apiMod.buildDeleteOidcClientRequest(BigInt(5)));
    expect(requestBody).toEqual({ id: '5' });
    expect(res.$typeName).toBe('api.admin.v1.OkResponse');

    server.use(
      http.post(DELETE_OIDC_CLIENT_URL, () => new HttpResponse(null, { status: 500 })),
    );
    let caught: unknown;
    try {
      await apiMod.deleteOidcClient(apiMod.buildDeleteOidcClientRequest(BigInt(5)));
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(ApiError);
    expect((caught as ApiError).httpStatus).toBe(500);
  });
});

// ---------------------------------------------------------------------------
// 请求构造 / 校验 / 展示纯函数（落位 api.ts，node 可测）
// ---------------------------------------------------------------------------

describe('buildListSsoClientsRequest / buildListOidcClientsRequest（分页 §1.7）', () => {
  test('排序仅 order 非空时下发；分页直映射（两族同构）', () => {
    const base = initialTableQuery();
    const ssoSorted = apiMod.buildListSsoClientsRequest({
      ...base,
      sort: 'client_id',
      order: 'desc',
    });
    expect(ssoSorted.page).toBe(BigInt(1));
    expect(ssoSorted.pageSize).toBe(BigInt(20));
    expect(ssoSorted.sort).toBe('client_id');
    expect(ssoSorted.order).toBe('desc');

    const oidcPlain = apiMod.buildListOidcClientsRequest(base);
    expect(oidcPlain.sort).toBeUndefined();
    expect(oidcPlain.order).toBeUndefined();
  });
});

describe('cleanStringList / redirectUrisIssue / scopesIssue（§1.7 前端自律，对齐后端条目规则）', () => {
  test('cleanStringList：去首尾空白 + 剔除空串；全空 → 空数组', () => {
    expect(apiMod.cleanStringList([' a ', '', 'b', '   '])).toEqual(['a', 'b']);
    expect(apiMod.cleanStringList([])).toEqual([]);
    expect(apiMod.cleanStringList(['', '  '])).toEqual([]);
  });

  test('redirectUrisIssue：* / http(s):// 合法；其他前缀 → 文案；清洗后空表 → null', () => {
    expect(apiMod.redirectUrisIssue(['*', 'https://a.test/cb', 'http://b.test/cb'])).toBeNull();
    // 模块级存键（REDIRECT_URIS_ISSUE_TEXT_KEY），调用期 t() 取文案。
    expect(apiMod.redirectUrisIssue(['ftp://a.test/cb'])).toBe(
      t(apiMod.REDIRECT_URIS_ISSUE_TEXT_KEY),
    );
    expect(apiMod.redirectUrisIssue(['example.com/cb'])).toBe(
      t(apiMod.REDIRECT_URIS_ISSUE_TEXT_KEY),
    );
    expect(apiMod.redirectUrisIssue(['', '   '])).toBeNull();
  });

  test('scopesIssue：含逗号 → 文案；合法 / 清洗后空表 → null', () => {
    expect(apiMod.scopesIssue(['openid', 'profile'])).toBeNull();
    expect(apiMod.scopesIssue(['open,id'])).toBe(t(apiMod.SCOPES_ISSUE_TEXT_KEY));
    expect(apiMod.scopesIssue([])).toBeNull();
  });
});

describe('parseTtlField（TTL 表单文本收敛；值域 [1, max]）', () => {
  test('空 → 0（缺省语义）；正整数 ≤ max → 秒数；其余 → null', () => {
    expect(apiMod.parseTtlField('', 86400)).toBe(0);
    expect(apiMod.parseTtlField(' 3600 ', 86400)).toBe(3600);
    expect(apiMod.parseTtlField('86400', 86400)).toBe(86400);
    expect(apiMod.parseTtlField('0', 86400)).toBeNull();
    expect(apiMod.parseTtlField('-1', 86400)).toBeNull();
    expect(apiMod.parseTtlField('86401', 86400)).toBeNull();
    expect(apiMod.parseTtlField('1.5', 86400)).toBeNull();
    expect(apiMod.parseTtlField('abc', 86400)).toBeNull();
  });
});

describe('summarizeList / humanizeTtlSeconds / tokenTtlSummary / ttlDetailText（展示纯函数）', () => {
  test('summarizeList：空 → 占位；单条 → 原值；多条 → 首条 + 计数', () => {
    expect(apiMod.summarizeList([])).toBe('—');
    expect(apiMod.summarizeList(['https://a.test/cb'])).toBe('https://a.test/cb');
    expect(apiMod.summarizeList(['a', 'b', 'c'])).toBe('a 等 3 条');
  });

  test('humanizeTtlSeconds：整除换算天 / 小时 / 分钟，否则原样秒数', () => {
    expect(apiMod.humanizeTtlSeconds(2592000)).toBe('30 天');
    expect(apiMod.humanizeTtlSeconds(3600)).toBe('1 小时');
    expect(apiMod.humanizeTtlSeconds(300)).toBe('5 分钟');
    expect(apiMod.humanizeTtlSeconds(3700)).toBe('3700 秒');
    expect(apiMod.humanizeTtlSeconds(45)).toBe('45 秒');
  });

  test('tokenTtlSummary / ttlDetailText：int64 经 toCount 收窄后拼装', () => {
    expect(apiMod.tokenTtlSummary(BigInt(3600), BigInt(2592000))).toBe('访问 1 小时 / 刷新 30 天');
    expect(apiMod.ttlDetailText(BigInt(3600))).toBe('1 小时（3600 秒）');
    expect(apiMod.ttlDetailText(BigInt(45))).toBe('45 秒（45 秒）');
  });
});

// ---------------------------------------------------------------------------
// StringListEditor（零 Semi 依赖 → 不可变编排纯函数 + 静态渲染）
// ---------------------------------------------------------------------------

describe('replaceListItem / removeListItem / appendListItem（不可变编排纯函数）', () => {
  test('replace：命中换值 / 越界原引用；remove：按位剔除 / 越界原引用；append：追加空串', () => {
    const items = ['a', 'b', 'c'];
    expect(replaceListItem(items, 1, 'x')).toEqual(['a', 'x', 'c']);
    expect(replaceListItem(items, -1, 'x')).toBe(items);
    expect(replaceListItem(items, 5, 'x')).toBe(items);
    expect(removeListItem(items, 0)).toEqual(['b', 'c']);
    expect(removeListItem(items, 5)).toBe(items);
    expect(appendListItem(items)).toEqual(['a', 'b', 'c', '']);
    // 原数组不变（不可变）。
    expect(items).toEqual(['a', 'b', 'c']);
  });
});

describe('StringListEditor（静态渲染：受控条目 + 添加 / 删除按钮 + 空表提示 + 禁用）', () => {
  test('values 按序渲染 + aria-label 派生 + 添加按钮；非空表不渲染空表提示', () => {
    const markup = renderToStaticMarkup(
      createElement(StringListEditor, {
        values: ['https://a.test/cb', ''],
        onChange: () => {},
        disabled: false,
        ariaLabel: '回调地址',
        addText: '添加回调地址',
        placeholder: 'https:// 或 *',
        emptyHint: '暂无回调地址',
      }),
    );
    expect(markup).toContain('https://a.test/cb');
    expect(markup).toContain('添加回调地址');
    expect(markup).toContain('aria-label="回调地址 1"');
    expect(markup).toContain('aria-label="回调地址 1 删除"');
    expect(markup).not.toContain('disabled');
    expect(markup).not.toContain('暂无回调地址');
  });

  test('空表渲染 emptyHint；disabled → 输入 / 按钮 disabled 属性', () => {
    const markup = renderToStaticMarkup(
      createElement(StringListEditor, {
        values: [],
        onChange: () => {},
        disabled: true,
        ariaLabel: '权限范围',
        addText: '添加权限范围',
        placeholder: 'openid',
        emptyHint: '暂无权限范围',
      }),
    );
    expect(markup).toContain('暂无权限范围');
    expect(markup).toContain('添加权限范围');
    expect(markup).toContain('disabled');
  });
});

// ---------------------------------------------------------------------------
// api settings 族 msw（§5.6 行 1287；后端已实装——GetSettings
// 36 键全量投影 + SetSettings 全量替换：零值也写入）
// ---------------------------------------------------------------------------

describe('api.getSettings（§5.6 行 1287：36 键全量投影）', () => {
  test('→ SettingsResponse 解码（int64 十进制字符串 → bigint + repeated + protojson 零值省略 → proto 零值）', async () => {
    server.use(
      http.post(GET_SETTINGS_URL, () =>
        HttpResponse.json({
          pwdMinLength: '12',
          pwdRequireClasses: '2',
          mfaEnabled: false,
          loginMethods: ['password', 'webauthn'],
          ssoDomains: ['a.test'],
          cookieName: 'x_session',
          staticBase: '/cdn/',
          httpsDeployment: 'false',
        }),
      ),
    );

    const res = await apiMod.getSettings();

    expect(res.$typeName).toBe('api.admin.v1.SettingsResponse');
    expect(res.pwdMinLength).toBe(BigInt(12));
    expect(res.pwdRequireClasses).toBe(BigInt(2));
    expect(res.mfaEnabled).toBe(false);
    expect(res.loginMethods).toEqual(['password', 'webauthn']);
    expect(res.ssoDomains).toEqual(['a.test']);
    expect(res.cookieName).toBe('x_session');
    expect(res.staticBase).toBe('/cdn/');
    expect(res.httpsDeployment).toBe('false');
    // protojson 零值省略 → 解码为 proto 零值（零值即真值，不用默认值兜底）。
    expect(res.pwdMaxLength).toBe(BigInt(0));
    expect(res.allowRegistration).toBe(false);
    expect(res.gatewayTokens).toEqual([]);
  });

  test('500 reject → ApiError', async () => {
    server.use(
      http.post(GET_SETTINGS_URL, () => new HttpResponse(null, { status: 500 })),
    );
    let caught: unknown;
    try {
      await apiMod.getSettings();
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(ApiError);
    expect((caught as ApiError).httpStatus).toBe(500);
  });
});

describe('api.setSettings（§5.6 行 1287 全量替换：36 键整体提交，不能只提交改动字段）', () => {
  test('默认草稿全量提交：30 个非零键全在 wire；6 个零值键（四个空 provider key + 两个空列表）protojson 省略 = 服务端读零值写入', async () => {
    let requestBody: unknown;
    server.use(
      http.post(SET_SETTINGS_URL, async ({ request }) => {
        requestBody = await request.json();
        return HttpResponse.json({});
      }),
    );

    const res = await apiMod.setSettings(
      apiMod.buildSetSettingsRequest(DEFAULT_SETTINGS),
    );

    // toEqual 精确匹配：既验证 36 键全量构造（未改动键也在），又验证零值键
    // wire 省略（省略 = 后端读零值 = 写入零值，与全量替换语义等价）。
    expect(requestBody).toEqual({
      pwdMinLength: '8',
      pwdMaxLength: '64',
      pwdRequireClasses: '3',
      pwdDisallowUsername: true,
      pwdDisallowCommon: true,
      allowPasswordReset: true,
      otpResendInterval: '60',
      otpTtl: '300',
      otpMaxAttempts: '5',
      otpDailyLimitTarget: '10',
      otpDailyLimitIp: '50',
      loginMethods: ['password', 'otp_sms', 'otp_email', 'webauthn', 'thirdparty'],
      allowRegistration: true,
      allowSignupPassword: true,
      allowSignupPhone: true,
      allowSignupEmail: true,
      mfaEnabled: true,
      mfaMethods: ['totp', 'otp_sms', 'otp_email', 'webauthn'],
      pwdFailCapture: '3',
      pwdFailBan: '6',
      pwdBanTtl: '21600',
      sessionTtl: '604800',
      cookieName: 'al_session',
      queueWorkers: '4',
      queueCapacity: '8192',
      queueBatch: '200',
      queueFlushMs: '2000',
      eventlogRetentionDays: '180',
      staticBase: '/assets',
      httpsDeployment: 'auto',
    });
    expect(res.$typeName).toBe('api.admin.v1.OkResponse');
  });

  test('管理员显式零值（pwd_ban_ttl=0 / mfa 关闭）同样全量提交：零值键 wire 省略、其余键完整下发', async () => {
    let requestBody: unknown;
    server.use(
      http.post(SET_SETTINGS_URL, async ({ request }) => {
        requestBody = await request.json();
        return HttpResponse.json({});
      }),
    );

    await apiMod.setSettings(
      apiMod.buildSetSettingsRequest({
        ...DEFAULT_SETTINGS,
        pwdBanTtl: 0,
        mfaEnabled: false,
        mfaMethods: [],
        otpMaxAttempts: 3,
      }),
    );

    const body = requestBody as Record<string, unknown>;
    // 零值省略（= 写入零值）：这 4 键不在 wire。
    expect(body).not.toHaveProperty('pwdBanTtl');
    expect(body).not.toHaveProperty('mfaEnabled');
    expect(body).not.toHaveProperty('mfaMethods');
    // 改动后的非零键仍下发；未改动键同样全量在（抽查两侧）。
    expect(body.otpMaxAttempts).toBe('3');
    expect(body.pwdMinLength).toBe('8');
    expect(body.staticBase).toBe('/assets');
    expect(body.httpsDeployment).toBe('auto');
  });

  test('500 reject → ApiError', async () => {
    server.use(
      http.post(SET_SETTINGS_URL, () => new HttpResponse(null, { status: 500 })),
    );
    let caught: unknown;
    try {
      await apiMod.setSettings(apiMod.buildSetSettingsRequest(DEFAULT_SETTINGS));
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(ApiError);
    expect((caught as ApiError).httpStatus).toBe(500);
  });
});

// ---------------------------------------------------------------------------
// settingsLogic 纯函数（键集 / 默认值 / 草稿 / 交叉校验，零 Semi node 可测）
// ---------------------------------------------------------------------------

describe('DEFAULT_SETTINGS（§5.6 行 1296-1354 四张表默认值逐字）', () => {
  test('36 键默认值与文档逐字一致（键集 = 生成物 SetSettingsRequest 现状字段集，含 https_deployment=36）', () => {
    // 密码策略（行 1296-1300）。
    expect(DEFAULT_SETTINGS.pwdMinLength).toBe(8);
    expect(DEFAULT_SETTINGS.pwdMaxLength).toBe(64);
    expect(DEFAULT_SETTINGS.pwdRequireClasses).toBe(3);
    expect(DEFAULT_SETTINGS.pwdDisallowUsername).toBe(true);
    expect(DEFAULT_SETTINGS.pwdDisallowCommon).toBe(true);
    // 账号策略（行 1314）。
    expect(DEFAULT_SETTINGS.allowPasswordReset).toBe(true);
    // 验证码限流（行 1320-1324）。
    expect(DEFAULT_SETTINGS.otpResendInterval).toBe(60);
    expect(DEFAULT_SETTINGS.otpTtl).toBe(300);
    expect(DEFAULT_SETTINGS.otpMaxAttempts).toBe(5);
    expect(DEFAULT_SETTINGS.otpDailyLimitTarget).toBe(10);
    expect(DEFAULT_SETTINGS.otpDailyLimitIp).toBe(50);
    // 其余设置项（行 1330-1353）。
    expect(DEFAULT_SETTINGS.loginMethods).toEqual([
      'password',
      'otp_sms',
      'otp_email',
      'webauthn',
      'thirdparty',
    ]);
    expect(DEFAULT_SETTINGS.allowRegistration).toBe(true);
    expect(DEFAULT_SETTINGS.allowSignupPassword).toBe(true);
    expect(DEFAULT_SETTINGS.allowSignupPhone).toBe(true);
    expect(DEFAULT_SETTINGS.allowSignupEmail).toBe(true);
    expect(DEFAULT_SETTINGS.mfaEnabled).toBe(true);
    expect(DEFAULT_SETTINGS.mfaMethods).toEqual(['totp', 'otp_sms', 'otp_email', 'webauthn']);
    expect(DEFAULT_SETTINGS.pwdFailCapture).toBe(3);
    expect(DEFAULT_SETTINGS.pwdFailBan).toBe(6);
    expect(DEFAULT_SETTINGS.pwdBanTtl).toBe(21600);
    expect(DEFAULT_SETTINGS.sessionTtl).toBe(604800);
    expect(DEFAULT_SETTINGS.cookieName).toBe('al_session');
    expect(DEFAULT_SETTINGS.ssoDomains).toEqual([]);
    expect(DEFAULT_SETTINGS.queueWorkers).toBe(4);
    expect(DEFAULT_SETTINGS.queueCapacity).toBe(8192);
    expect(DEFAULT_SETTINGS.queueBatch).toBe(200);
    expect(DEFAULT_SETTINGS.queueFlushMs).toBe(2000);
    expect(DEFAULT_SETTINGS.captchaProviderKey).toBe('');
    expect(DEFAULT_SETTINGS.smsProviderKey).toBe('');
    expect(DEFAULT_SETTINGS.emailProviderKey).toBe('');
    expect(DEFAULT_SETTINGS.avatarStorageProvider).toBe('');
    expect(DEFAULT_SETTINGS.gatewayTokens).toEqual([]);
    expect(DEFAULT_SETTINGS.eventlogRetentionDays).toBe(180);
    expect(DEFAULT_SETTINGS.staticBase).toBe('/assets');
    // https_deployment（行 1354：string 三态，默认 auto）。
    expect(DEFAULT_SETTINGS.httpsDeployment).toBe('auto');
    // 键集 = 36（与生成物 SetSettingsRequest 字段数一致，含 https_deployment=36）。
    expect(Object.keys(DEFAULT_SETTINGS).length).toBe(36);
  });
});

describe('getSettingsSections / getLoginMethodOptions / getMfaMethodOptions / getHttpsDeploymentOptions（表单分区与选项值域；函数化调用期求值）', () => {
  test('9 区 36 键全覆盖、无重复（分区键集 = DEFAULT_SETTINGS 键集）', () => {
    const sectionKeys = getSettingsSections().flatMap((section) =>
      section.fields.map((field) => field.key),
    );
    expect(new Set(sectionKeys).size).toBe(36);
    expect([...sectionKeys].sort()).toEqual(
      Object.keys(DEFAULT_SETTINGS).sort(),
    );
  });

  test('登录方式选项 = 因子名 + thirdparty 五值；MFA 选项四值、recovery_code 随 totp 不单列（行 1330/1336）', () => {
    expect(getLoginMethodOptions().map((option) => option.value)).toEqual([
      'password',
      'otp_sms',
      'otp_email',
      'webauthn',
      'thirdparty',
    ]);
    expect(getMfaMethodOptions().map((option) => option.value)).toEqual([
      'totp',
      'otp_sms',
      'otp_email',
      'webauthn',
    ]);
  });

  test('HTTPS 部署选项三态 = 行 1356 文案定稿（自动推断 / 强制开启 / 强制关闭）', () => {
    expect(getHttpsDeploymentOptions()).toEqual([
      { value: 'auto', label: '自动推断' },
      { value: 'true', label: '强制开启' },
      { value: 'false', label: '强制关闭' },
    ]);
  });
});

describe('静态表渲染期求值回归（setLocale 后取表得对应语言文案，防 locale 冻结）', () => {
  // 本 describe 会切换模块级语言状态：每条用例后复位默认 zh-CN（i18n.test.ts 同模式）。
  afterEach(() => {
    setLocale('zh-CN');
  });

  test("setLocale('en-US') 后 SETTINGS_SECTIONS / 选项表 / *_LABELS 表 / SECTION_TITLES 得 en 文案", () => {
    setLocale('en-US');
    // SETTINGS_SECTIONS（settingsLogic 函数化，调用期求值）。
    const sections = getSettingsSections();
    expect(sections[0].title).toBe('Password policy');
    expect(sections[0].fields[0].label).toBe('Minimum length');
    expect(sections[0].fields[0].hint).toBe('Default 8');
    // LOGIN / MFA / HTTPS_DEPLOYMENT 选项表。
    expect(getLoginMethodOptions()[0].label).toBe('Password');
    expect(getMfaMethodOptions()[0].label).toBe('Authenticator code');
    expect(getHttpsDeploymentOptions()[0].label).toBe('Auto-detect');
    // USER_CREDENTIAL_KIND_LABELS 表（键映射 + credentialKindLabel 调用期 t()）。
    expect(apiMod.credentialKindLabel('password')).toBe('Password');
    expect(apiMod.credentialKindLabel('mfa_setting')).toBe('MFA switch');
    // EVENT_TYPE_LABELS 表（经 eventTypeLabel）。
    expect(apiMod.eventTypeLabel('login_success')).toBe('Signed in');
    // SECTION_TITLES（schemaLogic，textKey 形态渲染处 t()）。
    expect(t(SECTION_TITLES.basic)).toBe('Basic information');
    // USER_STATUS_FILTERS（textKey 形态，消费方渲染同式 map）。
    expect(
      apiMod.USER_STATUS_FILTERS.map(({ value, textKey }) => ({
        value,
        text: t(textKey),
      })),
    ).toEqual([
      { value: '1', text: 'Active' },
      { value: '0', text: 'Disabled' },
    ]);
    // 反向复核：切回 zh-CN 后同表回中文（求值确实晚于 setLocale）。
    setLocale('zh-CN');
    expect(getSettingsSections()[0].title).toBe('密码策略');
    expect(apiMod.credentialKindLabel('password')).toBe('密码登录');
  });
});

// ---------------------------------------------------------------------------
// routes：未知路径兜底真渲染（测试链解锁 Semi 加载）
// ---------------------------------------------------------------------------

describe('routes：未知路径兜底真渲染', () => {
  function renderAdminApp(pathname: string): string {
    rs.stubGlobal('window', {
      location: { pathname },
      __AUTHLOFT_INIT__: (globalThis as { __AUTHLOFT_INIT__?: unknown })
        .__AUTHLOFT_INIT__,
    });
    return renderToStaticMarkup(createElement(routesMod.AdminApp));
  }

  test('未知 /admin/** → 带布局兜底：Semi Empty 文案 + 返回管理首页链接', () => {
    const html = renderAdminApp('/admin/does-not-exist');
    expect(html).toContain('页面不存在');
    expect(html).toContain('返回管理首页');
    expect(html).toContain('href="/admin/providers"');
    // 经 AdminLayout 挂载（文件头部透明壳 mock 的标记），与裸兜底分支区分。
    expect(html).toContain('__ADMIN_LAYOUT_STUB__');
    expect(html).toContain('semi-empty');
  });

  test('非 /admin 前缀 → 裸兜底（同款文案链接，不套 Layout）', () => {
    const html = renderAdminApp('/nope');
    expect(html).toContain('页面不存在');
    expect(html).toContain('返回管理首页');
    expect(html).toContain('href="/admin/providers"');
    expect(html).not.toContain('__ADMIN_LAYOUT_STUB__');
  });
});

describe('draftFromSettings（GetSettings 响应 → 草稿全键映射；全量替换的对称面：零值即真值）', () => {
  test('36 键直映射：bigint → number、数组防御性拷贝（改草稿不回写响应）', () => {
    const response = create(SettingsResponseSchema, {
      pwdMinLength: BigInt(12),
      pwdRequireClasses: BigInt(2),
      mfaEnabled: false,
      loginMethods: ['password'],
      mfaMethods: ['totp', 'webauthn'],
      ssoDomains: ['a.test', 'b.test'],
      cookieName: 'x_session',
      captchaProviderKey: ' geetest ',
      staticBase: '/cdn/',
      httpsDeployment: 'true',
    });
    const draft = draftFromSettings(response);

    expect(draft.pwdMinLength).toBe(12);
    expect(draft.pwdRequireClasses).toBe(2);
    expect(draft.mfaEnabled).toBe(false);
    expect(draft.loginMethods).toEqual(['password']);
    expect(draft.mfaMethods).toEqual(['totp', 'webauthn']);
    expect(draft.ssoDomains).toEqual(['a.test', 'b.test']);
    expect(draft.cookieName).toBe('x_session');
    expect(draft.captchaProviderKey).toBe(' geetest ');
    expect(draft.staticBase).toBe('/cdn/');
    expect(draft.httpsDeployment).toBe('true');
    // 数组为新引用（防御性拷贝）。
    expect(draft.loginMethods).not.toBe(response.loginMethods);
  });

  test('protojson 零值省略的响应 → 草稿全零值（不做默认值兜底：后端读出的零值 = 真值）', () => {
    const draft = draftFromSettings(create(SettingsResponseSchema));
    expect(draft.pwdMinLength).toBe(0);
    expect(draft.allowRegistration).toBe(false);
    expect(draft.loginMethods).toEqual([]);
    expect(draft.staticBase).toBe('');
  });
});

describe('settingsDraftIssue（§5.6 行 1363 值域交叉约束前端自律）', () => {
  test('默认草稿 → null；非法值逐类命中', () => {
    expect(settingsDraftIssue(DEFAULT_SETTINGS)).toBeNull();

    // pwd_require_classes 值域 1-3（行 1298）。
    expect(
      settingsDraftIssue({ ...DEFAULT_SETTINGS, pwdRequireClasses: 0 }),
    ).not.toBeNull();
    expect(
      settingsDraftIssue({ ...DEFAULT_SETTINGS, pwdRequireClasses: 4 }),
    ).not.toBeNull();
    // pwd_min_length ≤ pwd_max_length 交叉约束（行 1363）。
    expect(
      settingsDraftIssue({ ...DEFAULT_SETTINGS, pwdMinLength: 65 }),
    ).not.toBeNull();
    // pwd_max_length ≤ 64 服务端硬上限（行 1297：可调低不可调高）。
    expect(
      settingsDraftIssue({ ...DEFAULT_SETTINGS, pwdMaxLength: 65 }),
    ).not.toBeNull();
    // 数字字段非负整数。
    expect(
      settingsDraftIssue({ ...DEFAULT_SETTINGS, queueWorkers: -1 }),
    ).not.toBeNull();
    expect(
      settingsDraftIssue({ ...DEFAULT_SETTINGS, otpTtl: 1.5 }),
    ).not.toBeNull();
    // https_deployment 三态（行 1361：非 true / false / auto → invalid_request）。
    expect(
      settingsDraftIssue({ ...DEFAULT_SETTINGS, httpsDeployment: 'yes' }),
    ).not.toBeNull();
    expect(
      settingsDraftIssue({ ...DEFAULT_SETTINGS, httpsDeployment: '' }),
    ).not.toBeNull();
    // 三态取值本身全合法。
    for (const value of ['auto', 'true', 'false']) {
      expect(
        settingsDraftIssue({ ...DEFAULT_SETTINGS, httpsDeployment: value }),
      ).toBeNull();
    }
  });
});

describe('buildSetSettingsRequest（全量构造：number → bigint / 文本 trim / 列表清洗）', () => {
  test('草稿 36 键整体构造（含未改动键）；文本去空白、列表去空条目', () => {
    const request = apiMod.buildSetSettingsRequest({
      ...DEFAULT_SETTINGS,
      cookieName: ' x_session ',
      ssoDomains: [' a.test ', '', '  '],
      gatewayTokens: [' gw-1 ', ''],
      staticBase: ' /cdn/ ',
      otpMaxAttempts: 4,
      httpsDeployment: 'false',
    });

    expect(request.pwdMinLength).toBe(BigInt(8));
    expect(request.otpMaxAttempts).toBe(BigInt(4));
    expect(request.cookieName).toBe('x_session');
    expect(request.ssoDomains).toEqual(['a.test']);
    expect(request.gatewayTokens).toEqual(['gw-1']);
    expect(request.staticBase).toBe('/cdn/');
    expect(request.httpsDeployment).toBe('false');
    expect(request.loginMethods).toEqual([
      'password',
      'otp_sms',
      'otp_email',
      'webauthn',
      'thirdparty',
    ]);
  });
});

// ---------------------------------------------------------------------------
// 工具三页族（接口文档 §5.6 行 1288-1290；后端已实装）
// ---------------------------------------------------------------------------

describe('api.listEvents（§5.6 行 1288：统一事件视图，六筛选 + 分页 §1.7）', () => {
  test('请求体 wire（login_records 预设强制 event=login_success + actorType 叠加 + 分页/排序）→ EventListResponse 解码（EventItem 全字段 + 零值省略）', async () => {
    let requestBody: unknown;
    server.use(
      http.post(LIST_EVENTS_URL, async ({ request }) => {
        requestBody = await request.json();
        return HttpResponse.json({
          items: [
            {
              id: '9',
              event: 'login_success',
              actorType: 'user',
              actorId: '42',
              userId: '42',
              clientId: 'web-portal',
              amr: 'pwd',
              ip: '203.0.113.1',
              ua: 'Mozilla/5.0',
              target: '',
              detail: { session_id: 's-1' },
              createdAt: '1730000100',
            },
            {
              id: '10',
              event: 'oidc_authorize_no_state',
              actorType: 'system',
              actorId: '0',
              userId: '0',
              createdAt: '1730000200',
            },
          ],
          total: '2',
          page: '2',
          pageSize: '20',
        });
      }),
    );

    const query: TableQueryState = {
      ...initialTableQuery(),
      page: 2,
      sort: 'created_at',
      order: 'desc',
    };
    const res = await apiMod.listEvents(
      apiMod.buildListEventsRequest('login_records', { actorType: 'user' }, query),
    );

    // 预设「登录记录」→ event 强制 login_success；其余筛选透传；排序仅 order 非空下发。
    expect(requestBody).toEqual({
      event: 'login_success',
      actorType: 'user',
      page: '2',
      pageSize: '20',
      sort: 'created_at',
      order: 'desc',
    });
    expect(res.$typeName).toBe('api.admin.v1.EventListResponse');
    expect(res.total).toBe(BigInt(2));
    expect(res.page).toBe(BigInt(2));
    expect(res.pageSize).toBe(BigInt(20));
    expect(res.items).toHaveLength(2);
    expect(res.items[0].id).toBe(BigInt(9));
    expect(res.items[0].event).toBe('login_success');
    expect(res.items[0].actorType).toBe('user');
    expect(res.items[0].actorId).toBe(BigInt(42));
    expect(res.items[0].clientId).toBe('web-portal');
    expect(res.items[0].detail?.session_id).toBe('s-1');
    expect(res.items[0].createdAt).toBe(BigInt(1730000100));
    // protojson 零值省略 → 解码为 proto 零值（''/0/undefined，展示层 §9 第 18 条兜底）。
    expect(res.items[1].actorType).toBe('system');
    expect(res.items[1].userId).toBe(BigInt(0));
    expect(res.items[1].ip).toBe('');
    expect(res.items[1].detail).toBeUndefined();
  });

  test('all 预设 × 四项数值/时间筛选（UI 暴露形态）→ 请求体 wire 十进制字符串（超 2^53 ID 保真）→ 解码', async () => {
    let requestBody: unknown;
    server.use(
      http.post(LIST_EVENTS_URL, async ({ request }) => {
        requestBody = await request.json();
        return HttpResponse.json({ items: [], total: '0', page: '1', pageSize: '20' });
      }),
    );

    // UI 换算产物形态（AuditPage idInputToFilter / dateToUnixFilter）：actorId
    // 超 2^53（InputNumber 超精度以 string 原样承载 → BigInt 无精度损失，§1.12）。
    const res = await apiMod.listEvents(
      apiMod.buildListEventsRequest(
        'all',
        {
          actorId: BigInt('9007199254740993'),
          userId: BigInt(7),
          from: BigInt(1730000000),
          to: BigInt(1730000600),
        },
        initialTableQuery(),
      ),
    );

    // §1.12 wire：整型一律十进制字符串，超精度 bigint ID 逐字符保真。
    expect(requestBody).toEqual({
      actorId: '9007199254740993',
      userId: '7',
      from: '1730000000',
      to: '1730000600',
      page: '1',
      pageSize: '20',
    });
    expect(res.$typeName).toBe('api.admin.v1.EventListResponse');
    expect(res.items).toHaveLength(0);
    expect(res.total).toBe(BigInt(0));
  });

  test('500 reject → ApiError', async () => {
    server.use(
      http.post(LIST_EVENTS_URL, () => new HttpResponse(null, { status: 500 })),
    );
    let caught: unknown;
    try {
      await apiMod.listEvents(
        apiMod.buildListEventsRequest('all', {}, initialTableQuery()),
      );
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(ApiError);
    expect((caught as ApiError).httpStatus).toBe(500);
  });
});

describe('buildListEventsRequest（§5.6 行 1288 六筛选 + §1.7 行 275-278 分页）', () => {
  test('login_records 预设强制 event=LOGIN_RECORDS_EVENT，手动 event 让位、其余筛选叠加', () => {
    expect(apiMod.LOGIN_RECORDS_EVENT).toBe('login_success');
    const req = apiMod.buildListEventsRequest(
      'login_records',
      { event: 'change_password', actorType: 'admin' },
      initialTableQuery(),
    );
    expect(req.event).toBe('login_success');
    expect(req.actorType).toBe('admin');
  });

  test('all 预设：缺省筛选全省略；六筛选全量直映射；排序仅 order 非空下发', () => {
    const base = initialTableQuery();

    // 查询参数缺省即不过滤（生成物头注：一律 optional）。
    const plain = apiMod.buildListEventsRequest('all', {}, base);
    expect(plain.event).toBeUndefined();
    expect(plain.actorType).toBeUndefined();
    expect(plain.actorId).toBeUndefined();
    expect(plain.userId).toBeUndefined();
    expect(plain.from).toBeUndefined();
    expect(plain.to).toBeUndefined();
    expect(plain.page).toBe(BigInt(1));
    expect(plain.pageSize).toBe(BigInt(20));
    expect(plain.sort).toBeUndefined();
    expect(plain.order).toBeUndefined();

    const full = apiMod.buildListEventsRequest(
      'all',
      {
        event: 'settings_update',
        actorType: 'system',
        actorId: BigInt(1),
        userId: BigInt(7),
        from: BigInt(1730000000),
        to: BigInt(1730000600),
      },
      { ...base, sort: 'created_at', order: 'asc' },
    );
    expect(full.event).toBe('settings_update');
    expect(full.actorType).toBe('system');
    expect(full.actorId).toBe(BigInt(1));
    expect(full.userId).toBe(BigInt(7));
    expect(full.from).toBe(BigInt(1730000000));
    expect(full.to).toBe(BigInt(1730000600));
    expect(full.sort).toBe('created_at');
    expect(full.order).toBe('asc');

    // 清除排序（dataTableLogic：order=''）→ sort / order 均不下发。
    const cleared = apiMod.buildListEventsRequest('all', {}, {
      ...base,
      sort: 'created_at',
      order: '',
    });
    expect(cleared.sort).toBeUndefined();
    expect(cleared.order).toBeUndefined();
  });

  test('login_records 预设 × actorId/userId/from/to 叠加照常下发（四项在预设下不让位）', () => {
    // 预设下 event 让位、其余五项照常叠加（构造函数既有语义，UI 不禁用四项）。
    const req = apiMod.buildListEventsRequest(
      'login_records',
      {
        event: 'settings_update',
        actorId: BigInt(42),
        userId: BigInt(1),
        from: BigInt(1730000000),
        to: BigInt(1730000600),
      },
      initialTableQuery(),
    );
    expect(req.event).toBe('login_success');
    expect(req.actorId).toBe(BigInt(42));
    expect(req.userId).toBe(BigInt(1));
    expect(req.from).toBe(BigInt(1730000000));
    expect(req.to).toBe(BigInt(1730000600));
  });
});

// ---------------------------------------------------------------------------
// 「敏感操作」预设扩集（2026-11-06 定稿五类封闭集：改密、重置
// 密码、解绑、启用/停用两步验证；admin_reset_password 不入集）
// ---------------------------------------------------------------------------

describe('SENSITIVE_RECORDS_EVENTS / eventTypeFilterOptions / resolveEventFilterOnPreset（预设映射）', () => {
  test('SENSITIVE_RECORDS_EVENTS = 五类封闭集逐字对应 event 值域（admin_reset_password 不入集）；默认事件 change_password', () => {
    expect(apiMod.SENSITIVE_RECORDS_EVENTS).toEqual([
      'change_password',
      'reset_password',
      'thirdparty_unbind',
      'enable_mfa',
      'disable_mfa',
    ]);
    expect(apiMod.SENSITIVE_RECORDS_DEFAULT_EVENT).toBe('change_password');
    // admin_reset_password 明确不入集（2026-11-06 定稿）。
    expect(apiMod.SENSITIVE_RECORDS_EVENTS).not.toContain('admin_reset_password');
    // 五类均在 17 类全量值域内（optionList 复用 EVENT_TYPE_FILTERS 对应项）。
    const allValues = apiMod.EVENT_TYPE_FILTERS.map((option) => option.value);
    for (const value of apiMod.SENSITIVE_RECORDS_EVENTS) {
      expect(allValues).toContain(value);
    }
  });

  test('eventTypeFilterOptions：sensitive_records 限定五类（沿 EVENT_TYPE_FILTERS 声明序）；切回 all / login_records 恢复 17 类全量', () => {
    // 预设切换 optionList 限定五类（复用 EVENT_TYPE_FILTERS 对应项，value + textKey 同构）。
    const sensitive = apiMod.eventTypeFilterOptions('sensitive_records');
    expect(sensitive.map((option) => option.value)).toEqual([
      'change_password',
      'reset_password',
      'enable_mfa',
      'disable_mfa',
      'thirdparty_unbind',
    ]);
    for (const option of sensitive) {
      expect(apiMod.EVENT_TYPE_FILTERS).toContainEqual(option);
    }
    // 切回「全部」恢复 17 类全量（login_records 下拉禁用但仍全量）。
    const all = apiMod.eventTypeFilterOptions('all');
    expect(all).toHaveLength(17);
    expect(apiMod.eventTypeFilterOptions('login_records')).toHaveLength(17);
    expect(all.map((option) => option.value)).toEqual(
      apiMod.EVENT_TYPE_FILTERS.map((option) => option.value),
    );
  });

  test('resolveEventFilterOnPreset：进敏感操作出集（含空）默认 change_password、入集保留；切其余预设保留现值', () => {
    // 进预设：出集 / 空现值 → 默认 change_password（列表立即有数据非空态）。
    expect(apiMod.resolveEventFilterOnPreset('sensitive_records', '')).toBe('change_password');
    expect(apiMod.resolveEventFilterOnPreset('sensitive_records', 'settings_update')).toBe(
      'change_password',
    );
    // 入集现值保留（用户已单选另四类亦然；本次新增 reset_password / disable_mfa）。
    expect(apiMod.resolveEventFilterOnPreset('sensitive_records', 'change_password')).toBe(
      'change_password',
    );
    expect(apiMod.resolveEventFilterOnPreset('sensitive_records', 'reset_password')).toBe(
      'reset_password',
    );
    expect(apiMod.resolveEventFilterOnPreset('sensitive_records', 'thirdparty_unbind')).toBe(
      'thirdparty_unbind',
    );
    expect(apiMod.resolveEventFilterOnPreset('sensitive_records', 'enable_mfa')).toBe('enable_mfa');
    expect(apiMod.resolveEventFilterOnPreset('sensitive_records', 'disable_mfa')).toBe(
      'disable_mfa',
    );
    // 切回「全部」/「登录记录」保留现值（预设切换不清筛选惯例；五类值在 17 类中合法）。
    expect(apiMod.resolveEventFilterOnPreset('all', 'thirdparty_unbind')).toBe(
      'thirdparty_unbind',
    );
    expect(apiMod.resolveEventFilterOnPreset('all', 'disable_mfa')).toBe('disable_mfa');
    expect(apiMod.resolveEventFilterOnPreset('all', '')).toBe('');
    expect(apiMod.resolveEventFilterOnPreset('login_records', 'change_password')).toBe(
      'change_password',
    );
  });
});

describe('buildListEventsRequest × sensitive_records（构造函数零改动，wire 单值实证）', () => {
  test('sensitive_records 与 all 同分支：event 取手动单值（五类逐一透传），四项筛选照常叠加', () => {
    for (const value of apiMod.SENSITIVE_RECORDS_EVENTS) {
      const req = apiMod.buildListEventsRequest(
        'sensitive_records',
        { event: value },
        initialTableQuery(),
      );
      expect(req.event).toBe(value);
    }
    // 四项筛选在该预设下照常叠加（与 login_records 下行为一致）。
    const req = apiMod.buildListEventsRequest(
      'sensitive_records',
      {
        event: 'change_password',
        actorType: 'user',
        actorId: BigInt(42),
        userId: BigInt(7),
        from: BigInt(1730000000),
        to: BigInt(1730000600),
      },
      initialTableQuery(),
    );
    expect(req.event).toBe('change_password');
    expect(req.actorType).toBe('user');
    expect(req.actorId).toBe(BigInt(42));
    expect(req.userId).toBe(BigInt(7));
    expect(req.from).toBe(BigInt(1730000000));
    expect(req.to).toBe(BigInt(1730000600));
  });

  test('msw wire：sensitive_records × 默认 change_password → 请求体 event 为单值字符串（非集合）+ userId 叠加', async () => {
    let requestBody: unknown;
    server.use(
      http.post(LIST_EVENTS_URL, async ({ request }) => {
        requestBody = await request.json();
        return HttpResponse.json({ items: [], total: '0', page: '1', pageSize: '20' });
      }),
    );

    await apiMod.listEvents(
      apiMod.buildListEventsRequest(
        'sensitive_records',
        { event: apiMod.SENSITIVE_RECORDS_DEFAULT_EVENT, userId: BigInt(7) },
        initialTableQuery(),
      ),
    );

    // §1.12 wire：event 单值字符串直下（ListEvents 无集合过滤原语），userId 十进制。
    expect(requestBody).toEqual({
      event: 'change_password',
      userId: '7',
      page: '1',
      pageSize: '20',
    });
  });
});

describe('api.decodeToken（§5.6 行 1289：{token, purpose} → Struct 载荷）', () => {
  test('请求体 wire（token 去首尾空白）→ DecodeResponse 解码（payload JsonObject）', async () => {
    let requestBody: unknown;
    server.use(
      http.post(DECODE_TOKEN_URL, async ({ request }) => {
        requestBody = await request.json();
        return HttpResponse.json({
          payload: { uid: '1', exp: '1730000600', amr: 'pwd' },
        });
      }),
    );

    const res = await apiMod.decodeToken(
      apiMod.buildDecodeTokenRequest('  tok-1  ', 'session'),
    );

    expect(requestBody).toEqual({ token: 'tok-1', purpose: 'session' });
    expect(res.$typeName).toBe('api.admin.v1.DecodeResponse');
    expect(res.payload?.uid).toBe('1');
    expect(res.payload?.exp).toBe('1730000600');
    expect(res.payload?.amr).toBe('pwd');
  });

  test('解码失败（篡改 / 跨 purpose / 无效令牌）→ 400 Connect 错误体 → ApiError invalid_argument', async () => {
    server.use(
      http.post(DECODE_TOKEN_URL, () =>
        HttpResponse.json(
          { code: 'invalid_argument', message: 'decode failed' },
          { status: 400 },
        ),
      ),
    );
    let caught: unknown;
    try {
      await apiMod.decodeToken(
        apiMod.buildDecodeTokenRequest('bad-token', 'login'),
      );
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(ApiError);
    expect((caught as ApiError).httpStatus).toBe(400);
    expect((caught as ApiError).code).toBe('invalid_argument');
  });
});

describe('api.getStatus（§5.6 行 1290：队列长度 / dropped / flush 耗时）', () => {
  test('无入参（空请求体）→ StatusResponse 解码（int64 十进制字符串 → bigint）', async () => {
    let requestBody: unknown;
    server.use(
      http.post(GET_STATUS_URL, async ({ request }) => {
        requestBody = await request.json();
        return HttpResponse.json({ queueLength: '5', dropped: '2', flushMs: '37' });
      }),
    );

    const res = await apiMod.getStatus();

    expect(requestBody).toEqual({});
    expect(res.$typeName).toBe('api.admin.v1.StatusResponse');
    expect(res.queueLength).toBe(BigInt(5));
    expect(res.dropped).toBe(BigInt(2));
    expect(res.flushMs).toBe(BigInt(37));
  });

  test('protojson 零值省略（空队列 / 未丢弃 / 未发生过 flush）→ 0n', async () => {
    server.use(http.post(GET_STATUS_URL, () => HttpResponse.json({})));
    const res = await apiMod.getStatus();
    expect(res.queueLength).toBe(BigInt(0));
    expect(res.dropped).toBe(BigInt(0));
    expect(res.flushMs).toBe(BigInt(0));
  });

  test('500 reject → ApiError', async () => {
    server.use(
      http.post(GET_STATUS_URL, () => new HttpResponse(null, { status: 500 })),
    );
    let caught: unknown;
    try {
      await apiMod.getStatus();
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(ApiError);
    expect((caught as ApiError).httpStatus).toBe(500);
  });
});

describe('eventTypeLabel / EVENT_TYPE_FILTERS（《后端架构》§4.6 值域锚定）', () => {
  test('EVENT_TYPE_FILTERS 值域 = §4.6 event 列 16 常量 + 行 809 oidc_authorize_no_state（17 项）', () => {
    expect(apiMod.EVENT_TYPE_FILTERS.map((option) => option.value)).toEqual([
      'login_success',
      'change_password',
      'reset_password',
      'bind_phone',
      'bind_email',
      'enable_mfa',
      'disable_mfa',
      'webauthn_register',
      'webauthn_delete',
      'thirdparty_bind',
      'thirdparty_unbind',
      'admin_disable_user',
      'admin_reset_password',
      'provider_create',
      'provider_update',
      'settings_update',
      'oidc_authorize_no_state',
    ]);
    // 下拉项文案可译非空（textKey 形态，渲染处 t() 取文案）。
    for (const option of apiMod.EVENT_TYPE_FILTERS) {
      expect(option.textKey).not.toBe('');
      expect(t(option.textKey)).not.toBe('');
      expect(t(option.textKey)).not.toBe(option.textKey);
    }
  });

  test('eventTypeLabel：已知值 → 中文文案；未知值原样兜底（§12.9 跨版本新增）', () => {
    expect(apiMod.eventTypeLabel('login_success')).toBe('登录成功');
    expect(apiMod.eventTypeLabel('admin_reset_password')).toBe('管理员重置密码');
    expect(apiMod.eventTypeLabel('future_event')).toBe('future_event');
  });
});

describe('actorTypeLabel / actorText / bigIdText / eventDetailText / decodePayloadText（展示纯函数，§9 第 18 条零值兜底）', () => {
  test('actorTypeLabel：user/admin/system → 文案；未知原样兜底', () => {
    expect(apiMod.actorTypeLabel('user')).toBe('用户');
    expect(apiMod.actorTypeLabel('admin')).toBe('管理员');
    expect(apiMod.actorTypeLabel('system')).toBe('系统');
    expect(apiMod.actorTypeLabel('robot')).toBe('robot');
  });

  test('actorText：system 事件不附 actor_id=0（§4.6 不编造用户 id）；user/admin 附 id', () => {
    expect(apiMod.actorText('system', BigInt(0))).toBe('系统');
    expect(apiMod.actorText('user', BigInt(42))).toBe('用户 42');
    expect(apiMod.actorText('admin', BigInt(1))).toBe('管理员 1');
  });

  test('bigIdText：零值 → 占位符；非零 → 十进制（§1.12 不经 Number）', () => {
    expect(apiMod.bigIdText(BigInt(0))).toBe('—');
    expect(apiMod.bigIdText(BigInt(7))).toBe('7');
    expect(apiMod.bigIdText(BigInt('9223372036854775807'))).toBe('9223372036854775807');
  });

  test('eventDetailText：缺省 → 占位符；JsonObject → 紧凑 JSON', () => {
    expect(apiMod.eventDetailText(undefined)).toBe('—');
    expect(apiMod.eventDetailText({ session_id: 's-1', n: 2 })).toBe(
      '{"session_id":"s-1","n":2}',
    );
  });

  test('decodePayloadText：缺省 → 占位符；JsonObject → 缩进 JSON', () => {
    expect(apiMod.decodePayloadText(undefined)).toBe('—');
    expect(apiMod.decodePayloadText({ uid: '1' })).toBe(
      JSON.stringify({ uid: '1' }, null, 2),
    );
  });
});

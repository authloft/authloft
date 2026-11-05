/**
 * AdminService client 方法封装（docs/前端架构.md §6 行 505-506；docs/接口文档.md §5）。
 * 本次交付 GetMe（§5.1 行 1159：前端获取管理员信息的唯一来源，`/admin/**`
 * 空壳页不注入 `admin` 字段）并追加 Provider 列表族：ListProviders /
 * SetProviderEnabled / SortProviders 薄封装 + 列表 / 排序请求构造与策略标签
 * 展示纯函数（§5.2 行 1164-1177）；并追加 Provider 编辑族：
 * GetProviderTypes / GetProviderSchema / GetProvider / Create / Update /
 * TestProvider（§5.2 行 1169-1177 + §5.3）；并追加用户管理族七方法
 * （§5.4 行 1249-1255）+ 请求构造 / 展示纯函数；并追加客户端管理族
 * 十方法（§5.5 行 1257-1268）+ 请求构造 / 校验 / 展示纯函数；并追加
 * settings 族 GetSettings / SetSettings（§5.6 行 1287 全量替换语义）+ 全量
 * 请求构造纯函数；并追加工具三页族：ListEvents（§5.6 行 1288 统一事件
 * 视图 + 预设视图）/ DecodeToken（§5.6 行 1289）/ GetStatus（§5.6 行 1290）
 * + 请求构造 / 预设映射 / 展示纯函数（管理端无 multipart 上传，§6 行 506）。
 *
 * 401/404 语义（§6 行 501，本实现关键；接口文档 §5 行 1149）：
 * - 未携带有效会话 → HTTP 401（`unauthenticated`，框架层错误不进 §1.6 词汇表）
 *   → 布局层统一跳登录；
 * - 会话有效但非管理员（uid≠1）→ HTTP 404（`not_found`，掩护管理面存在）
 *   → 已由 shared/api/http 归一为 ApiError（httpStatus 404），走统一错误
 *   处理显示错误态，**不跳登录**。
 * 两者均为 Connect 框架层错误，双条件（HTTP 状态 ∨ Connect 标准码）判定防
 * 后端未来改走 ErrorInfo 业务码（与 account/api.ts 的 isUnauthenticatedError
 * 同口径；entry 间禁止互引 §9 第 13 条，故在本模块重述）。分流判定落可测
 * 纯函数 adminMeFailureAction——AdminLayout 壳 import Semi 后模块图不可在
 * node 测试（工具链 blocker），纯逻辑按 account/api.ts 落位口径置此。
 *
 * transport 与 client 只在 shared/api/http.ts 构造（§9 第 16 条），本模块
 * 从那里拿 adminClient、不自建 transport；请求状态语义归
 * shared/hooks/useRequest（§3.2），本模块是薄封装。
 * 报文类型全部取自 src/gen/proto 生成物（§9 第 15 条）。
 */
import { create, fromJson, type JsonObject } from '@bufbuild/protobuf';
import { StructSchema } from '@bufbuild/protobuf/wkt';
import { ApiError, resolveCode } from '../shared/api/errors';
import { adminClient } from '../shared/api/http';
import { t } from '../shared/i18n';
import { FIRST_PAGE, MAX_PAGE_SIZE, type TableQueryState } from '../shared/app-ui/dataTableLogic';
import { toCount } from '../shared/utils/int';
import type { MeResponse, OkResponse } from '../gen/proto/api/admin/v1/admin_pb';
import type {
  CreateOidcClientRequest,
  CreateSsoClientRequest,
  DeleteOidcClientRequest,
  DeleteSsoClientRequest,
  GetOidcClientRequest,
  GetSsoClientRequest,
  ListOidcClientsRequest,
  ListSsoClientsRequest,
  OidcClient,
  OidcClientListResponse,
  SsoClient,
  SsoClientListResponse,
  UpdateOidcClientRequest,
  UpdateSsoClientRequest,
} from '../gen/proto/api/admin/v1/client_pb';
import {
  CreateOidcClientRequestSchema,
  CreateSsoClientRequestSchema,
  DeleteOidcClientRequestSchema,
  DeleteSsoClientRequestSchema,
  GetOidcClientRequestSchema,
  GetSsoClientRequestSchema,
  ListOidcClientsRequestSchema,
  ListSsoClientsRequestSchema,
  UpdateOidcClientRequestSchema,
  UpdateSsoClientRequestSchema,
} from '../gen/proto/api/admin/v1/client_pb';
import type {
  GetUserEventsRequest,
  GetUserRequest,
  ListUsersRequest,
  ResetUserPasswordRequest,
  UnbindUserThirdpartyRequest,
  UnlockUserRequest,
  UpdateUserStatusRequest,
  UserDetailResponse,
  UserEventsResponse,
  UserListResponse,
} from '../gen/proto/api/admin/v1/user_pb';
import {
  GetUserEventsRequestSchema,
  GetUserRequestSchema,
  ListUsersRequestSchema,
  ResetUserPasswordRequestSchema,
  UnbindUserThirdpartyRequestSchema,
  UnlockUserRequestSchema,
  UpdateUserStatusRequestSchema,
} from '../gen/proto/api/admin/v1/user_pb';
import type { MfaResponse } from '../gen/proto/api/account/v1/mfa_pb';
import type {
  AdminProvider,
  GetProviderRequest,
  ListProvidersRequest,
  Provider,
  ProviderListResponse,
  SetProviderEnabledRequest,
  SortProvidersRequest,
  TestProviderRequest,
} from '../gen/proto/api/admin/v1/provider_pb';
import {
  ListProvidersRequestSchema,
  SortProvidersRequestSchema,
} from '../gen/proto/api/admin/v1/provider_pb';
import type {
  GetProviderSchemaRequest,
  ProviderTypesResponse,
  SchemaResponse,
} from '../gen/proto/api/admin/v1/schema_pb';
import type {
  SetSettingsRequest,
  SettingsResponse,
} from '../gen/proto/api/admin/v1/settings_pb';
import { SetSettingsRequestSchema } from '../gen/proto/api/admin/v1/settings_pb';
import type { SettingsDraft } from './settingsLogic';
import type {
  EventListResponse,
  ListEventsRequest,
} from '../gen/proto/api/admin/v1/events_pb';
import { ListEventsRequestSchema } from '../gen/proto/api/admin/v1/events_pb';
import type {
  DecodeResponse,
  DecodeTokenRequest,
  StatusResponse,
} from '../gen/proto/api/admin/v1/tools_pb';
import { DecodeTokenRequestSchema } from '../gen/proto/api/admin/v1/tools_pb';

/** 当前管理员信息（§5.1 行 1159）：`{id, username, nickname, avatarUrl, isAdmin:true}`，无入参。 */
export function getMe(): Promise<MeResponse> {
  return adminClient.getMe({});
}

// ---------------------------------------------------------------------------
// Provider 列表族（§5.2 行 1164-1177）：读路径真调（后端已实装
// List/Get/GetProviderSchema），写路径启停 / 排序后端已实装，单测走 msw。
// ---------------------------------------------------------------------------

/** Provider 列表（§5.2 行 1165）：筛选入参 {category, type, isEnabled} + 分页 §1.7；本页全量取数（见 buildListProvidersRequest）。 */
export function listProviders(
  request: ListProvidersRequest,
): Promise<ProviderListResponse> {
  return adminClient.listProviders(request);
}

/** 行内启停（§5.2 行 1173：`{providerKey, isEnabled}`）→ OkResponse；StatusSwitch 经此持久化。 */
export function setProviderEnabled(
  request: SetProviderEnabledRequest,
): Promise<OkResponse> {
  return adminClient.setProviderEnabled(request);
}

/** 拖拽排序（§5.2 行 1174：`{items:[{providerKey, sortOrder}]}`）→ OkResponse。 */
export function sortProviders(
  request: SortProvidersRequest,
): Promise<OkResponse> {
  return adminClient.sortProviders(request);
}

/**
 * 列表请求构造：第 1 页 × pageSize 100（§1.7 行 277 上限）。**全量取数**是
 * 拖拽排序的前提——SortProviders 按行集整体重排 sort_order（见
 * buildSortProvidersRequest），部分行集重排会与未载入行的排序值冲突；Provider
 * 注册表规模（oauth / captcha / sms / email / storage / notify 各有限几种
 * 类型）远小于 100。超限兜底：ProvidersPage 停用拖拽（数据仍展示）。
 */
export function buildListProvidersRequest(): ListProvidersRequest {
  return create(ListProvidersRequestSchema, {
    page: BigInt(FIRST_PAGE),
    pageSize: BigInt(MAX_PAGE_SIZE),
  });
}

/**
 * 排序请求构造：拖拽落定后按新数组序整体重排（index+1 → 1..n），全量行集
 * 下即全局一致序。不可变：只读入参，输出独立消息。
 */
export function buildSortProvidersRequest(
  rows: readonly Provider[],
): SortProvidersRequest {
  return create(SortProvidersRequestSchema, {
    items: rows.map((row, index) => ({
      providerKey: row.providerKey,
      sortOrder: BigInt(index + 1),
    })),
  });
}

// ---------------------------------------------------------------------------
// Provider 编辑族（§5.2 行 1169-1177 + §5.3）：GetProviderTypes /
// GetProviderSchema / GetProvider / Create / Update / Test 全部真调（后端
// 已实装）；Create / Update 请求体为 google.protobuf.Struct（提交体
// 即 {"<key>": <value>} 平铺，构造逻辑在 schema/schemaLogic.buildProviderStruct）。
// ---------------------------------------------------------------------------

/** type 下拉数据源（§5.2 行 1175：来自注册表 metas，不分页）。 */
export function getProviderTypes(): Promise<ProviderTypesResponse> {
  return adminClient.getProviderTypes({});
}

/** 动态表单 schema（§5.2 行 1176 / §5.3：{type} → {type, category, fields}）。 */
export function getProviderSchema(
  request: GetProviderSchemaRequest,
): Promise<SchemaResponse> {
  return adminClient.getProviderSchema(request);
}

/** 详情（§5.2 行 1170：{providerKey}，返回明文凭证——全站唯一明文出口）。 */
export function getProvider(request: GetProviderRequest): Promise<AdminProvider> {
  return adminClient.getProvider(request);
}

/** 新建（§5.2 行 1169：请求体为 §5.3 schema 字段集合，JsonObject 平铺含 type）→ OkResponse。 */
export function createProvider(values: JsonObject): Promise<OkResponse> {
  return adminClient.createProvider(fromJson(StructSchema, values));
}

/** 编辑（§5.2 行 1171：提交体平铺含 provider_key 定位，缺省键保留）→ OkResponse。 */
export function updateProvider(values: JsonObject): Promise<OkResponse> {
  return adminClient.updateProvider(fromJson(StructSchema, values));
}

/** 发送测试（§5.2 行 1177：{providerKey, target}，短信 / 邮件类）→ OkResponse。 */
export function testProvider(request: TestProviderRequest): Promise<OkResponse> {
  return adminClient.testProvider(request);
}

/**
 * 策略标签展示纯函数（§5.2 行 1165 列表「策略标签」列）：enableSignin /
 * enableSignup / autoBind 三开关 → 文案标签；全 false（如 sms / email /
 * storage / captcha 类）→ 空数组，消费方渲染占位。零 Semi 依赖、node 可测
 * （展示纯函数落位同 adminDisplayName 口径）。
 */
export function policyTags(provider: Provider): readonly string[] {
  const tags: string[] = [];
  if (provider.enableSignin) {
    tags.push('允许登录');
  }
  if (provider.enableSignup) {
    tags.push('允许注册');
  }
  if (provider.autoBind) {
    tags.push('自动绑定');
  }
  return tags;
}

/**
 * 401 判定（§6 行 501）：transport 归一后的 ApiError，HTTP 401 或 Connect
 * 标准码 unauthenticated（接口文档 §1.5 行 184-193 两者同源；双条件并列）。
 */
export function isUnauthenticatedError(error: unknown): boolean {
  return (
    error instanceof ApiError &&
    (error.httpStatus === 401 || error.code === 'unauthenticated')
  );
}

/**
 * 404 掩护判定（§6 行 501 / 接口文档 §5 行 1149）：会话有效但非管理员 →
 * HTTP 404（`not_found`）；双条件口径与 isUnauthenticatedError 对称。
 */
export function isAdminNotFoundError(error: unknown): boolean {
  return (
    error instanceof ApiError &&
    (error.httpStatus === 404 || error.code === 'not_found')
  );
}

/** GetMe 失败分流结果（§6 行 501：401 跳登录 / 其余含 404 掩护走错误态）。 */
export type AdminMeFailureAction = 'redirect_login' | 'show_error';

/**
 * GetMe 失败分流判定（§6 行 501 纯函数，node 可测）：
 * - 401（未携带有效会话）→ 'redirect_login'：布局层跳 `{al_root}/sso/login`；
 * - 其余（含 404 掩护——会话有效但非管理员）→ 'show_error'：ApiError 走
 *   统一错误处理显示错误态，**不跳登录**（跳登录即泄露管理面存在）。
 */
export function adminMeFailureAction(error: unknown): AdminMeFailureAction {
  return isUnauthenticatedError(error) ? 'redirect_login' : 'show_error';
}

/**
 * 顶栏管理员展示名（§5.1 行 1159 + §9 第 18 条零值兜底）：昵称缺省回落
 * username；两者皆空的极端情形（后端不该下发）回落「管理员」占位。
 */
export function adminDisplayName(me: MeResponse): string {
  if (me.nickname !== '') {
    return me.nickname;
  }
  return me.username !== '' ? me.username : '管理员';
}

/** 非 ApiError（未知异常）兜底文案；与 errors.code.unknown 同文（i18n 无独立键）。 */
const UNKNOWN_ERROR_TEXT = '操作失败，请稍后重试';

/**
 * 提交错误 → 展示文案（§1.5 行 202：i18n 优先；404 掩护即经
 * errors.code.not_found 出通用「资源不存在」文案，不暴露管理面语义）；
 * 未知异常兜底不透出内部信息（既定口径）。
 */
export function apiErrorText(error: unknown): string {
  if (error instanceof ApiError) {
    return t(resolveCode(error).i18nKey);
  }
  return UNKNOWN_ERROR_TEXT;
}

// ---------------------------------------------------------------------------
// 用户管理族（§5.4 行 1245-1255）：ListUsers / GetUser / UpdateUserStatus /
// ResetUserPassword / UnbindUserThirdparty / UnlockUser / GetUserEvents 七方法
// 全部真调（后端已实装）；单测走 msw。请求构造 / 展示纯函数同段落位
// （adminDisplayName 同口径，node 可测；页面壳 import Semi 不可测见
// admin.test.tsx 头注）。user_status 值域（§5.4 行 1251）：1 启用 0 禁用。
// ---------------------------------------------------------------------------

/** ListUsers（§5.4 行 1249：筛选入参 {q, userStatus} + 分页 §1.7）→ 用户列表。 */
export function listUsers(request: ListUsersRequest): Promise<UserListResponse> {
  return adminClient.listUsers(request);
}

/** GetUser（§5.4 行 1250：{id} 详情，含凭证概览 / 三方绑定 / MFA 状态）。 */
export function getUser(request: GetUserRequest): Promise<UserDetailResponse> {
  return adminClient.getUser(request);
}

/**
 * 禁用 / 启用（§5.4 行 1251：{id, userStatus: 0 或 1}）→ OkResponse；
 * UsersPage 行内开关经此持久化（DataTable switchColumn 消费方）。
 */
export function updateUserStatus(request: UpdateUserStatusRequest): Promise<OkResponse> {
  return adminClient.updateUserStatus(request);
}

/**
 * 管理员重置密码（§5.4 行 1252：{id, password}，§5.6 密码策略服务端权威）→
 * OkResponse **仅成功**——§5.4 未定义返回新密码，新密码由管理员输入并转交
 * 该用户（范围明确不含自动生成新密码）。
 */
export function resetUserPassword(request: ResetUserPasswordRequest): Promise<OkResponse> {
  return adminClient.resetUserPassword(request);
}

/** 解绑第三方（§5.4 行 1253：{id, providerKey}）→ OkResponse。 */
export function unbindUserThirdparty(
  request: UnbindUserThirdpartyRequest,
): Promise<OkResponse> {
  return adminClient.unbindUserThirdparty(request);
}

/** 解除登录限制（§5.4 行 1254：{id}，清 uid / ip+账号 维度键）→ OkResponse。 */
export function unlockUser(request: UnlockUserRequest): Promise<OkResponse> {
  return adminClient.unlockUser(request);
}

/** 该用户登录记录（§5.4 行 1255：{id} + 分页 §1.7）→ UserEventsResponse。 */
export function getUserEvents(request: GetUserEventsRequest): Promise<UserEventsResponse> {
  return adminClient.getUserEvents(request);
}

/** user_status 值域（§5.4 行 1251）：1 启用 0 禁用。 */
export const USER_STATUS_ENABLED = BigInt(1);
export const USER_STATUS_DISABLED = BigInt(0);

/**
 * userStatus 筛选 / 行内开关共用的列 dataIndex（§5.4 行 1249 筛选入参）。
 * 可排序列的 dataIndex 直接取 wire 字段名（§1.7 行 277 sort 由前端限定），
 * TableQueryState.sort / filters 即 wire 值，无需映射表。
 */
export const USER_STATUS_DATA_INDEX = 'user_status';

/** 状态筛选下拉（DataTableColumn.filters；值 = user_status 十进制字符串）。 */
export const USER_STATUS_FILTERS: readonly { readonly value: string; readonly text: string }[] = [
  { value: '1', text: '正常' },
  { value: '0', text: '禁用' },
];

/**
 * ListUsers 请求构造（§5.4 行 1249 + §1.7 行 275-278）：
 * - q 去首尾空白，空即省略（不过滤；后端 q 匹配 username / nickname /
 *   email / phone 四列）；
 * - userStatus 取筛选列「恰好单选」的值（0 / 1 互斥语义，未选 / 多选即
 *   不过滤——多选等价全集，确定性规则）；
 * - 分页直映射；排序仅 order 非空时下发（dataTableLogic：清除排序后
 *   order=''，受控渲染与 wire 均只认非空 order）。
 */
export function buildListUsersRequest(q: string, query: TableQueryState): ListUsersRequest {
  const statusFilter = query.filters[USER_STATUS_DATA_INDEX] ?? [];
  const trimmed = q.trim();
  return create(ListUsersRequestSchema, {
    q: trimmed === '' ? undefined : trimmed,
    userStatus:
      statusFilter.length === 1 ? BigInt(statusFilter[0]) : undefined,
    page: BigInt(query.page),
    pageSize: BigInt(query.pageSize),
    sort: query.order === '' ? undefined : query.sort,
    order: query.order === '' ? undefined : query.order,
  });
}

/** GetUser 请求构造（§5.4 行 1250：{id}）。 */
export function buildGetUserRequest(id: bigint): GetUserRequest {
  return create(GetUserRequestSchema, { id });
}

/**
 * UpdateUserStatus 请求构造（§5.4 行 1251）：next=true 启用（1）/
 * false 禁用（0）。protojson 零值省略：禁用（0）时 userStatus 不下发，
 * 后端读零值即禁用，语义一致。
 */
export function buildUpdateUserStatusRequest(
  id: bigint,
  next: boolean,
): UpdateUserStatusRequest {
  return create(UpdateUserStatusRequestSchema, {
    id,
    userStatus: next ? USER_STATUS_ENABLED : USER_STATUS_DISABLED,
  });
}

/** ResetUserPassword 请求构造（§5.4 行 1252：{id, password}）。 */
export function buildResetUserPasswordRequest(
  id: bigint,
  password: string,
): ResetUserPasswordRequest {
  return create(ResetUserPasswordRequestSchema, { id, password });
}

/** UnbindUserThirdparty 请求构造（§5.4 行 1253：{id, providerKey}）。 */
export function buildUnbindUserThirdpartyRequest(
  id: bigint,
  providerKey: string,
): UnbindUserThirdpartyRequest {
  return create(UnbindUserThirdpartyRequestSchema, { id, providerKey });
}

/** UnlockUser 请求构造（§5.4 行 1254：{id}）。 */
export function buildUnlockUserRequest(id: bigint): UnlockUserRequest {
  return create(UnlockUserRequestSchema, { id });
}

/** GetUserEvents 请求构造（§5.4 行 1255：{id} + 分页 §1.7；排序口径同 buildListUsersRequest）。 */
export function buildGetUserEventsRequest(
  id: bigint,
  query: TableQueryState,
): GetUserEventsRequest {
  return create(GetUserEventsRequestSchema, {
    id,
    page: BigInt(query.page),
    pageSize: BigInt(query.pageSize),
    sort: query.order === '' ? undefined : query.sort,
    order: query.order === '' ? undefined : query.order,
  });
}

/**
 * Unix 秒 → 本地时间 YYYY-MM-DD HH:mm；零值 / 负值 → 占位符（§9 第 18 条
 * 零值兜底）。entry 间禁止互引（§9 第 13 条）故不 import account/api.ts
 * 同名函数，此处为 admin 落位版（实现同构）。
 */
export function formatUnixTime(seconds: bigint): string {
  if (seconds <= BigInt(0)) {
    return '—';
  }
  const d = new Date(Number(seconds) * 1000);
  const pad = (n: number): string => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** user_status 展示文案（§5.4 行 1251 值域 1/0）。 */
export function userStatusLabel(userStatus: bigint): string {
  return userStatus === USER_STATUS_ENABLED ? '正常' : '禁用';
}

/**
 * 凭证类型展示文案（《后端架构》§4.3 行 669 kind 五值域：password|totp|
 * webauthn|recovery_code|mfa_setting——GetUser 凭证概览含 mfa_setting
 * 行；跨版本新增原样兜底）。
 */
const USER_CREDENTIAL_KIND_LABELS: Readonly<Record<string, string>> = {
  password: '密码',
  totp: 'TOTP 动态码',
  webauthn: '通行密钥',
  recovery_code: '恢复码',
  mfa_setting: 'MFA 开关',
};

/** 凭证类型 kind → 展示文案（§5.4 行 1250 凭证概览）。 */
export function credentialKindLabel(kind: string): string {
  return USER_CREDENTIAL_KIND_LABELS[kind] ?? kind;
}

/** MFA 因子展示文案（§3.5 行 891-895 factor 值域；新增值原样兜底）。 */
const MFA_FACTOR_LABELS: Readonly<Record<string, string>> = {
  totp: 'TOTP 动态码',
  otp_sms: '短信验证码',
  otp_email: '邮箱验证码',
  webauthn: '通行密钥',
  recovery_code: '恢复码',
};

/** MFA 因子 factor → 展示文案。 */
export function mfaFactorLabel(factor: string): string {
  return MFA_FACTOR_LABELS[factor] ?? factor;
}

/**
 * 详情页 MFA 状态（§5.4 行 1250「MFA 状态」）：已绑定因子的展示文案列表；
 * mfa 缺省（protojson 零值省略）或无已绑定因子 → 空数组（消费方渲染占位）。
 */
export function boundMfaFactors(mfa: MfaResponse | undefined): string[] {
  return (mfa?.factors ?? [])
    .filter((factor) => factor.bound)
    .map((factor) => mfaFactorLabel(factor.factor));
}

// ---------------------------------------------------------------------------
// 客户端管理族（§5.5 行 1257-1268）：SSO 五方法 + OIDC 五方法全部
// 真调（后端已实装）；单测走 msw。字段：SSO = clientId /
// clientSecret / name / redirectUris[]（支持 *）；OIDC 额外 scopes[] /
// accessTokenTtl / refreshTokenTtl（§5.5 行 1262/1264「额外」逐字）。客户端
// 仅支持后台手动创建（§5.5 行 1266）；OIDC 不设授权类型字段（§5.5 行 1268
// 固定 authorization_code + refresh_token，不建模）。服务端口径（后端
// 实装语义，前端自律对齐 §1.7 行 277）：
// - Create：clientSecret 由服务端生成（请求同名字段被忽略，构造时不发）；
//   clientId 空 → 服务端生成、非空用提交值（≤64 字符）；redirectUris 条目
//   须字面 * 或 ^https?://；OIDC TTL 0 落库端默认（3600 / 2592000）。
// - Get：按自增 id 定位，返回明文 client_secret（全站唯一明文出口同
//   §5.2 行 1170 凭证口径）——Create 仅返回 OkResponse，密钥经 Get 查看。
// - Update：PATCH 缺省保留（空串 / 空组即不修改）；clientId 不可改（不发，
//   后端同值放行语义由空串触发保留分支）；clientSecret 非空 = 轮换；
//   OIDC TTL 0 保留原值、非 0 须在值域内。
// - Delete：硬删，行不存在 → 404。
// 请求构造 / 校验 / 展示纯函数同段落位（buildListUsersRequest 口径，
// node 可测；页面壳 import Semi 不可测见 admin.test.tsx 头注）。
// ---------------------------------------------------------------------------

/** SSO 客户端列表（§5.5 行 1261 + 分页 §1.7）→ SsoClientListResponse。 */
export function listSsoClients(
  request: ListSsoClientsRequest,
): Promise<SsoClientListResponse> {
  return adminClient.listSsoClients(request);
}

/** SSO 客户端新建（§5.5 行 1261）→ OkResponse（密钥服务端生成，经 Get 查看）。 */
export function createSsoClient(request: CreateSsoClientRequest): Promise<OkResponse> {
  return adminClient.createSsoClient(request);
}

/** SSO 客户端详情（§5.5 行 1262：{id} → SsoClient，含明文 client_secret）。 */
export function getSsoClient(request: GetSsoClientRequest): Promise<SsoClient> {
  return adminClient.getSsoClient(request);
}

/** SSO 客户端编辑（§5.5 行 1262：PATCH 缺省保留）→ OkResponse。 */
export function updateSsoClient(request: UpdateSsoClientRequest): Promise<OkResponse> {
  return adminClient.updateSsoClient(request);
}

/** SSO 客户端删除（§5.5 行 1262：{id} 硬删）→ OkResponse。 */
export function deleteSsoClient(request: DeleteSsoClientRequest): Promise<OkResponse> {
  return adminClient.deleteSsoClient(request);
}

/** OIDC 客户端列表（§5.5 行 1263 + 分页 §1.7）→ OidcClientListResponse。 */
export function listOidcClients(
  request: ListOidcClientsRequest,
): Promise<OidcClientListResponse> {
  return adminClient.listOidcClients(request);
}

/** OIDC 客户端新建（§5.5 行 1263 + 额外 scopes / TTL）→ OkResponse。 */
export function createOidcClient(request: CreateOidcClientRequest): Promise<OkResponse> {
  return adminClient.createOidcClient(request);
}

/** OIDC 客户端详情（§5.5 行 1264：{id} → OidcClient，含明文 client_secret）。 */
export function getOidcClient(request: GetOidcClientRequest): Promise<OidcClient> {
  return adminClient.getOidcClient(request);
}

/** OIDC 客户端编辑（§5.5 行 1264：PATCH 缺省保留 + TTL 0 保留原值）→ OkResponse。 */
export function updateOidcClient(request: UpdateOidcClientRequest): Promise<OkResponse> {
  return adminClient.updateOidcClient(request);
}

/** OIDC 客户端删除（§5.5 行 1264：{id} 硬删）→ OkResponse。 */
export function deleteOidcClient(request: DeleteOidcClientRequest): Promise<OkResponse> {
  return adminClient.deleteOidcClient(request);
}

/**
 * 列表条目非空清洗：逐条去首尾空白后剔除空串（编辑器允许中间态空行，
 * 提交前统一收口）。新建与编辑的 redirectUris / scopes 共用。
 */
export function cleanStringList(values: readonly string[]): string[] {
  return values.map((value) => value.trim()).filter((value) => value !== '');
}

/** 客户端标识长度上限（后端 sso_client.client_id VARCHAR(64) 字符数防御）。 */
export const CLIENT_ID_MAX_LEN = 64;

/** 展示名长度上限（后端 client_name_max_runes 同值）。 */
export const CLIENT_NAME_MAX_LEN = 128;

/** OIDC 访问令牌 TTL 默认 / 上限（秒；后端 §4.5 DDL 默认 3600、值域 [1, 86400]）。 */
export const OIDC_ACCESS_TTL_DEFAULT = 3600;
export const OIDC_ACCESS_TTL_MAX = 86400;

/** OIDC 刷新令牌 TTL 默认 / 上限（秒；DDL 默认 2592000、值域 [1, 2592000]）。 */
export const OIDC_REFRESH_TTL_DEFAULT = 2592000;
export const OIDC_REFRESH_TTL_MAX = 2592000;

/** redirectUris 条目校验失败文案（对齐后端：字面 * 或 ^https?://）。 */
export const REDIRECT_URIS_ISSUE_TEXT = '回调地址须为 * 或以 http:// / https:// 开头';

/**
 * 回调白名单条目校验（§5.5 行 1262「支持 *」+ §12.3 整段匹配；后端
 * 条目规则：字面 * 或 ^https?:// 前缀）。清洗后逐条判定，首个非法
 * 条目 → 文案；全部合法 / 空表 → null（空表合法性归调用方，见编辑阻断）。
 */
export function redirectUrisIssue(uris: readonly string[]): string | null {
  for (const uri of cleanStringList(uris)) {
    if (uri !== '*' && !/^https?:\/\//.test(uri)) {
      return REDIRECT_URIS_ISSUE_TEXT;
    }
  }
  return null;
}

/** scopes 条目校验失败文案（后端口径：非空且不含逗号——逗号串存储）。 */
export const SCOPES_ISSUE_TEXT = '权限范围条目不能为空，且不能包含逗号';

/**
 * 权限范围条目校验（§5.5 行 1264；后端口径：条目空串 / 含逗号 →
 * invalid_request）。清洗后逐条判定；全部合法 / 空表 → null。
 */
export function scopesIssue(scopes: readonly string[]): string | null {
  for (const scope of cleanStringList(scopes)) {
    if (scope.includes(',')) {
      return SCOPES_ISSUE_TEXT;
    }
  }
  return null;
}

/**
 * TTL 表单文本 → 秒数：空串 → 0（新建落库端默认 / 编辑保留原值）；正整数
 * 且 ≤ max → 秒数；其余（0 / 负数 / 非整数 / 超上限 / 非数字）→ null。
 */
export function parseTtlField(raw: string, max: number): number | null {
  const trimmed = raw.trim();
  if (trimmed === '') {
    return 0;
  }
  if (!/^\d+$/.test(trimmed)) {
    return null;
  }
  const value = Number(trimmed);
  if (!Number.isSafeInteger(value) || value < 1 || value > max) {
    return null;
  }
  return value;
}

/** SSO 客户端表单草稿（新建与编辑共用字段形态；clientId 仅新建消费——创建后不可改）。 */
export interface SsoClientDraft {
  readonly clientId: string;
  readonly name: string;
  readonly redirectUris: readonly string[];
}

/** SSO 客户端编辑草稿（clientId 不编辑；newSecret 留空保留原密钥、非空轮换）。 */
export interface SsoClientPatchDraft {
  readonly newSecret: string;
  readonly name: string;
  readonly redirectUris: readonly string[];
}

/** OIDC 客户端表单草稿：SSO 基线 + scopes / TTL（秒；0 = 缺省/保留）。 */
export interface OidcClientDraft extends SsoClientDraft {
  readonly scopes: readonly string[];
  readonly accessTokenTtl: number;
  readonly refreshTokenTtl: number;
}

/** OIDC 客户端编辑草稿：SSO 基线 + scopes / TTL（0 = 保留原值）。 */
export interface OidcClientPatchDraft extends SsoClientPatchDraft {
  readonly scopes: readonly string[];
  readonly accessTokenTtl: number;
  readonly refreshTokenTtl: number;
}

/** ListSsoClients 请求构造（分页 §1.7；排序仅 order 非空时下发，同 buildListUsersRequest）。 */
export function buildListSsoClientsRequest(query: TableQueryState): ListSsoClientsRequest {
  return create(ListSsoClientsRequestSchema, {
    page: BigInt(query.page),
    pageSize: BigInt(query.pageSize),
    sort: query.order === '' ? undefined : query.sort,
    order: query.order === '' ? undefined : query.order,
  });
}

/** ListOidcClients 请求构造（口径同 buildListSsoClientsRequest）。 */
export function buildListOidcClientsRequest(query: TableQueryState): ListOidcClientsRequest {
  return create(ListOidcClientsRequestSchema, {
    page: BigInt(query.page),
    pageSize: BigInt(query.pageSize),
    sort: query.order === '' ? undefined : query.sort,
    order: query.order === '' ? undefined : query.order,
  });
}

/** GetSsoClient 请求构造（§5.5 行 1262：{id}）。 */
export function buildGetSsoClientRequest(id: bigint): GetSsoClientRequest {
  return create(GetSsoClientRequestSchema, { id });
}

/** GetOidcClient 请求构造（§5.5 行 1264：{id}）。 */
export function buildGetOidcClientRequest(id: bigint): GetOidcClientRequest {
  return create(GetOidcClientRequestSchema, { id });
}

/**
 * CreateSsoClient 请求构造：clientId / name 去空白；redirectUris 清洗后
 * 整组提交；clientSecret 不发（服务端生成，请求同名字段被后端忽略）。
 * clientId 空串在 protojson 下省略 → 后端读零值生成。
 */
export function buildCreateSsoClientRequest(draft: SsoClientDraft): CreateSsoClientRequest {
  return create(CreateSsoClientRequestSchema, {
    clientId: draft.clientId.trim(),
    name: draft.name.trim(),
    redirectUris: cleanStringList(draft.redirectUris),
  });
}

/** CreateOidcClient 请求构造：SSO 基线 + scopes 清洗 + TTL（0 省略落库端默认）。 */
export function buildCreateOidcClientRequest(draft: OidcClientDraft): CreateOidcClientRequest {
  return create(CreateOidcClientRequestSchema, {
    clientId: draft.clientId.trim(),
    name: draft.name.trim(),
    redirectUris: cleanStringList(draft.redirectUris),
    scopes: cleanStringList(draft.scopes),
    accessTokenTtl: BigInt(draft.accessTokenTtl),
    refreshTokenTtl: BigInt(draft.refreshTokenTtl),
  });
}

/**
 * UpdateSsoClient 请求构造（PATCH 缺省保留）：clientId 不发（创建后不可改，
 * 零值省略 → 后端保留分支）；newSecret 留空 → clientSecret 零值省略即保留
 * 原密钥、非空覆盖轮换；name 空串保留原值。
 */
export function buildUpdateSsoClientRequest(
  id: bigint,
  draft: SsoClientPatchDraft,
): UpdateSsoClientRequest {
  return create(UpdateSsoClientRequestSchema, {
    id,
    clientSecret: draft.newSecret.trim(),
    name: draft.name.trim(),
    redirectUris: cleanStringList(draft.redirectUris),
  });
}

/** UpdateOidcClient 请求构造：SSO 基线 + scopes / TTL（0 省略保留原值）。 */
export function buildUpdateOidcClientRequest(
  id: bigint,
  draft: OidcClientPatchDraft,
): UpdateOidcClientRequest {
  return create(UpdateOidcClientRequestSchema, {
    id,
    clientSecret: draft.newSecret.trim(),
    name: draft.name.trim(),
    redirectUris: cleanStringList(draft.redirectUris),
    scopes: cleanStringList(draft.scopes),
    accessTokenTtl: BigInt(draft.accessTokenTtl),
    refreshTokenTtl: BigInt(draft.refreshTokenTtl),
  });
}

/** DeleteSsoClient 请求构造（§5.5 行 1262：{id}）。 */
export function buildDeleteSsoClientRequest(id: bigint): DeleteSsoClientRequest {
  return create(DeleteSsoClientRequestSchema, { id });
}

/** DeleteOidcClient 请求构造（§5.5 行 1264：{id}）。 */
export function buildDeleteOidcClientRequest(id: bigint): DeleteOidcClientRequest {
  return create(DeleteOidcClientRequestSchema, { id });
}

/**
 * 列表列摘要展示（回调白名单 / 权限范围共用）：空 → 占位符；单条 → 原值；
 * 多条 → 首条 + 计数（表格列宽受限，全量展示在详情弹窗）。
 */
export function summarizeList(values: readonly string[]): string {
  const cleaned = cleanStringList(values);
  if (cleaned.length === 0) {
    return '—';
  }
  if (cleaned.length === 1) {
    return cleaned[0];
  }
  return `${cleaned[0]} 等 ${cleaned.length} 条`;
}

/**
 * TTL 秒数人性化（OIDC 列表「令牌有效期」列与详情共用）：整除换算
 * 天 / 小时 / 分钟，否则原样秒数（3700 秒不凑整）。
 */
export function humanizeTtlSeconds(seconds: number): string {
  if (seconds > 0 && seconds % 86400 === 0) {
    return `${seconds / 86400} 天`;
  }
  if (seconds > 0 && seconds % 3600 === 0) {
    return `${seconds / 3600} 小时`;
  }
  if (seconds > 0 && seconds % 60 === 0) {
    return `${seconds / 60} 分钟`;
  }
  return `${seconds} 秒`;
}

/** OIDC 令牌有效期列摘要：访问 / 刷新两段人性化（int64 经 toCount 收窄）。 */
export function tokenTtlSummary(accessTokenTtl: bigint, refreshTokenTtl: bigint): string {
  return `访问 ${humanizeTtlSeconds(toCount(accessTokenTtl))} / 刷新 ${humanizeTtlSeconds(
    toCount(refreshTokenTtl),
  )}`;
}

/** TTL 详情展示（详情弹窗）：人性化 + 原始秒数并列。 */
export function ttlDetailText(ttl: bigint): string {
  const seconds = toCount(ttl);
  return `${humanizeTtlSeconds(seconds)}（${seconds} 秒）`;
}

// ---------------------------------------------------------------------------
// settings 族（§5.6 行 1287 / §6 行 520）：GetSettings 读 + SetSettings
// 写全部真调（后端已实装全量投影 / 全量替换）。⚠️ 全量替换语义：
// 零值也会被写入（protojson 零值字段 wire 省略 = 服务端读零值 = 写入零值），
// 表单必须全量提交全部 36 键、不能只提交改动字段——buildSetSettingsRequest
// 以草稿整体构造（草稿初始化 / 交叉校验见 settingsLogic.ts，行 1363 值域
// 交叉约束由前端设置页自律保证）。键集 = 36 字段：35 既有键 +
// 定稿新增的 https_deployment（=36，行 1354/1360；行 1361 非三态 → invalid_request，
// settingsDraftIssue 前端自律拦截）。
// ---------------------------------------------------------------------------

/** 全部系统配置（§5.6 行 1287：36 键全量投影，键名不得另起别名）。 */
export function getSettings(): Promise<SettingsResponse> {
  return adminClient.getSettings({});
}

/** 全量提交系统配置（§5.6 行 1287 SetSettings）→ OkResponse（热更新生效）。 */
export function setSettings(request: SetSettingsRequest): Promise<OkResponse> {
  return adminClient.setSettings(request);
}

/**
 * SetSettings 全量请求构造（36 键整体构造，含未改动键）：文本字段去首尾
 * 空白、列表字段经 cleanStringList 清洗（条目去空白 + 剔除空串）后整组提交
 * ——中间态空行不落库；其余键原样直映射（https_deployment 三态枚举值不做
 * trim，非法值由 settingsDraftIssue 前置拦截）。零值字段（false / 0 / '' /
 * []）在 protojson 下 wire 省略，服务端按零值写入，语义等价（生成物
 * SetSettingsRequest 头注口径）。
 */
export function buildSetSettingsRequest(draft: SettingsDraft): SetSettingsRequest {
  return create(SetSettingsRequestSchema, {
    pwdMinLength: BigInt(draft.pwdMinLength),
    pwdMaxLength: BigInt(draft.pwdMaxLength),
    pwdRequireClasses: BigInt(draft.pwdRequireClasses),
    pwdDisallowUsername: draft.pwdDisallowUsername,
    pwdDisallowCommon: draft.pwdDisallowCommon,
    allowPasswordReset: draft.allowPasswordReset,
    otpResendInterval: BigInt(draft.otpResendInterval),
    otpTtl: BigInt(draft.otpTtl),
    otpMaxAttempts: BigInt(draft.otpMaxAttempts),
    otpDailyLimitTarget: BigInt(draft.otpDailyLimitTarget),
    otpDailyLimitIp: BigInt(draft.otpDailyLimitIp),
    loginMethods: cleanStringList(draft.loginMethods),
    allowRegistration: draft.allowRegistration,
    allowSignupPassword: draft.allowSignupPassword,
    allowSignupPhone: draft.allowSignupPhone,
    allowSignupEmail: draft.allowSignupEmail,
    mfaEnabled: draft.mfaEnabled,
    mfaMethods: cleanStringList(draft.mfaMethods),
    pwdFailCapture: BigInt(draft.pwdFailCapture),
    pwdFailBan: BigInt(draft.pwdFailBan),
    pwdBanTtl: BigInt(draft.pwdBanTtl),
    sessionTtl: BigInt(draft.sessionTtl),
    cookieName: draft.cookieName.trim(),
    ssoDomains: cleanStringList(draft.ssoDomains),
    queueWorkers: BigInt(draft.queueWorkers),
    queueCapacity: BigInt(draft.queueCapacity),
    queueBatch: BigInt(draft.queueBatch),
    queueFlushMs: BigInt(draft.queueFlushMs),
    captchaProviderKey: draft.captchaProviderKey.trim(),
    smsProviderKey: draft.smsProviderKey.trim(),
    emailProviderKey: draft.emailProviderKey.trim(),
    avatarStorageProvider: draft.avatarStorageProvider.trim(),
    gatewayTokens: cleanStringList(draft.gatewayTokens),
    eventlogRetentionDays: BigInt(draft.eventlogRetentionDays),
    staticBase: draft.staticBase.trim(),
    httpsDeployment: draft.httpsDeployment,
  });
}

// ---------------------------------------------------------------------------
// 工具三页族（§5.6 行 1288-1290 / §6 行 523-525）：ListEvents /
// DecodeToken / GetStatus 三方法全部真调（后端已实装）；单测走 msw。
// 预设视图口径（§5.6 行 1288「预设视图『登录记录』『敏感操作』」）：
// - 「登录记录」= event=login_success（《后端架构》§4.6 行 807 记录范围：
//   记录成功登录 + 各类敏感操作，登录记录即 login_success 单值）；
// - 「敏感操作」预设的事件类型集合文档未定义封闭集（《后端架构》§4.6
//   event 值域以 `|...` 收尾、§12.9 行 1754 跨版本可能新增；ListEvents
//   的 event 系单值正向精确过滤，无排除语义）——故停报该项，
//   仅交付「登录记录」预设 + 手动按类型筛选（需求 §4.6 行 260「可按类型
//   筛选」）。事件类型值域取《后端架构》§4.6 event 列注释，未知值原样
//   兜底展示（string 承载）。
// ---------------------------------------------------------------------------

/**
 * 统一事件视图（§5.6 行 1288：筛选入参 {event, actorType, actorId,
 * userId, from, to} + 分页 §1.7；查询参数缺省即不过滤，一律 optional）。
 */
export function listEvents(request: ListEventsRequest): Promise<EventListResponse> {
  return adminClient.listEvents(request);
}

/**
 * 解码工具（§5.6 行 1289：`{token, purpose:"login"｜"session"｜"cookie"}`
 * → DecodeResponse.payload，Struct 原样透传不为前台消费建模；排障用）。
 */
export function decodeToken(request: DecodeTokenRequest): Promise<DecodeResponse> {
  return adminClient.decodeToken(request);
}

/** 监控（§5.6 行 1290：队列长度 / dropped / flush 耗时，无入参）。 */
export function getStatus(): Promise<StatusResponse> {
  return adminClient.getStatus({});
}

/** 「登录记录」预设的事件类型（《后端架构》§4.6 行 807：成功登录 login_success）。 */
export const LOGIN_RECORDS_EVENT = 'login_success';

/**
 * AuditPage 预设视图（§5.6 行 1288）：'all' 统一视图（event 手动筛选）/
 * 'login_records' 登录记录（event 强制 login_success）。「敏感操作」预设
 * 事件类型集合文档未定义 → 按 STOP ② 停报，不在值域内（见段落头注）。
 */
export type AuditPreset = 'all' | 'login_records';

/** ListEvents 六筛选取值（§5.6 行 1288；undefined 即不下发 = 不过滤）。 */
export interface AuditEventFilters {
  readonly event?: string;
  readonly actorType?: string;
  readonly actorId?: bigint;
  readonly userId?: bigint;
  /** 起始时间，Unix 秒（§12.9 时间口径）。 */
  readonly from?: bigint;
  /** 结束时间，Unix 秒。 */
  readonly to?: bigint;
}

/**
 * ListEvents 请求构造（§5.6 行 1288 六筛选 + §1.7 行 275-278 分页）：
 * - login_records 预设：event 强制 login_success（手动 event 筛选让位）；
 *   其余五项筛选照常叠加（如「登录记录 + 操作者类型」）；
 * - all 预设：event 取手动筛选值，空 / 缺省即不过滤；
 * - 分页直映射；排序仅 order 非空时下发（dataTableLogic：清除排序后
 *   order=''，受控渲染与 wire 均只认非空 order，buildListUsersRequest 同口径）。
 */
export function buildListEventsRequest(
  preset: AuditPreset,
  filters: AuditEventFilters,
  query: TableQueryState,
): ListEventsRequest {
  return create(ListEventsRequestSchema, {
    event:
      preset === 'login_records'
        ? LOGIN_RECORDS_EVENT
        : filters.event === '' || filters.event === undefined
          ? undefined
          : filters.event,
    actorType: filters.actorType === '' || filters.actorType === undefined ? undefined : filters.actorType,
    actorId: filters.actorId,
    userId: filters.userId,
    from: filters.from,
    to: filters.to,
    page: BigInt(query.page),
    pageSize: BigInt(query.pageSize),
    sort: query.order === '' ? undefined : query.sort,
    order: query.order === '' ? undefined : query.order,
  });
}

/** DecodeToken 请求构造（§5.6 行 1289：{token, purpose}；token 去首尾空白）。 */
export function buildDecodeTokenRequest(token: string, purpose: string): DecodeTokenRequest {
  return create(DecodeTokenRequestSchema, { token: token.trim(), purpose });
}

/**
 * 事件类型展示文案（《后端架构》§4.6 event 列值域 16 常量 + §4.6 行 809
 * oidc_authorize_no_state，共 17 已知值；跨版本新增原样兜底，§12.9 行 1754）。
 */
const EVENT_TYPE_LABELS: Readonly<Record<string, string>> = {
  login_success: '登录成功',
  change_password: '修改密码',
  reset_password: '重置密码',
  bind_phone: '绑定手机号',
  bind_email: '绑定邮箱',
  enable_mfa: '启用两步验证',
  disable_mfa: '关闭两步验证',
  webauthn_register: '注册通行密钥',
  webauthn_delete: '删除通行密钥',
  thirdparty_bind: '绑定第三方',
  thirdparty_unbind: '解绑第三方',
  admin_disable_user: '管理员禁用用户',
  admin_reset_password: '管理员重置密码',
  provider_create: '新建提供方',
  provider_update: '更新提供方',
  settings_update: '更新系统设置',
  oidc_authorize_no_state: 'OIDC 授权缺少 state',
};

/** 事件类型 → 展示文案（未知值原样兜底，§9 第 18 条）。 */
export function eventTypeLabel(event: string): string {
  return EVENT_TYPE_LABELS[event] ?? event;
}

/** 事件类型筛选下拉（§5.6 行 1288 event 过滤；值域 = 上述 17 已知类型）。 */
export const EVENT_TYPE_FILTERS: readonly { readonly value: string; readonly text: string }[] =
  Object.entries(EVENT_TYPE_LABELS).map(([value, text]) => ({ value, text }));

/** 操作者类型展示文案（《后端架构》§4.6 actor_type 值域 user|admin|system）。 */
const ACTOR_TYPE_LABELS: Readonly<Record<string, string>> = {
  user: '用户',
  admin: '管理员',
  system: '系统',
};

/** 操作者类型 → 展示文案（未知值原样兜底）。 */
export function actorTypeLabel(actorType: string): string {
  return ACTOR_TYPE_LABELS[actorType] ?? actorType;
}

/** 操作者类型筛选下拉（§5.6 行 1288 actorType 过滤 user|admin|system）。 */
export const ACTOR_TYPE_FILTERS: readonly { readonly value: string; readonly text: string }[] =
  Object.entries(ACTOR_TYPE_LABELS).map(([value, text]) => ({ value, text }));

/**
 * 操作者展示（§4.6：system 事件 actor_id=0 不编造用户 id → 仅展示「系统」；
 * user / admin 附 actor_id 便于排查）。
 */
export function actorText(actorType: string, actorId: bigint): string {
  if (actorType === 'system') {
    return '系统';
  }
  return `${actorTypeLabel(actorType)} ${actorId}`;
}

/** ID 类 bigint 展示（§9 第 18 条零值兜底：0 → 占位符；其余十进制化）。 */
export function bigIdText(value: bigint): string {
  return value <= BigInt(0) ? '—' : value.toString();
}

/** 事件详情展示（EventItem.detail，JsonObject → 紧凑 JSON；缺省 → 占位符）。 */
export function eventDetailText(detail: JsonObject | undefined): string {
  return detail === undefined ? '—' : JSON.stringify(detail);
}

/** 解码载荷展示（DecodeResponse.payload，JsonObject → 缩进 JSON；缺省 → 占位符）。 */
export function decodePayloadText(payload: JsonObject | undefined): string {
  return payload === undefined ? '—' : JSON.stringify(payload, null, 2);
}

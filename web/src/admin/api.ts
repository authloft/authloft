/**
 * AdminService client 方法封装（docs/前端架构.md §6 行 505-506；docs/接口文档.md §5）。
 * 本次交付 GetMe（§5.1 行 1159：前端获取管理员信息的唯一来源，`/admin/**`
 * 空壳页不注入 `admin` 字段）并追加 Provider 列表族：ListProviders /
 * SetProviderEnabled / SortProviders 薄封装 + 列表 / 排序请求构造与策略标签
 * 展示纯函数（§5.2 行 1164-1177）；并追加 Provider 编辑族：
 * GetProviderTypes / GetProviderSchema / GetProvider / Create / Update /
 * TestProvider（§5.2 行 1169-1177 + §5.3）；并追加用户管理族七方法
 * （§5.4 行 1249-1255）+ 请求构造 / 展示纯函数；客户端 / settings /
 * 工具族方法随后续实现逐步追加（管理端无 multipart 上传，§6 行 506）。
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
import type { MeResponse, OkResponse } from '../gen/proto/api/admin/v1/admin_pb';
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

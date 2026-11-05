/**
 * AdminService client 方法封装（docs/前端架构.md §6 行 505-506；docs/接口文档.md §5）。
 * 本次交付 GetMe（§5.1 行 1159：前端获取管理员信息的唯一来源，`/admin/**`
 * 空壳页不注入 `admin` 字段）并追加 Provider 列表族：ListProviders /
 * SetProviderEnabled / SortProviders 薄封装 + 列表 / 排序请求构造与策略标签
 * 展示纯函数（§5.2 行 1164-1177）；用户 / 客户端 / settings / 工具族方法随
 * 后续实现逐步追加（管理端无 multipart 上传，§6 行 506）。
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
import { create } from '@bufbuild/protobuf';
import { ApiError, resolveCode } from '../shared/api/errors';
import { adminClient } from '../shared/api/http';
import { t } from '../shared/i18n';
import { FIRST_PAGE, MAX_PAGE_SIZE } from '../shared/app-ui/dataTableLogic';
import type { MeResponse, OkResponse } from '../gen/proto/api/admin/v1/admin_pb';
import type {
  ListProvidersRequest,
  Provider,
  ProviderListResponse,
  SetProviderEnabledRequest,
  SortProvidersRequest,
} from '../gen/proto/api/admin/v1/provider_pb';
import {
  ListProvidersRequestSchema,
  SortProvidersRequestSchema,
} from '../gen/proto/api/admin/v1/provider_pb';

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

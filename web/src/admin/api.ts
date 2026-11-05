/**
 * AdminService client 方法封装（docs/前端架构.md §6 行 505-506；docs/接口文档.md §5）。
 * 本次交付 GetMe（§5.1 行 1159：前端获取管理员信息的唯一来源，`/admin/**`
 * 空壳页不注入 `admin` 字段）；Provider / 用户 / 客户端 / settings / 工具族
 * 方法随后续实现逐步追加（管理端无 multipart 上传，§6 行 506）。
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
import { ApiError, resolveCode } from '../shared/api/errors';
import { adminClient } from '../shared/api/http';
import { t } from '../shared/i18n';
import type { MeResponse } from '../gen/proto/api/admin/v1/admin_pb';

/** 当前管理员信息（§5.1 行 1159）：`{id, username, nickname, avatarUrl, isAdmin:true}`，无入参。 */
export function getMe(): Promise<MeResponse> {
  return adminClient.getMe({});
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

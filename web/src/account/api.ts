/**
 * AccountService client 方法封装（docs/前端架构.md §5 行 479；docs/接口文档.md §3）。
 * 本次仅交付 GetProfile（§3.2 行 819，后端已实装）；其余方法
 * （GetConfig / UpdateProfile / ThirdpartyOauth 等）随消费页面落地时再封
 * （api.ts 可封装方法但页面不消费桩方法）。
 * 本 entry 另需的 SsoService 方法（Authorize scene=bind / CreateQrcode）
 * 从 shared/api/sso 取，不在此重复定义（§5 行 479）。
 *
 * transport 与 client 只在 shared/api/http.ts 构造（§9 第 16 条），本模块
 * 从那里拿 accountClient、不自建 transport；请求状态语义归
 * shared/hooks/useRequest（§3.2），本模块是薄封装。
 * 报文类型全部取自 src/gen/proto 生成物（§9 第 15 条）。
 *
 * 401 统一跳登录（§5 行 480）：shared/api/http 的错误归一层只做
 * ConnectError → ApiError（无统一跳转），判定 + 跳转的职责在本 entry：
 * isUnauthenticatedError 供各页面 / 布局层消费，跳转目标 loginUrl
 * 见 ./bootstrap。
 */
import type { ProfileResponse } from '../gen/proto/api/account/v1/profile_pb';
import { ApiError } from '../shared/api/errors';
import { accountClient } from '../shared/api/http';

/** 用户资料（§3.2 行 819；§3.1 统一用户信息结构，无入参）。 */
export function getProfile(): Promise<ProfileResponse> {
  return accountClient.getProfile({});
}

/**
 * 401 未登录判定（§5 行 480）：transport 归一后的 ApiError，HTTP 401 或
 * Connect 标准码 unauthenticated（接口文档 §1.5 行 184-193 两者同源；
 * 双条件并列防后端未来改走 ErrorInfo 业务码）。
 */
export function isUnauthenticatedError(error: unknown): boolean {
  return (
    error instanceof ApiError &&
    (error.httpStatus === 401 || error.code === 'unauthenticated')
  );
}

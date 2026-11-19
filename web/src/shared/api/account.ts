/**
 * 跨 entry 复用的 AccountService client 方法薄封装（docs/前端架构.md §3.1
 * 行 321；接口文档 §3）。只做薄封装、不承载业务分支（§3.1 行 321 关键约束：
 * proxy / direct 模式差异归 shared/hooks/useUpload，不外泄到本层）。
 *
 * 头像族四件（自 account/api.ts 迁移落位，原实现不再保留）：
 * GetConfig / PresignAvatar / CommitAvatar / UploadAvatar（接口文档 §3.2；
 * avatarUpload 供 useUpload 在 proxy / direct 间切换）。proxy 模式上传为
 * AccountService/UploadAvatar 一次 bytes 直传，走 transport 归一链。
 * ThirdpartyOauth（§3.7.1 A 行 969-1003）：OAuthCallbackPage b
 * 前缀分支的绑定回调实调（login entry 消费，§2.7.3）。
 *
 * transport 与 client 只在 shared/api/http.ts 构造（§9 第 16 条），本模块
 * 从那里拿 accountClient、不自建 transport；报文类型只从 src/gen/proto
 * 生成物引用（§9 第 15 条），不描述字段。
 */
import { accountClient } from './http';
import type {
  AccountConfigResponse,
  AvatarPresignResponse,
  AvatarResponse,
  CommitAvatarRequest,
  PresignAvatarRequest,
  UploadAvatarRequest,
} from '../../gen/proto/api/account/v1/profile_pb';
import type {
  ThirdpartyOauthRequest,
  ThirdpartyOauthResponse,
} from '../../gen/proto/api/account/v1/thirdparty_pb';

/**
 * 安全中心配置（§3.2 行 835）：avatarUpload / mfaPolicy / captcha / hasPassword；
 * account entry 的配置读取处（mfaPolicy 消费归安全中心，useUpload 只取 avatarUpload）。
 */
export function getConfig(): Promise<AccountConfigResponse> {
  return accountClient.getConfig({});
}

/** direct 模式取预签名（§3.2 行 839 / §10.8）：key 由服务端生成，前端无法覆盖。 */
export function presignAvatar(
  request: PresignAvatarRequest,
): Promise<AvatarPresignResponse> {
  return accountClient.presignAvatar(request);
}

/** direct 模式确认上传（§3.2 行 840）：仅记录已上传，不回读校验。 */
export function commitAvatar(
  request: CommitAvatarRequest,
): Promise<AvatarResponse> {
  return accountClient.commitAvatar(request);
}

/**
 * 三方绑定回调落地（§3.7.1 A 行 969-1003）：channel=redirect，OAuthCallbackPage
 * b 前缀分支实调（需 al_session）。**非信封**、不 Set-Cookie、不签发
 * login_token——绑定不改变登录态（行 1000）；失败为 Connect 错误体，
 * ErrorInfo.code 走 §1.6 位置二（由调用方消费，本层只薄转发）。
 */
export function thirdpartyOauth(
  request: ThirdpartyOauthRequest,
): Promise<ThirdpartyOauthResponse> {
  return accountClient.thirdpartyOauth(request);
}

/**
 * proxy 模式头像上传（§3.2 / §10.8）：AccountService/UploadAvatar 一次
 * bytes 直传，服务端校验 MIME / 大小后落盘并回显 url；protojson 编解码下
 * content 为 base64（§1.1），走 transport 统一错误归一链（请求体超上限由
 * 框架返回 resource_exhausted，§1.5）。
 */
export function uploadAvatar(
  request: UploadAvatarRequest,
): Promise<AvatarResponse> {
  return accountClient.uploadAvatar(request);
}

/**
 * 兼容转发名：account/api.ts 收编层按旧名 re-export（保既有调用方零改动），
 * 仅作编译兼容保留；proxy 模式上传已改走 AccountService/UploadAvatar，
 * REST multipart 端点不再存在。新代码一律用 uploadAvatar。
 */
export const uploadAvatarProxy = uploadAvatar;

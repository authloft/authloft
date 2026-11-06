/**
 * 跨 entry 复用的 AccountService client 方法薄封装（docs/前端架构.md §3.1
 * 行 321；接口文档 §3）。只做薄封装、不承载业务分支（§3.1 行 321 关键约束：
 * proxy / direct 模式差异归 shared/hooks/useUpload，不外泄到本层）。
 *
 * 头像族四件（自 account/api.ts 迁移落位，原实现不再保留）：
 * GetConfig / PresignAvatar / CommitAvatar + proxy 直传 postForm（接口文档
 * §3.2 行 835-840；avatarUpload 供 useUpload 在 proxy / direct 间切换）。
 * ThirdpartyOauth 随 OAuthCallbackPage b 分支联调再封（§2.7.3）。
 *
 * transport 与 client 只在 shared/api/http.ts 构造（§9 第 16 条），本模块
 * 从那里拿 accountClient、不自建 transport；报文类型只从 src/gen/proto
 * 生成物引用（§9 第 15 条），不描述字段。
 * proxy 直传是 REST 豁免端点（§1.0），不走 transport，经 http.ts 的 postForm
 * （XHR 进度 + 同口径错误归一）；URL 前缀 al_root 与 transport baseUrl 同口径
 * ——http.ts 的 resolveBaseUrl 不导出且契约层禁改，
 * shared 层禁止 import entry（§9 第 13 条），故内联同款归一（account/
 * bootstrap.ts normalizeAlRoot 同源口径）。
 */
import { accountClient, postForm, type UploadProgress } from './http';
import type {
  AccountConfigResponse,
  AvatarPresignResponse,
  AvatarResponse,
  CommitAvatarRequest,
  PresignAvatarRequest,
} from '../../gen/proto/api/account/v1/profile_pb';
import { AvatarResponseSchema } from '../../gen/proto/api/account/v1/profile_pb';

/** __AUTHLOFT_INIT__ 的最小形状（接口文档 §8 白名单中的 al_root）。 */
interface RawInit {
  al_root?: unknown;
}

/**
 * al_root 取法（与 shared/api/http.ts resolveBaseUrl 同口径）：string 校验 →
 * trim → 去尾斜杠；缺省回落当前站点源；非浏览器环境（单测 node）为空串。
 */
function resolveAlRoot(): string {
  const raw = (globalThis as { __AUTHLOFT_INIT__?: RawInit }).__AUTHLOFT_INIT__;
  const alRoot =
    typeof raw?.al_root === 'string' ? raw.al_root.trim().replace(/\/+$/, '') : '';
  if (alRoot !== '') {
    return alRoot;
  }
  return typeof location !== 'undefined' ? location.origin : '';
}

/**
 * 安全中心配置（§3.2 行 835）：avatarUpload / mfaPolicy / captcha / hasPassword；
 * account entry 的配置读取处（mfaPolicy 消费归安全中心，useUpload 只取 avatarUpload）。
 */
export function getConfig(): Promise<AccountConfigResponse> {
  return accountClient.getConfig({});
}

/** direct 模式取预签名（§3.2 行 839 / §10.8）：key 由服务端生成，前端无法覆盖。 */
export function presignAvatar(request: PresignAvatarRequest): Promise<AvatarPresignResponse> {
  return accountClient.presignAvatar(request);
}

/** direct 模式确认上传（§3.2 行 840）：仅记录已上传，不回读校验。 */
export function commitAvatar(request: CommitAvatarRequest): Promise<AvatarResponse> {
  return accountClient.commitAvatar(request);
}

/**
 * proxy 模式头像直传（§3.2 行 838：POST /api/account/avatar，multipart，
 * REST 豁免 §1.0）：不走 transport，经 shared/api/http 的 postForm（XHR 进度 +
 * 同口径错误归一）。
 */
export function uploadAvatarProxy(
  formData: FormData,
  onUploadProgress?: (progress: UploadProgress) => void,
): Promise<AvatarResponse> {
  return postForm(`${resolveAlRoot()}/api/account/avatar`, formData, {
    res: AvatarResponseSchema,
    onUploadProgress,
  });
}

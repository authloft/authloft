/**
 * 跨 entry 复用的 SsoService client 方法薄封装（docs/前端架构.md §3.1 行 282）：
 * 只放被 ≥2 个 entry 使用的调用，login 专属调用仍留在
 * login/api.ts（§3.1 行 282 职责列）。
 *
 * 本实现仅 CreateCaptchaImage——login（登录 / 注册 / 重置 / 扫码，接口文档 §2.5
 * 触发规则表）与 account（绑定 / 换绑手机号邮箱，接口文档 §3.4）两端的 captcha
 * 取图共用（§2.5 行 490-497）；Authorize / CreateQrcode 等留到有跨 entry 复用
 * 需求时再补，不预建。
 *
 * transport 与 client 只在 shared/api/http.ts 构造（§3.1 行 279、§9 第 16 条），
 * 本模块从那里拿 ssoClient、不自建 transport；报文类型只从 src/gen/proto
 * 生成物引用（§9 第 15 条），本模块不描述字段、不承载业务分支。
 */
import { ssoClient } from './http';
import type { CreateCaptchaImageResponse } from '../../gen/proto/api/sso/v1/login_pb';

/**
 * SsoService/CreateCaptchaImage（接口文档 §2.5 行 490）：新建自绘图形码
 * （无请求参数——全局仅一个 captcha Provider，服务端自行判定降级，空请求
 * 消息见生成物 login_pb.ts 行 185-187）。
 */
export async function createCaptchaImage(): Promise<CreateCaptchaImageResponse> {
  return ssoClient.createCaptchaImage({});
}

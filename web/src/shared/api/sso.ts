/**
 * 跨 entry 复用的 SsoService client 方法薄封装（docs/前端架构.md §3.1 行 282）：
 * 只放被 ≥2 个 entry 使用的调用，login 专属调用仍留在
 * login/api.ts（§3.1 行 282 职责列）。
 *
 * CreateCaptchaImage——login（登录 / 注册 / 重置 / 扫码，接口文档
 * §2.5 触发规则表）与 account（绑定 / 换绑手机号邮箱，接口文档 §3.4）两端的
 * captcha 取图共用（§2.5 行 490-497）。
 * 追加 Authorize / CreateQrcode（前端架构 §5 行 479：account entry 的
 * 三方绑定明确从本模块取这两个 SsoService 方法，不重复定义）；已完成收
 * 敛——login/api.ts 删除同构实现改为 re-export 本模块导出，MessageInput /
 * MessageField 工具类型亦以本模块为单一来源（§3.1 行 319 禁止双份手写）。
 *
 * transport 与 client 只在 shared/api/http.ts 构造（§3.1 行 279、§9 第 16 条），
 * 本模块从那里拿 ssoClient、不自建 transport；报文类型只从 src/gen/proto
 * 生成物引用（§9 第 15 条），本模块不描述字段、不承载业务分支。
 */
import { ssoClient } from './http';
import type { Message } from '@bufbuild/protobuf';
import type { CreateCaptchaImageResponse } from '../../gen/proto/api/sso/v1/login_pb';
import type { AuthorizeRequest, AuthorizeResponse } from '../../gen/proto/api/sso/v1/oauth_pb';
import type { CreateQrcodeRequest, CreateQrcodeResponse } from '../../gen/proto/api/sso/v1/ticket_pb';

/**
 * 生成物消息 → init 形状（@connectrpc/connect 未导出该工具类型；
 * 此处为唯一定义，login/api.ts 从本模块引用）：字段 optional 化、嵌套消息递
 * 归、剔除消息符号键 $typeName / $unknown——authorize({provider, scene})
 * 一类平铺对象即可入参。
 */
export type MessageInput<T> = {
  [P in keyof T as P extends '$typeName' | '$unknown' ? never : P]?: MessageField<T[P]>;
};

/** 嵌套字段递归：消息 → init；数组逐元素；其余（string / bigint / JsonObject）原样。 */
export type MessageField<F> =
  F extends Message<string>
    ? MessageInput<F>
    : F extends (infer U)[]
      ? MessageField<U>[]
      : F;

/**
 * SsoService/CreateCaptchaImage（接口文档 §2.5 行 490）：新建自绘图形码
 * （无请求参数——全局仅一个 captcha Provider，服务端自行判定降级，空请求
 * 消息见生成物 login_pb.ts 行 185-187）。
 */
export async function createCaptchaImage(): Promise<CreateCaptchaImageResponse> {
  return ssoClient.createCaptchaImage({});
}

/**
 * SsoService/Authorize（接口文档 §2.7.2 行 580）：取第三方授权 URL（RPC 非
 * 302）；scene 由请求消息承载（login 缺省 / bind 需 al_session），跳转由
 * 调用方 location.replace。
 */
export async function authorize(
  request: MessageInput<AuthorizeRequest>,
): Promise<AuthorizeResponse> {
  return ssoClient.authorize(request);
}

/**
 * SsoService/CreateQrcode（接口文档 §2.8 行 688）：拉取小程序码（必须携带
 * captcha，每次拉码都要新的，行 703；登录与绑定共用，靠 scene 区分）。
 */
export async function createQrcode(
  request: MessageInput<CreateQrcodeRequest>,
): Promise<CreateQrcodeResponse> {
  return ssoClient.createQrcode(request);
}

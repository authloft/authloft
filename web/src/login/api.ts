/**
 * SsoService client 方法封装（docs/前端架构.md §4.1 行 377；docs/接口文档.md §2）：
 * LoginDefault（§2.2）、Register（§2.3）、ResetPassword（§2.4）、Authorize（§2.7.2）、
 * LoginOauth（§2.7.4）、CreateQrcode（§2.8）、GetLoginTicket（§2.8 轮询）。
 * ConfirmLoginTicket 由宿主 / 第三方客户端调用，本工程不实现（接口文档 §2.8 行
 * 749）；CreateCaptchaImage 已归口 shared/api/sso.ts（跨 entry 共用，
 * 本实现删除本模块同名函数）；Authorize /
 * CreateQrcode 亦已归口该模块（登录与 account 绑定共用，本模块
 * re-export 保持消费方 ../api import 路径不变）。
 *
 * login_token 传递（接口文档 §1.8 / §1.3 行 145 唯一定义；前端架构 §4.1
 * 行 397-403 五条不可打折）：
 * - 请求体顶层自动注入 loginToken（loginTokenStore 内存变量，收到就替换、请求就带上）；
 * - 首次请求（尚无 login_token）额外带上 oidc——LoginDefault / Register /
 *   ResetPassword 取注入快照 __AUTHLOFT_INIT__.oidc（§2.2 行 425）；LoginOauth
 *   取跳转前落盘的 al_oidc_ctx（§2.7.2 行 599-600，读出即清）；
 * - 响应含 loginToken 则无条件覆盖内存变量（后端每次重签，旧值立即作废）；
 *   status=success 时清空。
 *
 * transport 与 client 只在 shared/api/http.ts 构造（前端架构 §3.1），本模块
 * 从那里拿 ssoClient、不自建 transport；请求状态语义归 ahooks useRequest +
 * shared/hooks/requestOptions（§3.2 定稿口径），本模块是薄封装。
 * 报文类型全部取自 src/gen/proto 生成物。
 */
import type { JsonObject } from '@bufbuild/protobuf';
import { ssoClient } from '../shared/api/http';
import type { MessageInput } from '../shared/api/sso';
import { getInit, type OidcContext } from '../shared/types/init';
import type { LoginFlowResponse } from '../gen/proto/api/sso/v1/envelope_pb';
import type { LoginDefaultRequest } from '../gen/proto/api/sso/v1/login_pb';
import type { RegisterRequest } from '../gen/proto/api/sso/v1/register_pb';
import type { ResetPasswordRequest } from '../gen/proto/api/sso/v1/reset_pb';
import type { LoginOauthRequest } from '../gen/proto/api/sso/v1/oauth_pb';
import { clearLoginToken, getLoginToken, setLoginToken } from './loginTokenStore';
import { loadOidcContext } from './oidcContext';

// ---------------------------------------------------------------------------
// 入参类型（从生成物派生，不重复描述报文结构）
// ---------------------------------------------------------------------------

/**
 * 生成物消息 → init 形状的入参工具类型（MessageInput / MessageField）唯一定义
 * 在 shared/api/sso.ts（本模块原有同构手写已删除），此处引用；
 * authorize / createQrcode 的入参形状随函数一并归口 shared 侧。
 */

/** 登录流程请求入参：再剔除托管字段 loginToken / oidc（由本模块统一注入）。 */
type FlowInput<T extends { loginToken: string }> = Omit<
  MessageInput<T>,
  'loginToken' | 'oidc'
>;

// ---------------------------------------------------------------------------
// loginToken / oidc 注入与信封响应后处理（§1.8 / §1.3 行 145）
// ---------------------------------------------------------------------------

/** OidcContext → google.protobuf.Struct 的 JSON 形状（原样透传，前端不解析，§2.2 行 425）。 */
function oidcToStruct(ctx: OidcContext): JsonObject {
  const out: JsonObject = {};
  for (const [key, value] of Object.entries(ctx)) {
    if (typeof value === 'string') {
      out[key] = value;
    }
  }
  return out;
}

/** 注入快照 oidc（__AUTHLOFT_INIT__.oidc，接口文档 §8）；缺省 undefined。 */
function snapshotOidc(): JsonObject | undefined {
  const ctx = getInit()?.oidc;
  return ctx === undefined ? undefined : oidcToStruct(ctx);
}

/** 跳转前落盘的 oidc（al_oidc_ctx，§2.7.2 行 599-600）；无值 undefined（读出即清）。 */
function storedOidc(): JsonObject | undefined {
  const ctx = loadOidcContext();
  return ctx === undefined ? undefined : oidcToStruct(ctx);
}

/**
 * 登录流程请求的托管字段：loginToken 恒注入（§1.8 常规传递：请求体顶层）；
 * oidc 仅首次请求（尚无 login_token）时回传（§2.2 行 425），源由调用方给定
 * （惰性求值：已有 token 时不读源）。
 */
function flowTokenFields(
  oidcSource: () => JsonObject | undefined,
): { loginToken: string; oidc?: JsonObject } {
  const loginToken = getLoginToken();
  if (loginToken !== '') {
    return { loginToken };
  }
  const oidc = oidcSource();
  return oidc === undefined ? { loginToken } : { loginToken, oidc };
}

/** 信封响应后处理（§1.3 行 145）：含 loginToken 无条件覆盖；status=success 清空。 */
function applyEnvelope(response: LoginFlowResponse): LoginFlowResponse {
  if (response.loginToken !== '') {
    setLoginToken(response.loginToken);
  }
  if (response.status === 'success') {
    clearLoginToken();
  }
  return response;
}

// ---------------------------------------------------------------------------
// 登录流程方法（响应共用 LoginFlowResponse，§1.3 行 104）
// ---------------------------------------------------------------------------

/** LoginDefault 入参（§2.2 字段表；loginToken / oidc 由本模块托管，不对外）。 */
export type LoginDefaultInput = FlowInput<LoginDefaultRequest>;

/** SsoService/LoginDefault（§2.2 行 414）：统一提交端点，flow=login，除 thirdparty 外。 */
export async function loginDefault(
  req: LoginDefaultInput,
): Promise<LoginFlowResponse> {
  return applyEnvelope(
    await ssoClient.loginDefault({ ...req, ...flowTokenFields(snapshotOidc) }),
  );
}

/** Register 入参（§2.3；loginToken / oidc 托管）。 */
export type RegisterInput = FlowInput<RegisterRequest>;

/** SsoService/Register（§2.3 行 440）：注册，flow=register。 */
export async function register(
  req: RegisterInput,
): Promise<LoginFlowResponse> {
  return applyEnvelope(
    await ssoClient.register({ ...req, ...flowTokenFields(snapshotOidc) }),
  );
}

/** ResetPassword 入参（§2.4；loginToken / oidc 托管）。 */
export type ResetPasswordInput = FlowInput<ResetPasswordRequest>;

/** SsoService/ResetPassword（§2.4 行 458）：重置密码，flow=reset。 */
export async function resetPassword(
  req: ResetPasswordInput,
): Promise<LoginFlowResponse> {
  return applyEnvelope(
    await ssoClient.resetPassword({ ...req, ...flowTokenFields(snapshotOidc) }),
  );
}

/** LoginOauth 入参（§2.7.4 字段表；loginToken / oidc 托管）。 */
export type LoginOauthInput = FlowInput<LoginOauthRequest>;

/** SsoService/LoginOauth（§2.7.4 行 616）：三方登录统一入口（跳转回调与小程序提交合并）。 */
export async function loginOauth(
  req: LoginOauthInput,
): Promise<LoginFlowResponse> {
  return applyEnvelope(
    await ssoClient.loginOauth({ ...req, ...flowTokenFields(storedOidc) }),
  );
}

// ---------------------------------------------------------------------------
// 其余方法（响应非信封，无 loginToken 注入 / 后处理）
// ---------------------------------------------------------------------------

/**
 * SsoService/Authorize（§2.7.2 行 580，取第三方授权 URL，跳转由调用方
 * location.replace）与 SsoService/CreateQrcode（§2.8 行 688，拉取小程序码，
 * captcha 必带、登录与绑定共用靠 scene 区分）已归口 shared/api/sso.ts
 * （登录与 account 绑定共用）；本模块 re-export 承载 login 域
 * 既有 ../api import 路径，消费方零改动。
 */
export { authorize, createQrcode } from '../shared/api/sso';

/**
 * SsoService/GetLoginTicket（§2.8 行 710）：查询 / 长轮询 / 完成登录；pollSeconds
 * 上限 15（§2.8 行 714，由调用方遵守）。
 *
 * 扫码轮询双层信封（§2.8 行 739/743）：外层是票据状态应答（status /
 * ticket / login），**内层 `login` 才是 §1.3 登录流程信封**（命中时后端
 * pollResult 必填）——loginToken 的覆盖 / 清空以内层为准：binding_required 时
 * 内层携带 tp 载荷 login_token（免密建号续接依赖），外层 success（票据终态）
 * 不得误清；外层 success 而内层缺失（防御，不会发生）时兜底清空。
 */
export async function getLoginTicket(
  ticket: string,
  pollSeconds?: number,
): Promise<LoginFlowResponse> {
  const response = await ssoClient.getLoginTicket({
    ticket,
    poll: BigInt(pollSeconds ?? 0),
  });
  if (response.login !== undefined) {
    applyEnvelope(response.login);
  } else if (response.status === 'success') {
    clearLoginToken();
  }
  return response;
}

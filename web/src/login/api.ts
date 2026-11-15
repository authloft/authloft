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
 *
 * captcha 提交位置（接口文档 §2.2 / §2.5）：作为**请求顶层 `captcha`**（与
 * `payload` 平级）随入参透传，`payload` 不再承载 captcha；captcha 失败统一走
 * 非 200 `ErrorInfo.code`（captcha_required / captcha_invalid），由 transport
 * 归一为 ApiError 后交 shared/captcha 的 gate 吸收，本模块不解析错误体。
 */
import type { JsonObject } from '@bufbuild/protobuf';
import { create } from '@bufbuild/protobuf';
import { ssoClient } from '../shared/api/http';
import type { MessageInput } from '../shared/api/sso';
import { getInit, type OidcContext } from '../shared/types/init';
import {
  LoginFlowResponseSchema,
  SsoErrorSchema,
  type LoginFlowResponse,
} from '../gen/proto/api/sso/v1/envelope_pb';
import {
  CaptchaPayloadSchema,
  type CaptchaPayload,
  type LoginDefaultRequest,
} from '../gen/proto/api/sso/v1/login_pb';
import type { RegisterRequest } from '../gen/proto/api/sso/v1/register_pb';
import type { ResetPasswordRequest } from '../gen/proto/api/sso/v1/reset_pb';
import type { LoginOauthRequest } from '../gen/proto/api/sso/v1/oauth_pb';
import {
  StartVerificationRequestSchema,
  SubmitVerificationRequestSchema,
  type StartVerificationRequest,
  type StartVerificationResponse,
  type SubmitVerificationRequest,
  type SubmitVerificationResponse,
} from '../gen/proto/api/common/v1/verification_pb';
import {
  clearLoginToken,
  getLoginToken,
  setLoginToken,
} from './loginTokenStore';
import { loadOidcContext } from './oidcContext';

// ---------------------------------------------------------------------------
// 入参类型（从生成物派生，不重复描述报文结构）
// ---------------------------------------------------------------------------

/**
 * 生成物消息 → init 形状的入参工具类型（MessageInput / MessageField）唯一定义
 * 在 shared/api/sso.ts（本模块原有同构手写已删除），此处引用；
 * authorize / createQrcode 的入参形状随函数一并归口 shared 侧。
 */

/** 登录流程请求入参：再剔除托管字段 loginToken / oidc（由本模块统一注入）；captcha 保持请求顶层（§2.2 / §2.5）。 */
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
function flowTokenFields(oidcSource: () => JsonObject | undefined): {
  loginToken: string;
  oidc?: JsonObject;
} {
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
export async function register(req: RegisterInput): Promise<LoginFlowResponse> {
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
  const oidc = snapshotOidc();
  const response = await ssoClient.getLoginTicket({
    ticket,
    poll: BigInt(pollSeconds ?? 0),
    ...(oidc !== undefined ? { oidc } : {}),
  });
  if (response.login !== undefined) {
    applyEnvelope(response.login);
  } else if (response.status === 'success') {
    clearLoginToken();
  }
  return response;
}

// ---------------------------------------------------------------------------
// 登录主路径 MFA 与扫码 step-up 共用（status=mfa_required / needs_step_up，
// 接口文档 §1.6 / §2.8 / §3.8、前端架构 §4.1）：以 loginToken 调
// StartVerification（biz_purpose=login、operation=mfa_verify）取因子能力视图。
// 首次不带 method 取 methods[]，选定因子后带 method 取 challengeToken（§4.1 行 492）。
// ---------------------------------------------------------------------------

/** StartVerification 入参：method 空 / 缺省 = 只取 methods[]；非空 = 取 challengeToken。 */
export interface LoginVerificationInput {
  /** 空 / 缺省 = 只取 methods[] 由前端选择；非空 = 选定本次下发的因子。 */
  method?: string;
  /** 请求级人机校验凭据（§2.5 / §3.8.5）。 */
  captcha?: CaptchaPayload;
}

/** 登录二次验证的 StartVerification：loginToken 主体凭证 + 两段式 method（§3.8.2）。 */
export function startLoginVerification(
  input: LoginVerificationInput = {},
): Promise<StartVerificationResponse> {
  const request = create(StartVerificationRequestSchema, {
    bizPurpose: 'login',
    operation: 'mfa_verify',
    loginToken: getLoginToken(),
    ...(input.method !== undefined && input.method !== ''
      ? { method: input.method }
      : {}),
    ...(input.captcha !== undefined
      ? { captcha: captchaToStruct(input.captcha) }
      : {}),
  });
  return ssoClient.startVerification(request);
}

// ---------------------------------------------------------------------------
// 扫码 step-up（SsoService/SubmitVerification，接口文档 §2.8 / §3.8）
//
// 扫码登录命中 MFA 时轮询返回 needs_step_up 并下发 loginToken；PC 端把该 token
// 存入 loginTokenStore 后复用登录主路径的 startLoginVerification / submitStepUp。
// SubmitVerification 响应即 §2.8 / §3.8.1 的登录流程结论，票据不写终态、不依赖下次轮询。
// ---------------------------------------------------------------------------

/**
 * CaptchaPayload → google.protobuf.Struct 的 JSON 形状（StartVerificationRequest.captcha
 * 为 Struct，§12.9）：只承载凭据字段（providerKey / id / answer / token），
 * 不把消息自带的类型标识与零值字段写进 Struct（标准 protojson 省略零值）。
 */
export function captchaToStruct(captcha: CaptchaPayload): JsonObject {
  const out: JsonObject = {};
  if (captcha.providerKey !== '') {
    out.providerKey = captcha.providerKey;
  }
  if (captcha.id !== '') {
    out.id = captcha.id;
  }
  if (captcha.answer !== '') {
    out.answer = captcha.answer;
  }
  if (captcha.token !== '') {
    out.token = captcha.token;
  }
  return out;
}

/**
 * SsoService/SubmitVerification（登录二次验证）：带 loginToken 恢复登录流程上下文
 * （§3.8.1 / §3.8.5）。响应即登录流程结论（§2.8 / §3.8.1）：success 即完成登录，
 * 内存 loginToken 不再保留；失败态保留以便原地重试。
 */
export async function submitStepUp(
  challengeToken: string,
  method: string,
  payload: JsonObject,
): Promise<SubmitVerificationResponse> {
  const request = create(SubmitVerificationRequestSchema, {
    challengeToken,
    method,
    payload,
    loginToken: getLoginToken(),
  });
  const response = await ssoClient.submitVerification(request);
  if (response.status === 'success') {
    clearLoginToken();
  }
  return response;
}

// ---------------------------------------------------------------------------
// 登录主路径 MFA 提交（status=mfa_required 之后的 challenge / verify 段，
// 接口文档 §3.8 / 前端架构 §4.1 行 492/498）
// ---------------------------------------------------------------------------

/**
 * LoginPayload init → `SubmitVerificationRequest.payload` 的 Struct JSON
 * （§2.6 / §12.9）：只拷非空字段，标准 protojson 省略零值（§1.1）；captcha 是
 * 请求级字段、不进因子 payload（§2.6 行 675）。
 */
function loginPayloadToStruct(
  payload: LoginDefaultInput['payload'],
): JsonObject {
  const out: JsonObject = {};
  if (payload === undefined) {
    return out;
  }
  for (const [name, raw] of Object.entries(payload)) {
    const value: unknown = raw;
    if (typeof value === 'string' && value !== '') {
      out[name] = value;
    } else if (value !== null && typeof value === 'object') {
      out[name] = value as JsonObject;
    }
  }
  return out;
}

/**
 * `SubmitVerificationResponse` → 登录流程信封（§3.8.1 / §3.8.2「响应即登录
 * 流程结论」、前端架构 §4.1 行 498 交回同一状态机终点处理）：结论只取
 * `status` / `redirectTo` / `syncCookieUrl`；`invalid_code` 的剩余次数由响应
 * `attemptsLeft` 落到信封 `error.attemptsLeft`（§1.6 / §2.6 行 679），
 * 零值或缺失即不展示（§1.1）。
 */
function stepUpToEnvelope(
  response: SubmitVerificationResponse,
): LoginFlowResponse {
  const { attemptsLeft } = response;
  const error =
    attemptsLeft !== undefined && attemptsLeft > BigInt(0)
      ? create(SsoErrorSchema, { attemptsLeft })
      : undefined;
  return create(LoginFlowResponseSchema, {
    status: response.status,
    redirectTo: response.redirectTo,
    syncCookieUrl: response.syncCookieUrl,
    ...(error !== undefined ? { error } : {}),
  });
}

/**
 * 登录主路径二次因子提交（SsoService/SubmitVerification，接口文档 §3.8、
 * 前端架构 §4.1 行 492/498）：保持 StartVerification 两段式——先带 `method`
 * （及请求级 `captcha`，§2.5 / §3.8.5）取 `challengeToken`，再以
 * `submitStepUp` 携带 `loginToken` 提交因子载荷；响应转信封交回状态机。
 * `status=success` 清空内存 `loginToken`（§1.3 五条之 3）——扫码 step-up 由
 * `submitStepUp` 自身在 success 时清空。
 */
export async function submitLoginFactor(
  input: LoginDefaultInput,
): Promise<LoginFlowResponse> {
  // method 经 MessageInput 全字段 optional（§9 第 18 条零值兜底）；提交恒带
  // state.method，空串仅作类型兜底、不改变两段式取挑战的语义。
  const method = input.method ?? '';
  const challenge = await startLoginVerification({
    method,
    ...(input.captcha !== undefined
      ? { captcha: create(CaptchaPayloadSchema, input.captcha) }
      : {}),
  });
  const response = await submitStepUp(
    challenge.challengeToken,
    method,
    loginPayloadToStruct(input.payload),
  );
  if (response.status === 'success') {
    clearLoginToken();
  }
  return stepUpToEnvelope(response);
}

export type {
  StartVerificationRequest,
  StartVerificationResponse,
  SubmitVerificationRequest,
  SubmitVerificationResponse,
};

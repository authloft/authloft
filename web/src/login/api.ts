/**
 * SsoService client 方法封装（docs/前端架构.md §4.1 行 377；docs/接口文档.md §2）：
 * LoginDefault（§2.2）、Register（§2.3）、ResetPassword（§2.4）、Authorize（§2.7.2）、
 * LoginOauth（§2.7.4）、CreateQrcode（§2.8）、GetLoginTicket（§2.8 轮询）。
 * ConfirmLoginTicket 由宿主 / 第三方客户端调用，本工程不实现（接口文档 §2.8 行
 * 749）；CreateCaptchaImage 已归口 shared/api/sso.ts（跨 entry 共用，
 * 本实现删除本模块同名函数）；Authorize / CreateQrcode 报文归口该模块
 * （登录与 account 绑定共用），本模块保留 login 域包装注入 ssoClientId，
 * 消费方 ../api import 路径不变。
 *
 * login_token 传递（接口文档 §1.8 / §1.3 行 145 唯一定义；前端架构 §4.1
 * 行 397-403 五条不可打折）：
 * - 请求体顶层自动注入 loginToken（loginTokenStore 内存变量，收到就替换、请求就带上）；
 * - 首次请求（尚无 login_token）额外带上 oidc——LoginDefault / Register /
 *   ResetPassword 取注入快照 __AUTHLOFT_INIT__.oidc（§2.2 行 425）；LoginOauth
 *   取跳转前落盘的 al_oidc_ctx（§2.7.2 行 599-600，读出即清）；
 * - SSO 应用上下文（接口文档 §2.1 / 前端架构 §1.5 首签回传条目）：首签请求
 *   （尚无 login_token）随顶层 ssoClientId 回传 __AUTHLOFT_INIT__.sso.clientId
 *   （§2.2 / §2.3；reset 不带——不建会话、无应用回跳语义）；Authorize /
 *   CreateQrcode 按 scene 分派携带（login 携带、bind 不带，§2.7.2 / §2.8）。
 *   上下文只存注入快照（页面内存），不新增 localStorage 键；续步请求不带
 *   （服务端按首签口径装载快照后随 login_token 保留，§2.2 首签口径）；
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
import { accountClient, ssoClient } from '../shared/api/http';
import type { MessageInput } from '../shared/api/sso';
import { DEFAULT_ACCOUNT_HOME } from '../shared/urls';
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
import type {
  AuthorizeRequest,
  AuthorizeResponse,
  LoginOauthRequest,
} from '../gen/proto/api/sso/v1/oauth_pb';
import type {
  CreateQrcodeRequest,
  CreateQrcodeResponse,
} from '../gen/proto/api/sso/v1/ticket_pb';
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
import {
  clearOidcContext,
  getOidcSelectedScope,
  loadOidcContext,
} from './oidcContext';
import {
  ConsentApproveRequestSchema,
  ConsentDenyRequestSchema,
  type ConsentApproveRequest,
  type ConsentDenyRequest,
  type ConsentResponse,
} from '../gen/proto/api/account/v1/consent_pb';

// ---------------------------------------------------------------------------
// 入参类型（从生成物派生，不重复描述报文结构）
// ---------------------------------------------------------------------------

/**
 * 生成物消息 → init 形状的入参工具类型（MessageInput / MessageField）唯一定义
 * 在 shared/api/sso.ts（本模块原有同构手写已删除），此处引用。
 */

/**
 * 登录流程请求入参：再剔除托管字段 loginToken / oidc / ssoClientId（由本模块
 * 统一注入）；captcha 保持请求顶层（§2.2 / §2.5）。
 */
type FlowInput<T extends { loginToken: string }> = Omit<
  MessageInput<T>,
  'loginToken' | 'oidc' | 'ssoClientId'
>;

// ---------------------------------------------------------------------------
// loginToken / oidc / ssoClientId 注入与信封响应后处理（§1.8 / §1.3 行 145）
// ---------------------------------------------------------------------------

/** 回传 Struct 的七个授权参数白名单（§4.2）：mode / client_name / account 是注入的展示与分派字段，不是授权参数，绝不回传（防前端扩权）。 */
const OIDC_FORWARD_KEYS = [
  'client_id',
  'redirect_uri',
  'scope',
  'state',
  'nonce',
  'code_challenge',
  'code_challenge_method',
] as const;

/** OidcContext → google.protobuf.Struct 的 JSON 形状（仅七授权参数原样透传，前端不解析，§2.2 行 425）。 */
function oidcToStruct(ctx: OidcContext): JsonObject {
  const out: JsonObject = {};
  for (const key of OIDC_FORWARD_KEYS) {
    const value = ctx[key];
    if (typeof value === 'string') {
      out[key] = value;
    }
  }
  return out;
}

/**
 * 注入快照 oidc（__AUTHLOFT_INIT__.oidc，接口文档 §8）；缺省 undefined。
 * scopeOverride 为形态 A 勾选收敛后的 scope 子集（空格分隔），仅覆盖回传 Struct 的
 * scope，其余六参数原样；未显式给定时回退勾选收敛点（§4.2：注册 / 扫码等
 * 非主因子首签路径同样以勾选子集承载，LoginPage 经 setOidcSelectedScope
 * 同步）——两处皆空 → 注入原值。服务端以注册 scopes 为上限权威重校（§4.2）。
 */
function snapshotOidc(scopeOverride?: string): JsonObject | undefined {
  const ctx = getInit()?.oidc;
  if (ctx === undefined) {
    return undefined;
  }
  const out = oidcToStruct(ctx);
  const narrowed = scopeOverride ?? getOidcSelectedScope();
  if (narrowed !== '') {
    out.scope = narrowed;
  }
  return out;
}

/**
 * 注入快照的 SSO 应用标识（__AUTHLOFT_INIT__.sso.clientId，接口文档 §2.1）；
 * 未注入 / 空串 → undefined（直登场景自然不带，行为与现状一致）。
 * 上下文只存页面内存（注入快照），不落盘。
 */
function snapshotSsoClientId(): string | undefined {
  const clientId = getInit()?.sso?.clientId;
  return clientId === undefined || clientId === '' ? undefined : clientId;
}

/** 跳转前落盘的 oidc（al_oidc_ctx，§2.7.2 行 599-600）；无值 undefined（读出即清）。 */
function storedOidc(): JsonObject | undefined {
  const ctx = loadOidcContext();
  return ctx === undefined ? undefined : oidcToStruct(ctx);
}

/**
 * 登录流程请求的托管字段：loginToken 恒注入（§1.8 常规传递：请求体顶层）；
 * oidc 与 ssoClientId 仅首次请求（尚无 login_token）时回传（§2.2），oidc 源
 * 由调用方给定（惰性求值：已有 token 时不读源）；ssoClientId 按 withSso 开关
 * 注入——LoginDefault / Register 首签装载应用快照（§2.2 / §2.3），ResetPassword
 * 不带（不建会话，§2.1 注册首签回传、reset 不带）。
 */
function flowTokenFields(
  oidcSource: () => JsonObject | undefined,
  withSso = false,
): {
  loginToken: string;
  oidc?: JsonObject;
  ssoClientId?: string;
} {
  const loginToken = getLoginToken();
  if (loginToken !== '') {
    return { loginToken };
  }
  const oidc = oidcSource();
  const ssoClientId = withSso ? snapshotSsoClientId() : undefined;
  return {
    loginToken,
    ...(oidc !== undefined ? { oidc } : {}),
    ...(ssoClientId !== undefined ? { ssoClientId } : {}),
  };
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

/**
 * LoginDefault 入参（§2.2 字段表；loginToken / oidc / ssoClientId 由本模块
 * 托管，不对外）。
 */
export type LoginDefaultInput = FlowInput<LoginDefaultRequest>;

/**
 * SsoService/LoginDefault（§2.2 行 414）：统一提交端点，flow=login，除 thirdparty 外。
 * oidcScopeOverride 为形态 A 勾选收敛后的 scope 子集（空格分隔），仅首签回传；
 * 非 OIDC 场景不传，行为与现状一致。
 */
export async function loginDefault(
  req: LoginDefaultInput,
  oidcScopeOverride?: string,
): Promise<LoginFlowResponse> {
  return applyEnvelope(
    await ssoClient.loginDefault({
      ...req,
      ...flowTokenFields(() => snapshotOidc(oidcScopeOverride), true),
    }),
  );
}

/** Register 入参（§2.3；loginToken / oidc / ssoClientId 托管）。 */
export type RegisterInput = FlowInput<RegisterRequest>;

/** SsoService/Register（§2.3 行 440）：注册，flow=register；首签携带 ssoClientId（§2.3）。 */
export async function register(req: RegisterInput): Promise<LoginFlowResponse> {
  return applyEnvelope(
    await ssoClient.register({
      ...req,
      ...flowTokenFields(snapshotOidc, true),
    }),
  );
}

/**
 * ResetPassword 入参（§2.4；loginToken / oidc 托管；不带 ssoClientId——
 * 重置不建会话，应用默认回跳无承载点，§2.1 reset 不回传）。
 */
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
 * scene=bind（绑定流程不读应用配置，接口文档 §2.7.2 / §2.8）
 * → 原样透传；其余（login 缺省 / 显式 login）→ 注入 __AUTHLOFT_INIT__.sso
 * 的 clientId（三方链路应用上下文唯一入口，§2.7.2）。account entry
 * 从 shared/api/sso 直取、不经本包装，bind 请求自然不带。
 */
function withLoginSso<T extends { scene?: string }>(
  req: T,
): T & { ssoClientId?: string } {
  if (req.scene === 'bind') {
    return req;
  }
  const ssoClientId = snapshotSsoClientId();
  return ssoClientId === undefined ? req : { ...req, ssoClientId };
}

/**
 * SsoService/Authorize（§2.7.2 行 580，取第三方授权 URL，跳转由调用方
 * location.replace）：报文归口 shared/api/sso.ts（登录与 account 绑定共用），
 * 本模块包装 login 域入口注入 ssoClientId（scene=bind 不带），承载既有
 * ../api import 路径，消费方零改动。
 */
export async function authorize(
  req: MessageInput<AuthorizeRequest>,
): Promise<AuthorizeResponse> {
  return ssoClient.authorize(withLoginSso(req));
}

/**
 * SsoService/CreateQrcode（§2.8 行 688，拉取小程序码，captcha 必带、登录与
 * 绑定共用靠 scene 区分）：报文归口 shared/api/sso.ts，本模块包装 login 域
 * 入口注入 ssoClientId（仅 scene=login 携带，§2.8）。
 */
export async function createQrcode(
  req: MessageInput<CreateQrcodeRequest>,
): Promise<CreateQrcodeResponse> {
  return ssoClient.createQrcode(withLoginSso(req));
}

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

// ---------------------------------------------------------------------------
// OIDC 授权同意（形态 B，§3.10 / 前端架构 §4.4）：两 RPC 走用户会话鉴权的
// accountClient（transport credentials:include，§3.1），落点消息由 §1.3 终点
// 顺序消费；本模块只做请求映射与终点解析（纯函数、node 可测），不直接 replace。
// ---------------------------------------------------------------------------

/** ConsentApprove 请求入参（§3.10 七参数 + 勾选子集，取自注入，不新增字段）。 */
export type ConsentApproveInput = MessageInput<ConsentApproveRequest>;
/** ConsentDeny 请求入参（§3.10 client_id / redirect_uri / state）。 */
export type ConsentDenyInput = MessageInput<ConsentDenyRequest>;

/**
 * 注入 OidcContext → ConsentApprove 请求字段映射（纯函数，node 可测）：
 * 七参数原样取自注入（缺省空串），selectedScope 为右栏上抛的勾选子集。
 */
export function toConsentApproveInput(
  ctx: OidcContext,
  selectedScope: string,
): ConsentApproveInput {
  return {
    clientId: ctx.client_id,
    redirectUri: ctx.redirect_uri,
    scope: ctx.scope ?? '',
    selectedScope,
    state: ctx.state ?? '',
    nonce: ctx.nonce ?? '',
    codeChallenge: ctx.code_challenge ?? '',
    codeChallengeMethod: ctx.code_challenge_method ?? '',
  };
}

/** 注入 OidcContext → ConsentDeny 请求字段映射（纯函数，node 可测）。 */
export function toConsentDenyInput(ctx: OidcContext): ConsentDenyInput {
  return {
    clientId: ctx.client_id,
    redirectUri: ctx.redirect_uri,
    state: ctx.state ?? '',
  };
}

/** AccountService/ConsentApprove（§3.10）：同意授权，响应为落点消息（不 302）。 */
export function consentApprove(
  req: ConsentApproveInput,
): Promise<ConsentResponse> {
  return accountClient.consentApprove(create(ConsentApproveRequestSchema, req));
}

/** AccountService/ConsentDeny（§3.10）：拒绝授权，响应为落点消息（不 302）。 */
export function consentDeny(req: ConsentDenyInput): Promise<ConsentResponse> {
  return accountClient.consentDeny(create(ConsentDenyRequestSchema, req));
}

/**
 * 同意 / 拒绝响应的终点 URL（§1.3 顺序 1→2 的纯解析，node 可测）：
 * syncCookieUrl 非空 → 它（多域名同步首跳）；否则 redirectTo；两者皆空 →
 * 默认落点（防御，服务端约定必填其一）。同意落点复用登录终点顺序，不另造
 * 分支（§1.3 行 171 / 前端架构 §4.4 行 558）。
 */
export function consentTerminalUrl(response: ConsentResponse): string {
  if (response.syncCookieUrl !== '') {
    return response.syncCookieUrl;
  }
  if (response.redirectTo !== '') {
    return response.redirectTo;
  }
  return DEFAULT_ACCOUNT_HOME;
}

/**
 * 同意 / 拒绝成功后的落点副作用（§1.3 顺序 1→2，node 可测）：
 * 先清 al_oidc_ctx（§4.2 注：回调读完即清，不留存），再按 syncCookieUrl →
 * redirectTo 跳转。navigate 由调用方注入（生产传 location.replace），使effect
 * 用例可用记录函数断言目标 URL，不依赖真实浏览器。
 */
export function landConsent(
  response: ConsentResponse,
  navigate: (url: string) => void,
  clear: () => void = clearConsentOidcContext,
): void {
  clear();
  const url = consentTerminalUrl(response);
  if (url !== '') {
    navigate(url);
  }
}

/** 同意成功后清理三方跳转落盘的 OIDC 上下文（§4.2 注：原参数不落 localStorage，仅 al_oidc_ctx 例外）。 */
export function clearConsentOidcContext(): void {
  clearOidcContext();
}

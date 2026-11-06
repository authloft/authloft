/**
 * AccountService client 方法封装（docs/前端架构.md §5 行 479；docs/接口文档.md §3）。
 * 本次交付 GetProfile（§3.2 行 819）与安全中心族：GetConfig /
 * ChangePassword / BindPhone / BindEmail / PresignAvatar / CommitAvatar +
 * proxy 直传（§3.2-§3.4 / §10.8）；追加 MFA + 通行密钥族：GetMfa /
 * SetMfa / BindTotp / GetRecoveryCodes / RegenerateRecoveryCodes /
 * GetWebauthnCredentials / RegisterWebauthn / RenameWebauthnCredential /
 * DeleteWebauthnCredential + 注册编排 registerWebauthnCredential（§3.5-§3.6）。
 * 追加三方绑定族：GetThirdpartyBindings / UnbindThirdparty /
 * GetThirdpartyTicket + 置灰判定 / Union 识别 / 请求构造 / redirect 分派 /
 * ?bind= 参数与扫码 failed 帧文案纯逻辑（§3.7 / §3.7.1）。
 * 追加日志族：GetEvents + buildGetEventsRequest（§3.7 行 1041 本人
 * 登录记录分页；「仅成功记录」由服务端过滤，前端不发筛选参数）。
 * 头像族迁文档位：GetConfig / PresignAvatar / CommitAvatar / proxy
 * 直传四件薄封装迁 shared/api/account.ts（本模块转发保既有调用方零改动），
 * useUpload + 上传编排 / 预校验迁 shared/hooks/useUpload.ts（前端架构 §2
 * 行 174 / §3.2 行 321-322、344）。
 * 追加 UpdateProfile：薄封装 + PATCH 语义请求构造纯函数
 * buildUpdateProfileRequest（编辑表单）/ buildAvatarPersistRequest（头像
 * 持久化接线）+ gender 展示映射 profileGenderText（§3.2 行 837 /
 * §3.1 行 810-814）。ThirdpartyOauth 实调归 OAuthCallbackPage b 分支
 * 联调批落地再封（api.ts 可封装方法但页面不消费桩方法）。
 * 本 entry 另需的 SsoService 方法（Authorize scene=bind / CreateQrcode）
 * 从 shared/api/sso 取，不在此重复定义（§5 行 479）。
 *
 * transport 与 client 只在 shared/api/http.ts 构造（§9 第 16 条），本模块
 * 从那里拿 accountClient、不自建 transport；请求状态语义归
 * shared/hooks/useRequest（§3.2），本模块是薄封装。
 * 报文类型全部取自 src/gen/proto 生成物（§9 第 15 条）。
 *
 * 【纯逻辑落位说明】表单请求构造等可测纯函数落在本模块（而非组件文件）：
 * 组件壳 import Semi 后，任何含其模块图的测试文件都在 rstest 0.12.5 加载期
 * 崩（实测 blocker，见 account.test.tsx 头注），本模块零 Semi 依赖、
 * node 可测（前端架构 §8 行 626 的被测对象在此）。头像上传编排 / 预校验随
 * useUpload 迁文档位 shared/hooks/useUpload.ts（同样零 Semi 依赖、
 * node 可测；被测对象移至彼处，测试直引新落位，本模块不转发）。
 *
 * 401 统一跳登录（§5 行 480）：shared/api/http 的错误归一层只做
 * ConnectError → ApiError（无统一跳转），判定 + 跳转的职责在本 entry：
 * isUnauthenticatedError 供各页面 / 布局层消费，跳转目标 loginUrl
 * 见 ./bootstrap。
 */
import { create, type JsonObject } from '@bufbuild/protobuf';
import {
  startRegistration,
  type PublicKeyCredentialCreationOptionsJSON,
  type RegistrationResponseJSON,
} from '@simplewebauthn/browser';
import type {
  MfaPolicyMethod,
  OkResponse,
  ProfileResponse,
  UpdateProfileRequest,
} from '../gen/proto/api/account/v1/profile_pb';
import {
  UpdateProfileRequestSchema,
  UserProfileSchema,
} from '../gen/proto/api/account/v1/profile_pb';
import type {
  BindEmailRequest,
  BindPhoneRequest,
  ChangePasswordRequest,
} from '../gen/proto/api/account/v1/security_pb';
import {
  BindEmailRequestSchema,
  BindPhoneRequestSchema,
  ChangePasswordRequestSchema,
} from '../gen/proto/api/account/v1/security_pb';
import type {
  BindTotpRequest,
  BindTotpResponse,
  MfaFactor,
  MfaResponse,
  RecoveryCodesResponse,
  RegenerateRecoveryCodesRequest,
  SetMfaRequest,
} from '../gen/proto/api/account/v1/mfa_pb';
import {
  BindTotpRequestSchema,
  RegenerateRecoveryCodesRequestSchema,
  SetMfaRequestSchema,
} from '../gen/proto/api/account/v1/mfa_pb';
import type {
  DeleteWebauthnCredentialRequest,
  RegisterWebauthnRequest,
  RegisterWebauthnResponse,
  RenameWebauthnCredentialRequest,
  WebauthnListResponse,
} from '../gen/proto/api/account/v1/webauthn_pb';
import {
  DeleteWebauthnCredentialRequestSchema,
  RegisterWebauthnRequestSchema,
  RenameWebauthnCredentialRequestSchema,
} from '../gen/proto/api/account/v1/webauthn_pb';
import type {
  GetEventsRequest,
  GetEventsResponse,
  GetThirdpartyTicketRequest,
  ThirdpartyBindingsResponse,
  UnbindThirdpartyRequest,
} from '../gen/proto/api/account/v1/thirdparty_pb';
import {
  GetEventsRequestSchema,
  GetThirdpartyTicketRequestSchema,
  UnbindThirdpartyRequestSchema,
} from '../gen/proto/api/account/v1/thirdparty_pb';
import type { LoginFlowResponse } from '../gen/proto/api/sso/v1/envelope_pb';
import type { CreateQrcodeRequest } from '../gen/proto/api/sso/v1/ticket_pb';
import { CreateQrcodeRequestSchema } from '../gen/proto/api/sso/v1/ticket_pb';
import type { CaptchaPayload } from '../gen/proto/api/sso/v1/login_pb';
import { DEFAULT_CODE_LENGTH } from '../shared/components/CodeInput';
import { MAX_POLL_SECONDS, type QRPanelPhase } from '../shared/components/QRCodePanel';
import { ApiError, resolveCode } from '../shared/api/errors';
import { accountClient } from '../shared/api/http';
import { authorize } from '../shared/api/sso';
import type { TableQueryState } from '../shared/app-ui/dataTableLogic';
import { t } from '../shared/i18n';
import { toCount } from '../shared/utils/int';
import {
  isValidEmail,
  isValidPhone,
  validatePassword,
  type PasswordWeakReason,
} from '../shared/utils/validate';

/** 用户资料（§3.2 行 836；§3.1 统一用户信息结构，无入参）。 */
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

// ---------------------------------------------------------------------------
// 安全中心族封装（§3.2-§3.4 / §10.8）
// ---------------------------------------------------------------------------

/**
 * 头像族迁移收编（§3.2 行 831-868）：GetConfig / PresignAvatar / CommitAvatar /
 * proxy 直传 uploadAvatarProxy 四件薄封装已迁文档位 shared/api/account.ts
 * （前端架构 §3.1 行 321 薄封装口径），此处转发保既有调用方（SecurityPage
 * 等）零改动——实现唯一、注释见彼处。proxy / direct 模式差异归
 * shared/hooks/useUpload，不外泄到本层。
 */
export {
  commitAvatar,
  getConfig,
  presignAvatar,
  uploadAvatarProxy,
} from '../shared/api/account';

/** 修改密码（§3.3 行 855-862）：成功空响应（OkResponse）；全会话失效由调用方消化。 */
export function changePassword(request: ChangePasswordRequest): Promise<OkResponse> {
  return accountClient.changePassword(request);
}

/** 手机号绑定 / 换绑（§3.4 行 870-871）：两步同端点，step=challenge｜verify。 */
export function bindPhone(request: BindPhoneRequest): Promise<OkResponse> {
  return accountClient.bindPhone(request);
}

/** 邮箱绑定 / 换绑（§3.4 行 872-873）：两步同端点，step=challenge｜verify。 */
export function bindEmail(request: BindEmailRequest): Promise<OkResponse> {
  return accountClient.bindEmail(request);
}

// ---------------------------------------------------------------------------
// 表单请求构造（纯函数，node 可测；落位说明见文件头）
// ---------------------------------------------------------------------------

/** 改密表单本地校验失败形态（§3.3 行 860 currentPassword 必填 + §5.6 新密码策略）。 */
export type PasswordChangeFieldError =
  | { readonly field: 'currentPassword' }
  | { readonly field: 'newPassword'; readonly reasons: readonly PasswordWeakReason[] };

/**
 * ChangePassword 请求构造（§3.3 行 855-862）：
 * - hasPassword=true：currentPassword 必填（空 → 'currentPassword'）；
 * - hasPassword=false：首设密码场景，currentPassword 置空串——标准 protojson
 *   序列化省略零值字段，wire 上即「省略」（行 860）；
 * - newPassword 过 §5.6 前端预校验（validatePassword；本表单无用户名 / 邮箱
 *   上下文，两项不传入——pwd_disallow_common 与之均归服务端权威）。
 */
export function buildChangePasswordRequest(
  hasPassword: boolean,
  currentPassword: string,
  newPassword: string,
): { ok: true; request: ChangePasswordRequest } | { ok: false; error: PasswordChangeFieldError } {
  if (hasPassword && currentPassword === '') {
    return { ok: false, error: { field: 'currentPassword' } };
  }
  const reasons = validatePassword(newPassword);
  if (reasons.length > 0) {
    return { ok: false, error: { field: 'newPassword', reasons } };
  }
  return {
    ok: true,
    request: create(ChangePasswordRequestSchema, {
      currentPassword: hasPassword ? currentPassword : '',
      newPassword,
    }),
  };
}

/** 绑定目标类型（§3.4：BindPhone / BindEmail 同构两步）。 */
export type ContactBindKind = 'phone' | 'email';

/** challenge 步本地校验失败（§3.4 行 870-873：目标格式 + captcha 必过）。 */
export type ContactBindChallengeError = 'invalid_target' | 'captcha_missing';

/** verify 步验证码格式（§2.1 codeLength 6，与 CodeInput DEFAULT_CODE_LENGTH 同源）。 */
const BIND_CODE_PATTERN = new RegExp(`^\\d{${DEFAULT_CODE_LENGTH}}$`);

/**
 * 绑定 challenge 请求构造（§3.4 行 870-873）：目标做体验性格式预校验
 * （§1.11 后端权威）；challenge 步 captcha 必过（行 880），CaptchaWidget
 * 未就绪（getToken → undefined）→ captcha_missing，不发包。
 */
export function buildBindChallengeRequest(
  kind: ContactBindKind,
  target: string,
  captcha: CaptchaPayload | undefined,
): { ok: true; request: BindPhoneRequest | BindEmailRequest } | { ok: false; error: ContactBindChallengeError } {
  if (!(kind === 'phone' ? isValidPhone(target) : isValidEmail(target))) {
    return { ok: false, error: 'invalid_target' };
  }
  if (captcha === undefined) {
    return { ok: false, error: 'captcha_missing' };
  }
  return kind === 'phone'
    ? {
        ok: true,
        request: create(BindPhoneRequestSchema, {
          step: 'challenge',
          payload: { phone: target, captcha },
        }),
      }
    : {
        ok: true,
        request: create(BindEmailRequestSchema, {
          step: 'challenge',
          payload: { email: target, captcha },
        }),
      };
}

/**
 * 绑定 verify 请求构造（§3.4 行 871/873、行 881-882）：verify 回传与
 * challenge 相同的 target（服务端据此拼键取码并校验码内 uid 归属）。
 */
export function buildBindVerifyRequest(
  kind: ContactBindKind,
  target: string,
  code: string,
): { ok: true; request: BindPhoneRequest | BindEmailRequest } | { ok: false; error: 'invalid_code' } {
  if (!BIND_CODE_PATTERN.test(code)) {
    return { ok: false, error: 'invalid_code' };
  }
  return kind === 'phone'
    ? {
        ok: true,
        request: create(BindPhoneRequestSchema, {
          step: 'verify',
          payload: { phone: target, code },
        }),
      }
    : {
        ok: true,
        request: create(BindEmailRequestSchema, {
          step: 'verify',
          payload: { email: target, code },
        }),
      };
}

// ---------------------------------------------------------------------------
// 错误展示文案（§1.5 行 202：i18n 优先 + 组件级语境覆盖）
// ---------------------------------------------------------------------------

/**
 * 提交错误 → 展示文案：ApiError 经 resolveCode 取 i18nKey（errors.code.<code>，
 * shared/i18n 字典——预校验 / 服务端同一份文案源）；调用方可传语境覆盖
 * （如改密表单把 invalid_credentials 覆写为「当前密码不正确」）；未知异常
 * 兜底走 errors.code.unknown，不透出内部信息（既定口径）。覆盖文案归
 * i18n 收口统一处理。
 */
export function apiErrorText(
  error: unknown,
  overrides: Readonly<Record<string, string>> = {},
): string {
  if (error instanceof ApiError) {
    const override = overrides[error.code];
    if (override !== undefined) {
      return override;
    }
    return t(resolveCode(error).i18nKey);
  }
  return t('errors.code.unknown');
}

// ---------------------------------------------------------------------------
// MFA + 通行密钥族封装（§3.5 / §3.6）
// ---------------------------------------------------------------------------

/** MFA 绑定明细（§3.5 行 903）：factors 与 mfaPolicy.methods 同集合，数组序即渲染序。 */
export function getMfa(): Promise<MfaResponse> {
  return accountClient.getMfa({});
}

/** 勾选启用因子集合（§3.5 行 904）：空数组=关闭（受 mfaPolicy.required 约束）；成功空响应。 */
export function setMfa(request: SetMfaRequest): Promise<OkResponse> {
  return accountClient.setMfa(request);
}

/** TOTP 绑定两步同端点（§3.5 行 905-906），由 step=challenge｜verify 区分。 */
export function bindTotp(request: BindTotpRequest): Promise<BindTotpResponse> {
  return accountClient.bindTotp(request);
}

/** 恢复码一次性展示（§3.5 行 907）。 */
export function getRecoveryCodes(): Promise<RecoveryCodesResponse> {
  return accountClient.getRecoveryCodes({});
}

/** 恢复码重新生成（§3.5 行 908）：全量作废后同格式一次性下发新码。 */
export function regenerateRecoveryCodes(
  request: RegenerateRecoveryCodesRequest,
): Promise<RecoveryCodesResponse> {
  return accountClient.regenerateRecoveryCodes(request);
}

/** 通行密钥列表（§3.6 行 914）。 */
export function getWebauthnCredentials(): Promise<WebauthnListResponse> {
  return accountClient.getWebauthnCredentials({});
}

/** 通行密钥注册两步（§3.6 行 915-916）：challenge 响应 {token, challengeData, expiresIn}。 */
export function registerWebauthn(
  request: RegisterWebauthnRequest,
): Promise<RegisterWebauthnResponse> {
  return accountClient.registerWebauthn(request);
}

/** 通行密钥重命名（§3.6 行 917）：成功空响应。 */
export function renameWebauthnCredential(
  request: RenameWebauthnCredentialRequest,
): Promise<OkResponse> {
  return accountClient.renameWebauthnCredential(request);
}

/** 通行密钥删除（§3.6 行 918）：成功空响应。 */
export function deleteWebauthnCredential(
  request: DeleteWebauthnCredentialRequest,
): Promise<OkResponse> {
  return accountClient.deleteWebauthnCredential(request);
}

// ---------------------------------------------------------------------------
// MFA + 通行密钥纯逻辑（node 可测；落位说明见文件头）
// ---------------------------------------------------------------------------

/** SetMfa 本地拒绝形态（§3.5 行 904 空数组=关闭 × §3.2 行 833 required 不可关闭）。 */
export type SetMfaDenyReason = 'mfa_required_locked';

/**
 * SetMfa 请求构造（§3.5 行 904）：以 GetConfig 摘要 methods 推导下一启用集——
 * 勾选 → 追加到启用集尾（保持其余因子既有顺序）；取消 → 从启用集移除；
 * required=true 且结果为空 → 本地拒绝不发包（策略强制不可关闭，§3.2 行 833；
 * 服务端同口径兜底），其余交给服务端权威。
 */
export function buildSetMfaRequest(
  methods: readonly MfaPolicyMethod[],
  factor: string,
  enable: boolean,
  required: boolean,
): { ok: true; request: SetMfaRequest } | { ok: false; error: SetMfaDenyReason } {
  const enabled = methods.filter((m) => m.enabled).map((m) => m.factor);
  const next = enable
    ? enabled.includes(factor)
      ? enabled
      : [...enabled, factor]
    : enabled.filter((f) => f !== factor);
  if (next.length === 0 && required) {
    return { ok: false, error: 'mfa_required_locked' };
  }
  return { ok: true, request: create(SetMfaRequestSchema, { methods: next }) };
}

/** BindTotp challenge 请求（§3.5 行 905）：{step:challenge}，secret / code 零值省略。 */
export function buildBindTotpChallengeRequest(): BindTotpRequest {
  return create(BindTotpRequestSchema, { step: 'challenge' });
}

/** TOTP 码格式（§1.10 totp 六位动态码；与 ContactBind verify 同 6 位数字口径）。 */
const TOTP_CODE_PATTERN = new RegExp(`^\\d{${DEFAULT_CODE_LENGTH}}$`);

/**
 * BindTotp verify 请求构造（§3.5 行 906）：回传 challenge 下发的 secret 与 TOTP 码。
 */
export function buildBindTotpVerifyRequest(
  secret: string,
  code: string,
): { ok: true; request: BindTotpRequest } | { ok: false; error: 'invalid_code' } {
  if (!TOTP_CODE_PATTERN.test(code)) {
    return { ok: false, error: 'invalid_code' };
  }
  return { ok: true, request: create(BindTotpRequestSchema, { step: 'verify', secret, code }) };
}

/** RegenerateRecoveryCodes 请求（§3.5 行 908）：action 固定 "regenerate"。 */
export function buildRegenerateRecoveryCodesRequest(): RegenerateRecoveryCodesRequest {
  return create(RegenerateRecoveryCodesRequestSchema, { action: 'regenerate' });
}

/** RegisterWebauthn challenge 请求（§3.6 行 915）：resident key 由服务端注入 options。 */
export function buildRegisterWebauthnChallengeRequest(): RegisterWebauthnRequest {
  return create(RegisterWebauthnRequestSchema, { step: 'challenge' });
}

/**
 * RegisterWebauthn verify 请求构造（§3.6 行 916）：token 前端不感知结构仅透传
 * （行 930）；credential 为浏览器断言对象原样提交（§12.9 行 1783 Struct 透传）。
 */
export function buildRegisterWebauthnVerifyRequest(
  token: string,
  credential: JsonObject,
  label: string,
): RegisterWebauthnRequest {
  return create(RegisterWebauthnRequestSchema, {
    step: 'verify',
    token,
    credential,
    label,
  });
}

/** RenameWebauthnCredential 请求（§3.6 行 917）：{id, label}。 */
export function buildRenameWebauthnRequest(
  id: bigint,
  label: string,
): RenameWebauthnCredentialRequest {
  return create(RenameWebauthnCredentialRequestSchema, { id, label });
}

/** DeleteWebauthnCredential 请求（§3.6 行 918）：{id}。 */
export function buildDeleteWebauthnRequest(id: bigint): DeleteWebauthnCredentialRequest {
  return create(DeleteWebauthnCredentialRequestSchema, { id });
}

/** WebAuthn 注册编排依赖（challenge → 浏览器创建 → verify）；测试可注入替身。 */
export interface WebauthnRegisterDeps {
  /** step=challenge：取 {token, challengeData, expiresIn}（§3.6 行 921-928）。 */
  challenge(): Promise<RegisterWebauthnResponse>;
  /** 浏览器创建凭据：challengeData 整体透传（§12.9 方案 A：前端不解析 options）。 */
  createCredential(optionsJSON: JsonObject): Promise<JsonObject>;
  /**
   * step=verify：{token, credential, label}（§3.6 行 916）；rpc 响应类型为
   * RegisterWebauthnResponse（verify 成功为其中零值消息，行 916 空响应口径）。
   */
  verify(request: RegisterWebauthnRequest): Promise<RegisterWebauthnResponse>;
}

/** 注册结果：ok=false 时 cancelled 区分用户取消（NotAllowedError）与失败（§4.3 口径）。 */
export type WebauthnRegisterResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly cancelled: boolean };

/** 缺省凭据创建：@simplewebauthn/browser startRegistration（浏览器原生 UI）。 */
async function defaultCreateCredential(optionsJSON: JsonObject): Promise<JsonObject> {
  const registration: RegistrationResponseJSON = await startRegistration({
    optionsJSON: optionsJSON as unknown as PublicKeyCredentialCreationOptionsJSON,
  });
  // @simplewebauthn 注册对象 → Struct JSON 形状（§12.9 行 1783 credential 透传）。
  return registration as unknown as JsonObject;
}

/** 真实依赖（生产与 msw 集成测试共用）。 */
export const webauthnRegisterDeps: WebauthnRegisterDeps = {
  challenge: () => registerWebauthn(buildRegisterWebauthnChallengeRequest()),
  createCredential: defaultCreateCredential,
  verify: registerWebauthn,
};

/**
 * WebAuthn 注册编排（§3.6 行 915-916 两步 + 浏览器凭据创建）：
 * challenge → startRegistration（challengeData 整体透传，不逐字段消费）→
 * verify（token 仅透传，行 930）。NotAllowedError = 用户取消（浏览器原生 UI
 * 关闭），其余为失败——异常语义收口在此，组件只消费 cancelled 布尔
 * （错误语义独立处理，§4.3 行 453 同 WebAuthnButton）。
 */
export async function registerWebauthnCredential(
  label: string,
  deps: WebauthnRegisterDeps = webauthnRegisterDeps,
): Promise<WebauthnRegisterResult> {
  try {
    const challenge = await deps.challenge();
    const credential = await deps.createCredential(challenge.challengeData ?? {});
    await deps.verify(buildRegisterWebauthnVerifyRequest(challenge.token, credential, label));
    return { ok: true };
  } catch (err) {
    return {
      ok: false,
      cancelled: err instanceof DOMException && err.name === 'NotAllowedError',
    };
  }
}

// ---------------------------------------------------------------------------
// 展示格式化纯函数（node 可测；时间展示统一走本入口，零值 → 占位符）
// ---------------------------------------------------------------------------

/** Unix 秒 → 本地时间 YYYY-MM-DD HH:mm；零值 / 负值 → 占位符（§3.1 零值兜底）。 */
export function formatUnixTime(seconds: bigint): string {
  if (seconds <= BigInt(0)) {
    return '—';
  }
  const d = new Date(Number(seconds) * 1000);
  const pad = (n: number): string => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/**
 * GetMfa 单因子明细文案（§3.5 行 890-895：不同因子只填各自相关字段）：
 * 未绑定 → 占位；totp → 绑定 / 使用时间；otp_sms / otp_email → 掩码目标 +
 * 使用时间；webauthn → 凭据数 + 使用时间；recovery_code → 剩余数。
 * formatTime 参数化以便测试注入固定时区断言。文案经 shared/i18n 域键
 * （account.*）；bigint 计数经 utils/int toCount 转 number（§9.17）。
 */
export function mfaFactorDetail(
  factor: MfaFactor,
  formatTime: (seconds: bigint) => string = formatUnixTime,
): string {
  if (!factor.bound) {
    return t('account.mfaNotBound');
  }
  const lastUsed =
    factor.lastUsedAt > BigInt(0)
      ? t('account.mfaLastUsedAt', { time: formatTime(factor.lastUsedAt) })
      : '';
  switch (factor.factor) {
    case 'totp':
      return t('account.boundAt', { time: formatTime(factor.boundAt) }) + lastUsed;
    case 'otp_sms':
    case 'otp_email':
      return t('account.mfaTarget', { target: factor.target }) + lastUsed;
    case 'webauthn':
      return (
        t('account.mfaCredentialCount', { count: toCount(factor.credentials) }) + lastUsed
      );
    case 'recovery_code':
      return t('account.mfaRemainingCount', { count: toCount(factor.remaining) });
    default:
      return factor.factor;
  }
}

// ---------------------------------------------------------------------------
// 三方绑定族封装（§3.7 / §3.7.1）
// ---------------------------------------------------------------------------

/** 三方绑定双列表（§3.7 行 936）：items=已绑定，available=可绑定（过滤口径行 942）。 */
export function getThirdpartyBindings(): Promise<ThirdpartyBindingsResponse> {
  return accountClient.getThirdpartyBindings({});
}

/**
 * 解绑（§3.7 行 937-938）：{providerKey}；置灰口径见 canUnbindThirdpartyRow，
 * 服务端按「解绑后」同一口径兜底校验（行 945），不满足返回 invalid_request。
 */
export function unbindThirdparty(request: UnbindThirdpartyRequest): Promise<OkResponse> {
  return accountClient.unbindThirdparty(request);
}

/**
 * 扫码绑定长轮询（§3.7.1 B 行 996、行 1011-1017）：{ticket, poll}；响应复用
 * 登录流程信封（§1.3 行 152-154，success 读 .bind）。
 */
export function getThirdpartyTicket(
  request: GetThirdpartyTicketRequest,
): Promise<LoginFlowResponse> {
  return accountClient.getThirdpartyTicket(request);
}

// ---------------------------------------------------------------------------
// 三方绑定纯逻辑（node 可测；落位说明见文件头）
// ---------------------------------------------------------------------------

/**
 * Union 绑定行识别（§3.7 行 945/947 + 后端架构 §2 行 185 / §12.7）：Union
 * Provider 是 provider/union/ 虚拟适配器（category=union）的实例，信封 type
 * = 适配器名（§2.7.1 例证 qq / wechat_mp_scan），wire 级标记即 type='union'。
 * 后端本接口未实装（桩，走 msw mock），实装若改用其他标记仅需改本判别一处。
 */
export function isUnionThirdpartyRow(row: { readonly type: string }): boolean {
  return row.type === 'union';
}

/**
 * 解绑入口置灰判定（§3.7 行 938「解绑后」口径 / 行 945 两个输入）：允许 =
 * hasPassword（解绑后仍持有 password 凭证），或排除自身行后非 Union 绑定数
 * ≥1（解绑后仍绑定至少 1 个非 Union 第三方）；Union 行不能单独解绑，恒 false
 * （行 947）。两者都不满足 → 置灰；服务端仍按同一口径校验兜底。
 */
export function canUnbindThirdpartyRow(
  hasPassword: boolean,
  items: readonly { readonly type: string; readonly providerKey: string }[],
  row: { readonly type: string; readonly providerKey: string },
): boolean {
  if (isUnionThirdpartyRow(row)) {
    return false;
  }
  if (hasPassword) {
    return true;
  }
  const remaining = items.filter(
    (item) => !isUnionThirdpartyRow(item) && item.providerKey !== row.providerKey,
  ).length;
  return remaining >= 1;
}

/**
 * 可绑定条目的绑定入口渲染判定（§3.7 行 943）：redirect / qrcode 渲染入口；
 * api（小程序接口）通道不提供绑定入口（宿主内直接完成登录，无「已登录」
 * 前提）；未知渠道保守不渲染（ProviderButtons 同口径）。
 */
export function hasBindEntry(channel: string): boolean {
  return channel === 'redirect' || channel === 'qrcode';
}

/**
 * available 可绑定条目排序（§3.7 行 936 sortOrder）：后端权威下发（§2.7.1
 * 同构，数组序即结果），前端按 sortOrder 升序兜底；bigint 直接比较不转
 * Number（§1.12），同值保持稳定（Array.sort 稳定语义）。
 */
export function sortThirdpartyOptions<T extends { readonly sortOrder: bigint }>(
  options: readonly T[],
): T[] {
  return [...options].sort((a, b) =>
    a.sortOrder < b.sortOrder ? -1 : a.sortOrder > b.sortOrder ? 1 : 0,
  );
}

/** UnbindThirdparty 请求（§3.7 行 937）：{providerKey}。 */
export function buildUnbindThirdpartyRequest(providerKey: string): UnbindThirdpartyRequest {
  return create(UnbindThirdpartyRequestSchema, { providerKey });
}

/** 扫码绑定轮询 poll 秒数 = §2.8 行 714 上限（与 QRCodePanel.MAX_POLL_SECONDS 同源）。 */
export const THIRD_PARTY_POLL_SECONDS = MAX_POLL_SECONDS;

/** GetThirdpartyTicket 请求（§3.7.1 B 行 1011-1017）：{ticket, poll}。 */
export function buildGetThirdpartyTicketRequest(ticket: string): GetThirdpartyTicketRequest {
  return create(GetThirdpartyTicketRequestSchema, {
    ticket,
    poll: BigInt(THIRD_PARTY_POLL_SECONDS),
  });
}

/**
 * CreateQrcode 绑定场景请求（§3.7.1 B 行 993 / §2.8 行 688-703）：scene 固定
 * bind（需 al_session）；captcha 每次拉码都要新的（行 703），由调用方实时
 * 取 CaptchaWidget 句柄传入。
 */
export function buildCreateQrcodeBindRequest(
  providerKey: string,
  captcha: CaptchaPayload,
): CreateQrcodeRequest {
  return create(CreateQrcodeRequestSchema, { providerKey, scene: 'bind', captcha });
}

/** redirect 绑定分派依赖（测试注入替身；缺省走 shared/api/sso 的 Authorize）。 */
export interface BindRedirectDeps {
  /** 取授权 URL（§2.7.2 行 580-587：{provider, scene:'bind'} → {authorizeUrl}）。 */
  request?: (provider: string) => Promise<string>;
}

/** 缺省取授权 URL：shared/api/sso 的 Authorize 薄封装（§5 行 479 落位）。 */
async function requestBindAuthorizeUrl(providerKey: string): Promise<string> {
  const response = await authorize({ provider: providerKey, scene: 'bind' });
  return response.authorizeUrl;
}

/**
 * redirect 渠道绑定分派（§3.7.1 A 行 956-960 + §2.7.2 行 589）：Authorize
 * {provider, scene:bind} 取 authorizeUrl，由调用方 location.replace 跳转
 * （RPC 非 302，不做 <a href> 直跳）。与 login 端 startRedirect 的差异：
 * **不做 saveOidcContext**——OIDC 上下文（§2.7.2 行 585、600）是 /auth/
 * authorize 注入的登录场景状态，绑定跳转无此上下文，取到 URL 直接跳。
 * 失败 / 空 authorizeUrl → undefined（零值兜底不跳转，§9 第 18 条）。
 */
export async function startBindRedirect(
  providerKey: string,
  deps: BindRedirectDeps = {},
): Promise<string | undefined> {
  const request = deps.request ?? requestBindAuthorizeUrl;
  try {
    const url = await request(providerKey);
    return url === '' ? undefined : url;
  } catch {
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// 绑定结果文案（target_taken 绑定语境）
// ---------------------------------------------------------------------------

/**
 * redirect 回调落地 ?bind= 参数读取（§3.7.1 A 行 969-970：OAuthCallbackPage
 * b 分支完成后 location.replace(/account/security?bind=…) 带回）；
 * 空 / 缺省 → undefined。
 */
export function readBindParam(search: string): string | undefined {
  const value = new URLSearchParams(search).get('bind');
  return value === null || value === '' ? undefined : value;
}

/**
 * ?bind={success|ErrorInfo.code} → 展示文案（§3.7.1 A 行 969-971）：success →
 * 成功提示；target_taken → 绑定语境文案（通用字典 errors.code.target_taken
 * 系联系方式语境）；其余按 §1.6 位置二出文案，未知码走
 * unknown 兜底（§1.6 行 272 不暴露内部信息）。文案经 shared/i18n 域键
 * （account.*）。
 */
export function bindParamMessage(code: string): string {
  if (code === 'success') {
    return t('account.bindSuccess');
  }
  return apiErrorText(
    new ApiError({ httpStatus: 400, code, message: '', requestId: '' }),
    { target_taken: t('account.bindTargetTaken') },
  );
}

/**
 * 扫码绑定 failed 帧文案映射：QRCodePanel 的
 * qrFailureText 按 §1.5 行 202 i18n 优先，target_taken 出通用文案（联系方式
 * 语境）；绑定语境（§3.7.1 B 行 1028）出「该账号已被其他账号绑定」
 * （account.bindTargetTaken 域键）。
 * lastPollStatus = 调用方在 pollUrl 里记录的最近一次轮询信封顶层 status——
 * failed 且 target_taken 时替换文案；其余帧原样返回（四态流转仍归面板控制器，
 * 面板四态流转测试约束不破）。
 */
export function bindPollPhase(
  phase: QRPanelPhase,
  lastPollStatus: string,
): QRPanelPhase {
  if (phase.kind === 'failed' && lastPollStatus === 'target_taken') {
    return { kind: 'failed', message: t('account.bindTargetTaken') };
  }
  return phase;
}

// ---------------------------------------------------------------------------
// 日志族封装（§3.7 行 1041 + §1.7 分页）
// ---------------------------------------------------------------------------

/**
 * 本人登录记录（§3.7 行 1041）：仅成功记录（服务端过滤），分页 §1.7；
 * 后端系桩，测试走 msw、联调待实装解锁。
 */
export function getEvents(request: GetEventsRequest): Promise<GetEventsResponse> {
  return accountClient.getEvents(request);
}

/**
 * GetEvents 请求构造（§3.7 行 1041 入参 + §1.7 行 275-278）：
 * - query 为 DataTable 受控查询状态（shared/app-ui/dataTableLogic 归一产物，
 *   page ≥1 / pageSize ∈ [1,100] 已在归一处夹取），wire 上 int64 字段经
 *   protojson 输出十进制字符串（§1.12）；
 * - 排序仅在 order 非空时下发（sort/order 值域前端限定 §1.7——本人记录页
 *   固定 created_at）；
 * - event 为行 1041 预留的类型过滤参数，本人记录页未消费（缺省省略不发）。
 * 实现注：create 显式传零值会置 proto3 optional 的 presence 位 → wire 上仍
 * 输出空串；故「未激活的段」不进 create 入参（条件展开），保持 §1.0 零值
 * 缺省语义（与 BindTotp challenge「secret/code 零值省略」同口径）。
 */
export function buildGetEventsRequest(
  query: TableQueryState,
  event?: string,
): GetEventsRequest {
  const sorted = query.order !== '' && query.sort !== '';
  return create(GetEventsRequestSchema, {
    page: BigInt(query.page),
    pageSize: BigInt(query.pageSize),
    ...(sorted ? { sort: query.sort, order: query.order } : {}),
    ...(event !== undefined && event !== '' ? { event } : {}),
  });
}

// ---------------------------------------------------------------------------
// UpdateProfile 封装 + 请求构造（§3.2 行 837 / §3.1 行 810-814）
// ---------------------------------------------------------------------------

/**
 * 更新用户资料（§3.2 行 837）：成功空响应（OkResponse）；username / 手机号 /
 * 邮箱不可由此修改（行 837）。后端 account 域桩未实装，前端按接口契约
 * 消费（msw mock 覆盖，不因 mock 放宽契约——契约先行批次口径）。
 */
export function updateProfile(request: UpdateProfileRequest): Promise<OkResponse> {
  return accountClient.updateProfile(request);
}

/**
 * 头像持久化请求（§3.2 行 837 avatarUrl）：头像上传链路（§10.8）终点
 * {url} 单字段提交，avatarUrl 不进资料编辑表单（走上传链路，持久化
 * 随本实现接通）。
 */
export function buildAvatarPersistRequest(url: string): UpdateProfileRequest {
  return create(UpdateProfileRequestSchema, { avatarUrl: url });
}

/** 资料编辑表单草稿：基线为 GetProfile 原值，构造时按 diff 只带变化字段。 */
export interface ProfileEditDraft {
  readonly nickname: string;
  /** 0/1/2（§3.1 行 811 枚举；Select 产出 number，wire int64 → bigint 构造处转换）。 */
  readonly gender: number;
  /** YYYY-MM-DD（§3.1 行 811）或 ''（未设置 / DatePicker 清空）。 */
  readonly birthday: string;
  readonly locale: string;
  readonly timezone: string;
  /**
   * extra JSON 文本（§3.1 行 813「JSON 对象透出」）：undefined = 未编辑
   * （diff 跳过不带 extra）；编辑过则须为合法 JSON 对象——原始值 / 数组 /
   * null 均拒绝；清空内容写 {}（消息字段无法表达 null 清除，契约限制）。
   */
  readonly extraText?: string;
}

/** UpdateProfile 本地校验失败形态（birthday 格式 / extra JSON 对象，§3.1）。 */
export type ProfileEditFieldError = 'invalid_birthday' | 'invalid_extra_json';

/** birthday 严格格式（§3.1 行 811 "1990-01-01"）。 */
const BIRTHDAY_PATTERN = /^\d{4}-\d{2}-\d{2}$/;

/**
 * UpdateProfile 请求构造（§3.2 行 837 PATCH 语义——缺省保留）：以 GetProfile
 * 原值为 diff 基线，「用户编辑过」（草稿 ≠ 原值）的字段才进 create 入参，
 * 未编辑字段不进 create → has 位未建立 → wire 省略 = 服务端不修改。
 * 入参全字段 proto3 optional（§3.2 行 843，2026-11-06 定稿）：编辑为空串的
 * string 字段 / gender=0 显式设值 → has 位建立 → wire 字段出现 = 覆盖
 * （「清空昵称 / 改回保密」可表达），不因 mock 放宽：
 * - birthday 编辑过且非空 → 校验 YYYY-MM-DD + 日历合法（DatePicker 正常
 *   产出恒合法，防异常态）→ invalid_birthday 不发包；
 * - extraText 编辑过 → JSON.parse + 对象校验（§3.1 行 813），失败
 *   invalid_extra_json 不发包；
 * - 全部字段无变化 → 零值 request（wire {}，服务端空操作幂等）。
 */
export function buildUpdateProfileRequest(
  current: ProfileResponse,
  draft: ProfileEditDraft,
): { ok: true; request: UpdateProfileRequest } | { ok: false; error: ProfileEditFieldError } {
  const currentProfile = current.profile;
  const currentGender = currentProfile?.gender ?? BigInt(0);
  const currentBirthday = currentProfile?.birthday ?? '';
  const currentLocale = currentProfile?.locale ?? '';
  const currentTimezone = currentProfile?.timezone ?? '';
  const gender = BigInt(draft.gender);
  const birthdayChanged = draft.birthday !== currentBirthday;
  const localeChanged = draft.locale !== currentLocale;
  const timezoneChanged = draft.timezone !== currentTimezone;
  if (
    birthdayChanged &&
    draft.birthday !== '' &&
    (!BIRTHDAY_PATTERN.test(draft.birthday) ||
      Number.isNaN(new Date(`${draft.birthday}T00:00:00`).getTime()))
  ) {
    return { ok: false, error: 'invalid_birthday' };
  }
  let extra: JsonObject | undefined = undefined;
  if (draft.extraText !== undefined) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(draft.extraText);
    } catch {
      return { ok: false, error: 'invalid_extra_json' };
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      return { ok: false, error: 'invalid_extra_json' };
    }
    extra = parsed as JsonObject;
  }
  const profileChanged =
    gender !== currentGender ||
    birthdayChanged ||
    localeChanged ||
    timezoneChanged ||
    extra !== undefined;
  return {
    ok: true,
    request: create(UpdateProfileRequestSchema, {
      ...(draft.nickname !== current.nickname ? { nickname: draft.nickname } : {}),
      ...(profileChanged
        ? {
            profile: create(UserProfileSchema, {
              ...(gender !== currentGender ? { gender } : {}),
              ...(birthdayChanged ? { birthday: draft.birthday } : {}),
              ...(localeChanged ? { locale: draft.locale } : {}),
              ...(timezoneChanged ? { timezone: draft.timezone } : {}),
              ...(extra !== undefined ? { extra } : {}),
            }),
          }
        : {}),
    }),
  };
}

/**
 * gender 展示映射（§3.1 行 811 枚举 0/1/2）：0 保密 / 1 男 / 2 女（接口文档
 * 未标注语义，按通用惯例裁量）；出域值原样显示数字不粉饰
 * （沿 mfaFactorDetail default 分支同口径）。
 */
export function profileGenderText(gender: bigint): string {
  switch (gender) {
    case BigInt(0):
      return t('account.genderSecret');
    case BigInt(1):
      return t('account.genderMale');
    case BigInt(2):
      return t('account.genderFemale');
    default:
      return gender.toString();
  }
}

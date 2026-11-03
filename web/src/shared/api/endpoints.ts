/**
 * 端点表（docs/前端架构.md §3.1 行 268、§9 行 642）：
 * 每条端点 `{ path, method, req, res, format }`，`format` 是每端点显式声明的常量，
 * 不做运行时探测；改一条即可让该端点走 Protobuf。消息 schema 一律取自
 * `web/src/gen/proto` 生成产物，禁止手写镜像结构（§9 第 15 条）。
 *
 * 入表口径：请求与响应消息均有生成产物的端点才入表；
 * 请求 / 响应产物缺失的端点待后续补齐。
 */

import type { DescMessage } from '@bufbuild/protobuf';
// sso 域 Connect 化：sso 生成物迁 gen/proto/api/sso/v1，信封消息更名
// LoginFlowResponse（接口文档 §1.3 行 104）、请求消息名随方法名（§12.9 行 1747）；
// 本表为编译通过做最小符号随迁，端点表整体 Connect client 化后续再改。
// account 域 Connect 化：account 生成物迁 gen/proto/api/account/v1，
// 请求消息名随方法名（BindTotpRequest 等）、两 step 合并响应 BindTotpResponse /
// RegisterWebauthnResponse、OkResponse 空响应化（§1.0 行 57 成功响应即消息本身）；
// 同样为编译通过做最小符号随迁。
import { LoginFlowResponseSchema } from '../../gen/proto/api/sso/v1/envelope_pb';
import { LoginDefaultRequestSchema } from '../../gen/proto/api/sso/v1/login_pb';
import { RegisterRequestSchema } from '../../gen/proto/api/sso/v1/register_pb';
import { ResetPasswordRequestSchema } from '../../gen/proto/api/sso/v1/reset_pb';
import { LoginOauthRequestSchema } from '../../gen/proto/api/sso/v1/oauth_pb';
import {
  CreateQrcodeRequestSchema,
  CreateQrcodeResponseSchema,
} from '../../gen/proto/api/sso/v1/ticket_pb';
import {
  AvatarResponseSchema,
  CommitAvatarRequestSchema,
  OkResponseSchema,
  PresignAvatarRequestSchema,
  AvatarPresignResponseSchema,
  UpdateProfileRequestSchema,
} from '../../gen/proto/api/account/v1/profile_pb';
import {
  BindEmailRequestSchema,
  BindPhoneRequestSchema,
} from '../../gen/proto/api/account/v1/security_pb';
import {
  BindTotpRequestSchema,
  BindTotpResponseSchema,
} from '../../gen/proto/api/account/v1/mfa_pb';
import {
  RegisterWebauthnRequestSchema,
  RegisterWebauthnResponseSchema,
} from '../../gen/proto/api/account/v1/webauthn_pb';

/** 响应 / 请求编码，见 docs/接口文档.md §1.1.1。 */
export type ApiFormat = 'json' | 'binary';

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

/**
 * 端点描述（自 http.ts 迁入）：`format` 是每端点显式声明的常量，
 * 不做运行时探测（docs/前端架构.md §3.1 行 268）。
 */
export interface Endpoint<
  Req extends DescMessage = DescMessage,
  Res extends DescMessage = DescMessage,
> {
  readonly path: string;
  readonly method: HttpMethod;
  readonly req: Req;
  readonly res: Res;
  readonly format: ApiFormat;
}

// ---------------------------------------------------------------------------
// /api/sso/**
// ---------------------------------------------------------------------------

/** POST /api/sso/login/default —— 统一提交端点，flow=login（docs/接口文档.md §2.2），响应为统一信封（§1.3）。 */
export const ssoLoginDefault: Endpoint<
  typeof LoginDefaultRequestSchema,
  typeof LoginFlowResponseSchema
> = {
  path: '/api/sso/login/default',
  method: 'POST',
  req: LoginDefaultRequestSchema,
  res: LoginFlowResponseSchema,
  format: 'json',
};

/** POST /api/sso/register —— 注册，flow=register（docs/接口文档.md §2.3），响应复用统一信封。 */
export const ssoRegister: Endpoint<
  typeof RegisterRequestSchema,
  typeof LoginFlowResponseSchema
> = {
  path: '/api/sso/register',
  method: 'POST',
  req: RegisterRequestSchema,
  res: LoginFlowResponseSchema,
  format: 'json',
};

/** POST /api/sso/reset-password —— 重置密码，flow=reset（docs/接口文档.md §2.4），响应复用统一信封。 */
export const ssoResetPassword: Endpoint<
  typeof ResetPasswordRequestSchema,
  typeof LoginFlowResponseSchema
> = {
  path: '/api/sso/reset-password',
  method: 'POST',
  req: ResetPasswordRequestSchema,
  res: LoginFlowResponseSchema,
  format: 'json',
};

/**
 * POST /api/sso/login/oauth —— 三方登录统一入口（docs/接口文档.md §2.7.4）。
 * 本工程（浏览器，不带 ticket_id）场景响应为统一信封；带 ticket_id 的小程序写入
 * 与 stage=scanned 应答为 TicketStatus / TicketStatusResponse，由宿主端消费，不入本表。
 */
export const ssoLoginOauth: Endpoint<
  typeof LoginOauthRequestSchema,
  typeof LoginFlowResponseSchema
> = {
  path: '/api/sso/login/oauth',
  method: 'POST',
  req: LoginOauthRequestSchema,
  res: LoginFlowResponseSchema,
  format: 'json',
};

/** POST /api/sso/qrcode —— 拉取小程序码（docs/接口文档.md §2.8），登录与绑定共用，靠 scene 区分。 */
export const ssoQrcode: Endpoint<
  typeof CreateQrcodeRequestSchema,
  typeof CreateQrcodeResponseSchema
> = {
  path: '/api/sso/qrcode',
  method: 'POST',
  req: CreateQrcodeRequestSchema,
  res: CreateQrcodeResponseSchema,
  format: 'json',
};

// ---------------------------------------------------------------------------
// /api/account/**（docs/接口文档.md §3，鉴权 al_session）
// ---------------------------------------------------------------------------

/** POST /api/account/profile —— 修改资料（docs/接口文档.md §3.2 行 820），成功为空响应。 */
export const accountUpdateProfile: Endpoint<
  typeof UpdateProfileRequestSchema,
  typeof OkResponseSchema
> = {
  path: '/api/account/profile',
  method: 'POST',
  req: UpdateProfileRequestSchema,
  res: OkResponseSchema,
  format: 'json',
};

/** POST /api/account/avatar/presign —— direct 模式取预签名（docs/接口文档.md §3.2 行 822、§10.8）。 */
export const accountAvatarPresign: Endpoint<
  typeof PresignAvatarRequestSchema,
  typeof AvatarPresignResponseSchema
> = {
  path: '/api/account/avatar/presign',
  method: 'POST',
  req: PresignAvatarRequestSchema,
  res: AvatarPresignResponseSchema,
  format: 'json',
};

/** POST /api/account/avatar/commit —— direct 模式确认上传（docs/接口文档.md §3.2 行 823），返回 {url}。 */
export const accountAvatarCommit: Endpoint<
  typeof CommitAvatarRequestSchema,
  typeof AvatarResponseSchema
> = {
  path: '/api/account/avatar/commit',
  method: 'POST',
  req: CommitAvatarRequestSchema,
  res: AvatarResponseSchema,
  format: 'json',
};

/** POST /api/account/phone/bind —— 手机号绑定 / 换绑两步（docs/接口文档.md §3.4），由 step 区分，成功为空响应。 */
export const accountPhoneBind: Endpoint<
  typeof BindPhoneRequestSchema,
  typeof OkResponseSchema
> = {
  path: '/api/account/phone/bind',
  method: 'POST',
  req: BindPhoneRequestSchema,
  res: OkResponseSchema,
  format: 'json',
};

/** POST /api/account/email/bind —— 邮箱绑定 / 换绑两步（docs/接口文档.md §3.4），由 step 区分，成功为空响应。 */
export const accountEmailBind: Endpoint<
  typeof BindEmailRequestSchema,
  typeof OkResponseSchema
> = {
  path: '/api/account/email/bind',
  method: 'POST',
  req: BindEmailRequestSchema,
  res: OkResponseSchema,
  format: 'json',
};

/** POST /api/account/mfa/totp（step=challenge）—— 取 TOTP 绑定密钥与二维码内容（docs/接口文档.md §3.5 行 905）。 */
export const accountMfaTotpChallenge: Endpoint<
  typeof BindTotpRequestSchema,
  typeof BindTotpResponseSchema
> = {
  path: '/api/account/mfa/totp',
  method: 'POST',
  req: BindTotpRequestSchema,
  res: BindTotpResponseSchema,
  format: 'json',
};

/** POST /api/account/mfa/totp（step=verify）—— 验证一次后生效并下发恢复码（docs/接口文档.md §3.5 行 906）。 */
export const accountMfaTotpVerify: Endpoint<
  typeof BindTotpRequestSchema,
  typeof BindTotpResponseSchema
> = {
  path: '/api/account/mfa/totp',
  method: 'POST',
  req: BindTotpRequestSchema,
  res: BindTotpResponseSchema,
  format: 'json',
};

/** POST /api/account/webauthn（step=challenge）—— 取注册挑战（docs/接口文档.md §3.6 行 915、920-928），要求 resident key。 */
export const accountWebauthnChallenge: Endpoint<
  typeof RegisterWebauthnRequestSchema,
  typeof RegisterWebauthnResponseSchema
> = {
  path: '/api/account/webauthn',
  method: 'POST',
  req: RegisterWebauthnRequestSchema,
  res: RegisterWebauthnResponseSchema,
  format: 'json',
};

/** 全部端点条目汇总（键为条目名），供遍历与测试使用。 */
export const endpoints = {
  ssoLoginDefault,
  ssoRegister,
  ssoResetPassword,
  ssoLoginOauth,
  ssoQrcode,
  accountUpdateProfile,
  accountAvatarPresign,
  accountAvatarCommit,
  accountPhoneBind,
  accountEmailBind,
  accountMfaTotpChallenge,
  accountMfaTotpVerify,
  accountWebauthnChallenge,
} as const;

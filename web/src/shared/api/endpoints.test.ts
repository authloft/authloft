// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径；
// 不调整 tsconfig，仅在测试文件放宽该 import 的类型解析。
// @ts-ignore
import { describe, expect, test } from 'rstack/test';
// sso 域 Connect 化：sso 生成物迁 gen/proto/api/sso/v1，信封消息更名
// LoginFlowResponse（接口文档 §1.3 行 104）、请求消息名随方法名（§12.9 行 1747）。
// account 域 Connect 化：account 生成物迁 gen/proto/api/account/v1，
// 请求消息名随方法名、两 step 合并响应 BindTotpResponse / RegisterWebauthnResponse，
// 符号随迁同 endpoints.ts（编译救活最小改动，端点表后续再改）。
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
import { endpoints } from './endpoints';

/** 期望表：path 逐条对照 docs/接口文档.md §2 / §3。 */
const EXPECTED_PATHS: Readonly<Record<string, string>> = {
  ssoLoginDefault: '/api/sso/login/default',
  ssoRegister: '/api/sso/register',
  ssoResetPassword: '/api/sso/reset-password',
  ssoLoginOauth: '/api/sso/login/oauth',
  ssoQrcode: '/api/sso/qrcode',
  accountUpdateProfile: '/api/account/profile',
  accountAvatarPresign: '/api/account/avatar/presign',
  accountAvatarCommit: '/api/account/avatar/commit',
  accountPhoneBind: '/api/account/phone/bind',
  accountEmailBind: '/api/account/email/bind',
  accountMfaTotpChallenge: '/api/account/mfa/totp',
  accountMfaTotpVerify: '/api/account/mfa/totp',
  accountWebauthnChallenge: '/api/account/webauthn',
};

const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];

describe('shared/api/endpoints', () => {
  test('端点表条目齐全（13 条，防意外删减）', () => {
    expect(Object.keys(endpoints).sort()).toEqual(
      Object.keys(EXPECTED_PATHS).sort(),
    );
    expect(Object.keys(EXPECTED_PATHS)).toHaveLength(13);
  });

  test('每条 path 与接口文档一致，method / format 为显式常量', () => {
    for (const [name, endpoint] of Object.entries(endpoints)) {
      expect(endpoint.path).toBe(EXPECTED_PATHS[name]);
      expect(endpoint.path.startsWith('/api/')).toBe(true);
      expect(HTTP_METHODS).toContain(endpoint.method);
      expect(['json', 'binary']).toContain(endpoint.format);
    }
  });

  test('req / res 均为生成产物 schema 引用（无手写镜像，§9 第 15 条）', () => {
    expect(endpoints.ssoLoginDefault.req).toBe(LoginDefaultRequestSchema);
    expect(endpoints.ssoLoginDefault.res).toBe(LoginFlowResponseSchema);
    expect(endpoints.ssoRegister.req).toBe(RegisterRequestSchema);
    expect(endpoints.ssoRegister.res).toBe(LoginFlowResponseSchema);
    expect(endpoints.ssoResetPassword.req).toBe(ResetPasswordRequestSchema);
    expect(endpoints.ssoResetPassword.res).toBe(LoginFlowResponseSchema);
    expect(endpoints.ssoLoginOauth.req).toBe(LoginOauthRequestSchema);
    expect(endpoints.ssoLoginOauth.res).toBe(LoginFlowResponseSchema);
    expect(endpoints.ssoQrcode.req).toBe(CreateQrcodeRequestSchema);
    expect(endpoints.ssoQrcode.res).toBe(CreateQrcodeResponseSchema);
    expect(endpoints.accountUpdateProfile.req).toBe(UpdateProfileRequestSchema);
    expect(endpoints.accountUpdateProfile.res).toBe(OkResponseSchema);
    expect(endpoints.accountAvatarPresign.req).toBe(PresignAvatarRequestSchema);
    expect(endpoints.accountAvatarPresign.res).toBe(AvatarPresignResponseSchema);
    expect(endpoints.accountAvatarCommit.req).toBe(CommitAvatarRequestSchema);
    expect(endpoints.accountAvatarCommit.res).toBe(AvatarResponseSchema);
    expect(endpoints.accountPhoneBind.req).toBe(BindPhoneRequestSchema);
    expect(endpoints.accountPhoneBind.res).toBe(OkResponseSchema);
    expect(endpoints.accountEmailBind.req).toBe(BindEmailRequestSchema);
    expect(endpoints.accountEmailBind.res).toBe(OkResponseSchema);
    expect(endpoints.accountMfaTotpChallenge.req).toBe(BindTotpRequestSchema);
    expect(endpoints.accountMfaTotpChallenge.res).toBe(BindTotpResponseSchema);
    expect(endpoints.accountMfaTotpVerify.req).toBe(BindTotpRequestSchema);
    expect(endpoints.accountMfaTotpVerify.res).toBe(BindTotpResponseSchema);
    expect(endpoints.accountWebauthnChallenge.req).toBe(RegisterWebauthnRequestSchema);
    expect(endpoints.accountWebauthnChallenge.res).toBe(RegisterWebauthnResponseSchema);
  });
});

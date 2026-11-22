// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化后移除）。
// @ts-ignore
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  rs,
  test,
  // moduleResolution=node 下 TS2307 定位在收尾行，首行的 @ts-ignore 覆盖不到
  //（tsconfig 现代化后连同两处 @ts-ignore 一起移除）。
  // @ts-ignore
} from 'rstack/test';
import * as React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from '@modern-js/runtime/router';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { create, toJson, type JsonObject } from '@bufbuild/protobuf';
import {
  AccountConfigResponseSchema,
  AvatarUploadConfigSchema,
  CommitAvatarRequestSchema,
  MfaPolicyMethodSchema,
  PresignAvatarRequestSchema,
  ProfileResponseSchema,
  UpdateProfileRequestSchema,
  UploadAvatarRequestSchema,
  UserProfileSchema,
  type AccountConfigResponse,
  type MfaPolicyMethod,
} from '../gen/proto/api/account/v1/profile_pb';
import { MfaFactorSchema } from '../gen/proto/api/account/v1/mfa_pb';
import {
  RegisterWebauthnResponseSchema,
  type RegisterWebauthnRequest,
} from '../gen/proto/api/account/v1/webauthn_pb';
import type {
  BindEmailRequest,
  BindPhoneRequest,
} from '../gen/proto/api/account/v1/security_pb';
import type { UserEventItem } from '../gen/proto/api/account/v1/thirdparty_pb';
import { CaptchaPayloadSchema } from '../gen/proto/api/sso/v1/login_pb';
import { CreateQrcodeRequestSchema } from '../gen/proto/api/sso/v1/ticket_pb';
import {
  GetEventsRequestSchema,
  GetThirdpartyTicketRequestSchema,
  ThirdpartyBindingSchema,
  ThirdpartyOptionSchema,
  UnbindThirdpartyRequestSchema,
  UserEventItemSchema,
} from '../gen/proto/api/account/v1/thirdparty_pb';
import {
  clampPageSize,
  DEFAULT_PAGE_SIZE,
  initialTableQuery,
  MAX_PAGE_SIZE,
  patchRowByKey,
  resolveTableQuery,
  runInlineToggle,
} from '../shared/app-ui/dataTableLogic';
import { LoginFlowResponseSchema } from '../gen/proto/api/sso/v1/envelope_pb';
import { SettingList } from '../shared/components/SettingList';
import { ApiError } from '../shared/api/errors';
import { t } from '../shared/i18n';
import { loginUrl, sanitizeReturnTo } from '../shared/urls';

/**
 * account 底座 + 安全中心测试。覆盖边界（既定口径「覆盖
 * 路由渲染 + api 封装 msw」的当前可运行子集）：
 * - bootstrap：注入变量读取 / 归一 / loginUrl / logoutUrl（§5 行 478 / §8）；
 * - api.getProfile：msw 走真实 transport 归一链（§3.2 行 819）；
 * - isUnauthenticatedError：401 判定纯函数（§5 行 480）；
 * - 安全中心族：GetConfig / ChangePassword / BindPhone / BindEmail /
 *   PresignAvatar / CommitAvatar / UploadAvatar 封装（msw 真实 transport
 *   归一链）、头像两模式编排 uploadAvatarFile（§10.8：direct 三步走 + proxy
 *   UploadAvatar bytes 直传得 url + 超限 / 类型预校验文案与后端一致，
 *   前端架构 §8.2 行 648）、表单请求构造纯函数（buildChangePasswordRequest /
 *   buildBind 系）、apiErrorText。
 *   薄封装经 account/api 转发自 shared/api/account（getConfig
 *   等仍走 apiMod）；上传编排 / 预校验直引新落位 shared/hooks/useUpload
 *   （uploadMod，被测对象移位、断言零改动）。
 * - MFA + 通行密钥族：GetMfa / SetMfa（buildSetMfaRequest：{enabled} 开关）
 *   / deriveMfaToggleView（开关可用性 / 禁用原因 / 无可用因子兜底）/
 *   BindTotp 两步（challenge wire 省略零值 + verify 回传 secret）/
 *   RegenerateRecoveryCodes（action=regenerate）/ GetWebauthnCredentials
 *   解码；registerWebauthnCredential
 *   三步编排（依赖注入：challengeData / credential 引用恒等透传、取消 /
 *   失败语义，§12.9 方案 A）；rename / delete wire；formatUnixTime /
 *   mfaFactorDetail 展示纯函数。
 * - 三方绑定族：GetThirdpartyBindings / UnbindThirdparty /
 *   GetThirdpartyTicket 封装（msw 真实 transport 归一链）+ shared/api/sso 的
 *   Authorize / CreateQrcode 薄封装（scene=bind wire）；置灰判定 / Union 识别
 *   / 入口分流 / 排序 / redirect 分派（不落盘 OIDC）/ CreateQrcode 请求构造 /
 *   ?bind= 参数与扫码 failed 帧文案纯函数（§3.7 / §3.7.1；target_taken 绑定
 *   语境文案「该账号已被其他账号绑定」）。
 * - 日志族 + DataTable 纯逻辑：GetEvents 封装（msw 真实 transport；
 *   后端系桩）+ buildGetEventsRequest 请求构造（§1.7 分页 wire）+
 *   shared/app-ui/dataTableLogic（前端架构 §8 行 621：分页 / 排序 / 筛选
 *   回调参数归一、行内开关的乐观更新与回滚；零 Semi 依赖，组件壳渲染测试
 *   仍受工具链 blocker——见文件头【Blocker】段）。
 * - UpdateProfile 资料编辑 + 头像持久化（§3.2）：
 *   updateProfile 封装 msw（成功 OkResponse 空响应 / 校验失败 400 Connect
 *   错误体归一 ApiError）+ buildUpdateProfileRequest PATCH 语义纯函数（diff
 *   基线 → 只带编辑过字段 / wire 零值省略契约限制 / changed 空改动判定 /
 *   birthday 格式 + 真日历本地校验）+ buildAvatarPersistRequest（头像持久化
 *   接线：AvatarUploader onUploaded 后 {avatarUrl} 单字段提交）+
 *   avatarPersistFailureMessage（持久化失败行内文案分派：401 归集中跳登录）
 *   + profileGenderText 展示映射 + locale / timezone 展示可读文案（与下拉
 *   选项 label 同源）+ 编辑下拉选项集现值兜底（locale 出域 /
 *   timezone 历史别名与出域 / gender 出域 → 补项防下拉空白与保存误清空）；
 *   ProfilePageView 静态渲染（展示帧 override 优先 + 持久化失败文案 +
 *   编辑帧字段绑定 / 下拉触发器渲染 / 错误呈现）。
 *
 * 【Blocker·已解除】routes / AppLayout / ProfilePage / SecurityPage / 表单组件的渲染
 * 测试曾在本工具链下无法落地：@douyinfe/semi-ui 的 lib/es 内部为无扩展名
 * import，node 原生 ESM 无法加载，rstest 0.12.5 对其 externalize（rs.mock /
 * __mocks__ 均为运行时机制，拦不住编译图对 external 包的链接期加载）→ 任何
 * 模块图含 semi import 的测试文件都在加载期崩（实测：rs.mock 全组件 /
 * __mocks__ 目录 / 子路径 import 三路都试过）。**测试链已修复**
 * （rstack.config.mts define.test bundleDependencies + ProvidePlugin，Semi 经
 * rspack 管线加载），路由兜底真渲染断言见文末 routes describe；表单交互的
 * 可测逻辑仍沿原收口落 api.ts（零 Semi 依赖）。
 *
 * msw 请求链沿 login/api.test.ts 模式；al_root 在 transport（http.ts）模块
 * 求值时读 globalThis，故被测模块经 beforeAll 动态 import；单测环境为
 * node，BASE 与既有测试文件取同值防跨文件竞争。account 注入白名单仅
 * al_root / static_base（接口文档 §8：methods 是 login 必填项，account 无）。
 */
const BASE = 'https://uc.test';
(globalThis as { __AUTHLOFT_INIT__?: unknown }).__AUTHLOFT_INIT__ = {
  al_root: `${BASE}/`,
  static_base: '/assets/',
};

const PROFILE_URL = `${BASE}/api.account.v1.AccountService/GetProfile`;
const CONFIG_URL = `${BASE}/api.account.v1.AccountService/GetConfig`;
const CHANGE_PASSWORD_URL = `${BASE}/api.account.v1.AccountService/ChangePassword`;
const BIND_PHONE_URL = `${BASE}/api.account.v1.AccountService/BindPhone`;
const BIND_EMAIL_URL = `${BASE}/api.account.v1.AccountService/BindEmail`;
const PRESIGN_AVATAR_URL = `${BASE}/api.account.v1.AccountService/PresignAvatar`;
const COMMIT_AVATAR_URL = `${BASE}/api.account.v1.AccountService/CommitAvatar`;
const UPLOAD_AVATAR_URL = `${BASE}/api.account.v1.AccountService/UploadAvatar`;
const GET_MFA_URL = `${BASE}/api.account.v1.AccountService/GetMfa`;
const SET_MFA_URL = `${BASE}/api.account.v1.AccountService/SetMfa`;
const BIND_TOTP_URL = `${BASE}/api.account.v1.AccountService/BindTotp`;
const REGEN_RECOVERY_CODES_URL = `${BASE}/api.account.v1.AccountService/RegenerateRecoveryCodes`;
const GET_WEBAUTHN_URL = `${BASE}/api.account.v1.AccountService/GetWebauthnCredentials`;
const RENAME_WEBAUTHN_URL = `${BASE}/api.account.v1.AccountService/RenameWebauthnCredential`;
const DELETE_WEBAUTHN_URL = `${BASE}/api.account.v1.AccountService/DeleteWebauthnCredential`;
const GET_THIRDPARTY_BINDINGS_URL = `${BASE}/api.account.v1.AccountService/GetThirdpartyBindings`;
const UNBIND_THIRDPARTY_URL = `${BASE}/api.account.v1.AccountService/UnbindThirdparty`;
const GET_THIRDPARTY_TICKET_URL = `${BASE}/api.account.v1.AccountService/GetThirdpartyTicket`;
const GET_EVENTS_URL = `${BASE}/api.account.v1.AccountService/GetEvents`;
const UPDATE_PROFILE_URL = `${BASE}/api.account.v1.AccountService/UpdateProfile`;
const SSO_AUTHORIZE_URL = `${BASE}/api.sso.v1.SsoService/Authorize`;
const SSO_CREATE_QRCODE_URL = `${BASE}/api.sso.v1.SsoService/CreateQrcode`;

/** 10 个恢复码样例（§3.5 行 906/907 一次性下发格式 xxxx-xxxx）。 */
const TEN_RECOVERY_CODES = Array.from(
  { length: 10 },
  (_, i) => `a1${i}b-c3d${i}`,
);

const server = setupServer();

/** 捕获 rejection 的返回值（沿 http.test.ts getRejection 模式）。 */
async function captureRejection(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error('expected the promise to reject');
}

let bootstrapMod: typeof import('./bootstrap');
let apiMod: typeof import('./api');
let ssoMod: typeof import('../shared/api/sso');
let sharedAccountMod: typeof import('../shared/api/account');
let uploadMod: typeof import('../shared/hooks/useUpload');
let routesMod: typeof import('./routes');
let mfaSettingMod: typeof import('./pages/SecurityPage/MfaSetting');
let securityPageMod: typeof import('./pages/SecurityPage');
let profilePageMod: typeof import('./pages/ProfilePage');
let eventLogTableMod: typeof import('./components/EventLogTable');

beforeAll(async () => {
  server.listen({ onUnhandledRequest: 'error' });
  bootstrapMod = await import('./bootstrap');
  apiMod = await import('./api');
  ssoMod = await import('../shared/api/sso');
  // uploadAvatar 落位 shared/api/account（account/api.ts 收编层仅按旧名
  // uploadAvatarProxy 转发，新薄封装直引新落位，同 uploadMod 先例）。
  sharedAccountMod = await import('../shared/api/account');
  uploadMod = await import('../shared/hooks/useUpload');
  routesMod = await import('./routes');
  mfaSettingMod = await import('./pages/SecurityPage/MfaSetting');
  securityPageMod = await import('./pages/SecurityPage');
  profilePageMod = await import('./pages/ProfilePage');
  eventLogTableMod = await import('./components/EventLogTable');
});

// rstest 对 .tsx 采用 classic JSX runtime，路由渲染断言经 createElement 显式
// 引用（admin.test.tsx / login/routes.test.tsx 同口径）。
const { createElement } = React;

beforeEach(() => {
  // classic JSX runtime：测试链 JSX 编译产物引用全局 React——渲染断言前 stub
  //（afterEach 的 unstubAllGlobals 移除，每测试重置）。
  rs.stubGlobal('React', React);
  // stub window 供 getInit（shared/types/init.ts）读取注入块 + routes 读 pathname。
  rs.stubGlobal('window', {
    location: { pathname: '/account/profile' },
    __AUTHLOFT_INIT__: (globalThis as { __AUTHLOFT_INIT__?: unknown })
      .__AUTHLOFT_INIT__,
  });
});

afterEach(() => {
  server.resetHandlers();
  rs.unstubAllGlobals();
});

afterAll(() => {
  server.close();
  (globalThis as { __AUTHLOFT_INIT__?: unknown }).__AUTHLOFT_INIT__ = undefined;
});

// ---------------------------------------------------------------------------
// bootstrap（§5 行 478 / §8 白名单 al_root + static_base）
// ---------------------------------------------------------------------------

describe('bootstrap（§5 行 478 / §8）', () => {
  test('normalizeStaticBase：空 / 缺省回落 /assets/，缺尾斜杠补齐', () => {
    expect(bootstrapMod.normalizeStaticBase(undefined)).toBe('/assets/');
    expect(bootstrapMod.normalizeStaticBase('')).toBe('/assets/');
    expect(bootstrapMod.normalizeStaticBase('  ')).toBe('/assets/');
    expect(bootstrapMod.normalizeStaticBase('/cdn-base')).toBe('/cdn-base/');
    expect(bootstrapMod.normalizeStaticBase('/assets/')).toBe('/assets/');
  });

  test('loadAccountBootstrap：注入块完整 → al_root 去尾斜杠 + static_base 归一（无 methods 必需校验）', () => {
    expect(bootstrapMod.loadAccountBootstrap()).toEqual({
      ok: true,
      alRoot: BASE,
      staticBase: '/assets/',
    });
  });

  test('loadAccountBootstrap：注入块未下发 → 缺省归一（§8 行 1428 默认 /assets；node 无 location → 空串）', () => {
    rs.stubGlobal('window', {
      location: { pathname: '/account/profile' },
      __AUTHLOFT_INIT__: undefined,
    });
    expect(bootstrapMod.loadAccountBootstrap()).toEqual({
      ok: true,
      alRoot: '',
      staticBase: '/assets/',
    });
  });

  test('loginUrl / logoutUrl：{al_root} 前缀拼接（§5 行 480 / §8 行 1418/1420）', () => {
    expect(bootstrapMod.loginUrl(BASE)).toBe(`${BASE}/sso/login`);
    expect(bootstrapMod.logoutUrl(BASE)).toBe(`${BASE}/sso/logout`);
  });

  test('loadAccountBootstrap：注入 al_root 空串 / 纯空白 → location.origin 兜底（壳注入空串合规，前端回落同源）', () => {
    const FALLBACK_ORIGIN = 'https://account-fallback.test';
    // normalizeAlRoot 读全局 location（非 window.location）；node 单测环境
    // 经 stubGlobal 模拟浏览器站点源，afterEach 的 unstubAllGlobals 自动恢复。
    rs.stubGlobal('location', { origin: FALLBACK_ORIGIN });
    // beforeEach 已按顶层注入 stub window（BASE 非空），此处覆盖为空串注入。
    rs.stubGlobal('window', {
      location: { pathname: '/account/profile' },
      __AUTHLOFT_INIT__: { al_root: '' },
    });
    expect(bootstrapMod.loadAccountBootstrap()).toEqual({
      ok: true,
      alRoot: FALLBACK_ORIGIN,
      staticBase: '/assets/',
    });
    // 纯空白：trim 后归一为空，仍回落站点源（与 setup/bootstrap.ts 同口径）。
    rs.stubGlobal('window', {
      location: { pathname: '/account/profile' },
      __AUTHLOFT_INIT__: { al_root: '   ' },
    });
    expect(bootstrapMod.loadAccountBootstrap()).toEqual({
      ok: true,
      alRoot: FALLBACK_ORIGIN,
      staticBase: '/assets/',
    });
  });
});

// ---------------------------------------------------------------------------
// api.getProfile（§3.2 行 819）：msw 走真实 transport 归一链
// ---------------------------------------------------------------------------

describe('api.getProfile（§3.2 行 819）', () => {
  test('Connect 协议 POST GetProfile → ProfileResponse 解码（protojson：int64 十进制字符串 → bigint）', async () => {
    let called = false;
    server.use(
      http.post(PROFILE_URL, () => {
        called = true;
        return HttpResponse.json({
          id: '10086',
          username: 'zhang_san',
          nickname: '张三',
          avatarUrl: 'https://cdn.test/a.jpg',
          phone: '138****8000',
          phoneVerified: '1',
          email: 'a***@example.com',
          emailVerified: '1',
          userStatus: '1',
          mfaRequired: '0',
          epoch: '3',
          lastLoginAt: '1761800000',
          createdAt: '1761700000',
          updatedAt: '1761800000',
        });
      }),
    );

    const res = await apiMod.getProfile();

    expect(called).toBe(true);
    expect(res.username).toBe('zhang_san');
    expect(res.nickname).toBe('张三');
    expect(res.id).toBe(BigInt(10086));
    expect(res.avatarUrl).toBe('https://cdn.test/a.jpg');
  });

  test('401 → transport 归一 ApiError → isUnauthenticatedError 为真（§5 行 480 401 判定）', async () => {
    server.use(
      http.post(PROFILE_URL, () => new HttpResponse(null, { status: 401 })),
    );

    let caught: unknown;
    try {
      await apiMod.getProfile();
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(ApiError);
    expect((caught as ApiError).httpStatus).toBe(401);
    expect(apiMod.isUnauthenticatedError(caught)).toBe(true);
  });

  test('非 401 错误不误判（§5 行 480：仅 401 触发跳登录）', async () => {
    server.use(
      http.post(PROFILE_URL, () => new HttpResponse(null, { status: 500 })),
    );

    let caught: unknown;
    try {
      await apiMod.getProfile();
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(ApiError);
    expect(apiMod.isUnauthenticatedError(caught)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// isUnauthenticatedError（§5 行 480 判定纯函数）
// ---------------------------------------------------------------------------

describe('isUnauthenticatedError（§5 行 480 判定纯函数）', () => {
  test('HTTP 401 或 Connect 标准码 unauthenticated → true', () => {
    expect(
      apiMod.isUnauthenticatedError(
        new ApiError({
          httpStatus: 401,
          code: 'unauthenticated',
          message: '',
          requestId: '',
        }),
      ),
    ).toBe(true);
    expect(
      apiMod.isUnauthenticatedError(
        new ApiError({
          httpStatus: 401,
          code: 'session_required',
          message: '',
          requestId: '',
        }),
      ),
    ).toBe(true);
    expect(
      apiMod.isUnauthenticatedError(
        new ApiError({
          httpStatus: 403,
          code: 'unauthenticated',
          message: '',
          requestId: '',
        }),
      ),
    ).toBe(true);
  });

  test('其他 ApiError / 非错误对象 → false', () => {
    expect(
      apiMod.isUnauthenticatedError(
        new ApiError({
          httpStatus: 403,
          code: 'permission_denied',
          message: '',
          requestId: '',
        }),
      ),
    ).toBe(false);
    expect(apiMod.isUnauthenticatedError(new Error('x'))).toBe(false);
    expect(apiMod.isUnauthenticatedError(undefined)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// api.getConfig（§3.2 行 819）——msw 走真实 transport 归一链
// ---------------------------------------------------------------------------

describe('api.getConfig（§3.2 行 819）', () => {
  test('AccountConfigResponse 解码：avatarUpload（int64 → bigint）+ mfaPolicy + captcha + hasPassword', async () => {
    server.use(
      http.post(CONFIG_URL, () =>
        HttpResponse.json({
          avatarUpload: {
            mode: 'direct',
            maxSize: '2097152',
            allowedTypes: ['image/png', 'image/jpeg'],
          },
          mfaPolicy: {
            enabled: true,
            trustedDeviceDays: '0',
            methods: [
              { factor: 'totp', bound: true },
              { factor: 'otp_email', bound: false },
            ],
          },
          captcha: { providerKey: 'builtin_image', type: 'image' },
          hasPassword: true,
        }),
      ),
    );

    const config = await apiMod.getConfig();

    expect(config.avatarUpload?.mode).toBe('direct');
    expect(config.avatarUpload?.maxSize).toBe(BigInt(2097152)); // int64 十进制字符串解码（§1.12）
    expect(config.avatarUpload?.allowedTypes).toEqual([
      'image/png',
      'image/jpeg',
    ]);
    expect(config.mfaPolicy?.enabled).toBe(true);
    expect(config.mfaPolicy?.trustedDeviceDays).toBe(BigInt(0)); // 预留恒 0（§3.2）
    expect(config.mfaPolicy?.methods[0]?.factor).toBe('totp');
    expect(config.mfaPolicy?.methods[0]?.bound).toBe(true);
    expect(config.mfaPolicy?.methods[1]?.factor).toBe('otp_email');
    expect(config.mfaPolicy?.methods[1]?.bound).toBe(false);
    expect(config.captcha?.providerKey).toBe('builtin_image');
    expect(config.captcha?.type).toBe('image');
    expect(config.captcha?.siteKey).toBe('');
    expect(config.hasPassword).toBe(true);
  });

  test('零值投影（§3.2 行 826）：protojson 省略零值 → maxSize 0n / allowedTypes [] → 隐藏上传入口', async () => {
    server.use(
      http.post(CONFIG_URL, () =>
        HttpResponse.json({
          avatarUpload: { mode: 'proxy' },
          hasPassword: false,
        }),
      ),
    );

    const config = await apiMod.getConfig();

    expect(config.avatarUpload?.mode).toBe('proxy');
    expect(config.avatarUpload?.maxSize).toBe(BigInt(0));
    expect(config.avatarUpload?.allowedTypes).toEqual([]);
    expect(uploadMod.isUploadEntryHidden(config.avatarUpload)).toBe(true);
    expect(config.mfaPolicy).toBeUndefined(); // 页面侧按 §3.1 零值兜底
  });
});

// ---------------------------------------------------------------------------
// api.changePassword（§3.3 行 855-863）
// ---------------------------------------------------------------------------

describe('api.changePassword（§3.3 行 855-863）', () => {
  test('hasPassword=false（首设密码）：currentPassword 零值省略（行 860）', async () => {
    let captured!: Request;
    server.use(
      http.post(CHANGE_PASSWORD_URL, ({ request }) => {
        captured = request;
        return HttpResponse.json({});
      }),
    );

    const built = apiMod.buildChangePasswordRequest(false, '', 'Abcdef12');
    expect(built.ok).toBe(true);
    if (!built.ok) {
      throw new Error('unreachable');
    }

    await apiMod.changePassword(built.request);

    const body = (await captured.json()) as Record<string, unknown>;
    expect(body).toEqual({ newPassword: 'Abcdef12' });
    expect(body).not.toHaveProperty('currentPassword');
  });

  test('hasPassword=true：currentPassword 随包（行 860 必填）', async () => {
    let captured!: Request;
    server.use(
      http.post(CHANGE_PASSWORD_URL, ({ request }) => {
        captured = request;
        return HttpResponse.json({});
      }),
    );

    const built = apiMod.buildChangePasswordRequest(
      true,
      'OldPass12',
      'NewPass12',
    );
    expect(built.ok).toBe(true);
    if (!built.ok) {
      throw new Error('unreachable');
    }

    await apiMod.changePassword(built.request);

    expect(await captured.json()).toEqual({
      currentPassword: 'OldPass12',
      newPassword: 'NewPass12',
    });
  });
});

// ---------------------------------------------------------------------------
// api.bindPhone / bindEmail（§3.4 行 870-873）
// ---------------------------------------------------------------------------

describe('api.bindPhone / bindEmail（§3.4 行 870-873）', () => {
  test('challenge：{step, payload:{phone}, captcha}——凭据为请求级顶层字段（§3.4 行 1029）', async () => {
    let captured!: Request;
    server.use(
      http.post(BIND_PHONE_URL, ({ request }) => {
        captured = request;
        return HttpResponse.json({});
      }),
    );

    const captcha = create(CaptchaPayloadSchema, {
      providerKey: 'builtin_image',
      id: 'cap-1',
      answer: '1234',
    });
    const built = apiMod.buildBindChallengeRequest(
      'phone',
      '13800138000',
      captcha,
    );
    expect(built.ok).toBe(true);
    if (!built.ok) {
      throw new Error('unreachable');
    }

    await apiMod.bindPhone(built.request as BindPhoneRequest);

    expect(await captured.json()).toEqual({
      step: 'challenge',
      payload: { phone: '13800138000' },
      captcha: { providerKey: 'builtin_image', id: 'cap-1', answer: '1234' },
    });
  });

  test('verify：{step, payload:{email, code}}——回传相同 target（行 881-882）', async () => {
    let captured!: Request;
    server.use(
      http.post(BIND_EMAIL_URL, ({ request }) => {
        captured = request;
        return HttpResponse.json({});
      }),
    );

    const built = apiMod.buildBindVerifyRequest(
      'email',
      'a@example.com',
      '123456',
    );
    expect(built.ok).toBe(true);
    if (!built.ok) {
      throw new Error('unreachable');
    }

    await apiMod.bindEmail(built.request as BindEmailRequest);

    expect(await captured.json()).toEqual({
      step: 'verify',
      payload: { email: 'a@example.com', code: '123456' },
    });
  });
});

// ---------------------------------------------------------------------------
// api.presignAvatar / commitAvatar（§3.2 行 822-823）
// ---------------------------------------------------------------------------

describe('api.presignAvatar / commitAvatar（§3.2 行 822-823）', () => {
  test('presign：size int64 十进制字符串上送；headers map / expiresIn 解码', async () => {
    let captured!: Request;
    server.use(
      http.post(PRESIGN_AVATAR_URL, ({ request }) => {
        captured = request;
        return HttpResponse.json({
          key: 'avatars/k1',
          uploadUrl: 'https://storage.test/put/k1',
          headers: { 'Content-Type': 'image/png' },
          expiresIn: '300',
        });
      }),
    );

    const result = await apiMod.presignAvatar(
      create(PresignAvatarRequestSchema, {
        filename: 'a.png',
        contentType: 'image/png',
        size: BigInt(2048),
      }),
    );

    expect(await captured.json()).toEqual({
      filename: 'a.png',
      contentType: 'image/png',
      size: '2048', // int64 → 十进制字符串（§1.12）
    });
    expect(result.key).toBe('avatars/k1');
    expect(result.uploadUrl).toBe('https://storage.test/put/k1');
    expect(result.headers['Content-Type']).toBe('image/png');
    expect(result.expiresIn).toBe(BigInt(300));
  });

  test('commit：{key} → {url}', async () => {
    let captured!: Request;
    server.use(
      http.post(COMMIT_AVATAR_URL, ({ request }) => {
        captured = request;
        return HttpResponse.json({ url: 'https://cdn.test/new.png' });
      }),
    );

    const result = await apiMod.commitAvatar(
      create(CommitAvatarRequestSchema, { key: 'avatars/k1' }),
    );

    expect(await captured.json()).toEqual({ key: 'avatars/k1' });
    expect(result.url).toBe('https://cdn.test/new.png');
  });
});

// ---------------------------------------------------------------------------
// api.uploadAvatar（§3.2 / §10.8 proxy 模式，UploadAvatar bytes 直传）
// ---------------------------------------------------------------------------

describe('api.uploadAvatar（§3.2 / §10.8 proxy 模式，UploadAvatar bytes 直传）', () => {
  test('bytes 一次直传 → {url}（protojson 下 content 为 base64，§1.1）', async () => {
    let captured!: Request;
    server.use(
      http.post(UPLOAD_AVATAR_URL, ({ request }) => {
        captured = request;
        return HttpResponse.json({ url: 'https://cdn.test/proxy.png' });
      }),
    );

    const content = new Uint8Array([1, 2, 3, 4]);
    const result = await sharedAccountMod.uploadAvatar(
      create(UploadAvatarRequestSchema, {
        filename: 'a.png',
        contentType: 'image/png',
        content,
      }),
    );

    const body = (await captured.json()) as {
      filename: string;
      contentType: string;
      content: string;
    };
    expect(body.filename).toBe('a.png');
    expect(body.contentType).toBe('image/png');
    expect(Buffer.from(body.content, 'base64')).toEqual(
      Buffer.from([1, 2, 3, 4]),
    );
    expect(result.url).toBe('https://cdn.test/proxy.png');
  });
});

// ---------------------------------------------------------------------------
// 表单请求构造纯函数（§3.3 / §3.4）
// ---------------------------------------------------------------------------

describe('buildChangePasswordRequest（§3.3，纯函数）', () => {
  test('hasPassword=true 且当前密码为空 → currentPassword 必填（行 860）', () => {
    expect(apiMod.buildChangePasswordRequest(true, '', 'Abcdef12')).toEqual({
      ok: false,
      error: { field: 'currentPassword' },
    });
  });

  test('新密码不过 §5.6 预校验 → newPassword + reasons（password_weak 服务端权威）', () => {
    const built = apiMod.buildChangePasswordRequest(true, 'OldPass12', 'short');
    expect(built.ok).toBe(false);
    if (built.ok || built.error.field !== 'newPassword') {
      throw new Error('unreachable');
    }
    expect(built.error.reasons).toEqual(['too_short', 'too_few_classes']);
  });

  test('hasPassword=false（首设密码）：currentPassword 置空（wire 省略）', () => {
    const built = apiMod.buildChangePasswordRequest(
      false,
      'whatever',
      'Abcdef12',
    );
    expect(built.ok).toBe(true);
    if (!built.ok) {
      throw new Error('unreachable');
    }
    expect(built.request.currentPassword).toBe('');
    expect(built.request.newPassword).toBe('Abcdef12');
  });

  test('hasPassword=true 通过：两字段齐备', () => {
    const built = apiMod.buildChangePasswordRequest(
      true,
      'OldPass12',
      'NewPass12',
    );
    expect(built.ok).toBe(true);
    if (!built.ok) {
      throw new Error('unreachable');
    }
    expect(built.request.currentPassword).toBe('OldPass12');
    expect(built.request.newPassword).toBe('NewPass12');
  });
});

describe('buildBindChallengeRequest / buildBindVerifyRequest（§3.4，纯函数）', () => {
  const captcha = create(CaptchaPayloadSchema, {
    providerKey: 'builtin_image',
    id: 'cap-1',
    answer: '1234',
  });

  test('目标格式不符 → invalid_target（§1.11 体验性预校验，后端权威）', () => {
    expect(apiMod.buildBindChallengeRequest('phone', '123', captcha)).toEqual({
      ok: false,
      error: 'invalid_target',
    });
    expect(
      apiMod.buildBindChallengeRequest('email', 'not-an-email', captcha),
    ).toEqual({
      ok: false,
      error: 'invalid_target',
    });
  });

  test('captcha 未就绪 → captcha_missing（§3.4 行 880 challenge 必过，不发包）', () => {
    expect(
      apiMod.buildBindChallengeRequest('phone', '13800138000', undefined),
    ).toEqual({
      ok: false,
      error: 'captcha_missing',
    });
  });

  test('phone challenge 就绪：step / payload 透传（captcha 引用恒等）', () => {
    const built = apiMod.buildBindChallengeRequest(
      'phone',
      '13800138000',
      captcha,
    );
    expect(built.ok).toBe(true);
    if (!built.ok) {
      throw new Error('unreachable');
    }
    expect(built.request.$typeName).toBe('api.account.v1.BindPhoneRequest');
    const request = built.request as BindPhoneRequest;
    expect(request.step).toBe('challenge');
    expect(request.payload?.phone).toBe('13800138000');
    expect(request.captcha).toBe(captcha);
  });

  test('email challenge 就绪：payload.email', () => {
    const built = apiMod.buildBindChallengeRequest(
      'email',
      'a@example.com',
      captcha,
    );
    expect(built.ok).toBe(true);
    if (!built.ok) {
      throw new Error('unreachable');
    }
    expect(built.request.$typeName).toBe('api.account.v1.BindEmailRequest');
    expect((built.request as BindEmailRequest).payload?.email).toBe(
      'a@example.com',
    );
  });

  test('verify：非 6 位 / 非数字 → invalid_code；就绪回传相同 target + code（行 881-882）', () => {
    expect(
      apiMod.buildBindVerifyRequest('phone', '13800138000', '12345'),
    ).toEqual({
      ok: false,
      error: 'invalid_code',
    });
    expect(
      apiMod.buildBindVerifyRequest('phone', '13800138000', '12345a'),
    ).toEqual({
      ok: false,
      error: 'invalid_code',
    });
    const built = apiMod.buildBindVerifyRequest(
      'phone',
      '13800138000',
      '123456',
    );
    expect(built.ok).toBe(true);
    if (!built.ok) {
      throw new Error('unreachable');
    }
    const request = built.request as BindPhoneRequest;
    expect(request.step).toBe('verify');
    expect(request.payload?.phone).toBe('13800138000');
    expect(request.payload?.code).toBe('123456');
  });
});

// ---------------------------------------------------------------------------
// 头像上传纯逻辑 + 两模式编排（§3.2 / §10.8 / 前端架构
// §8.2 行 648；被测对象已迁 shared/hooks/useUpload，直引新落位）
// ---------------------------------------------------------------------------

describe('头像上传（§3.2 / §10.8 / 前端架构 §8.2 行 648）', () => {
  test('isUploadEntryHidden：未加载 / 零值投影 → true；正常配置 → false（行 842）', () => {
    expect(uploadMod.isUploadEntryHidden(undefined)).toBe(true);
    expect(
      uploadMod.isUploadEntryHidden(
        create(AvatarUploadConfigSchema, { mode: 'proxy' }),
      ),
    ).toBe(true);
    expect(
      uploadMod.isUploadEntryHidden(
        create(AvatarUploadConfigSchema, {
          mode: 'proxy',
          maxSize: BigInt(2097152),
          allowedTypes: ['image/png'],
        }),
      ),
    ).toBe(false);
  });

  test('validateAvatarFile：超限 / 类型不符（code 与后端一致，行 868）', () => {
    const config = create(AvatarUploadConfigSchema, {
      mode: 'proxy',
      maxSize: BigInt(100),
      allowedTypes: ['image/png'],
    });
    expect(
      uploadMod.validateAvatarFile(config, { size: 101, type: 'image/png' }),
    ).toBe('file_too_large');
    expect(
      uploadMod.validateAvatarFile(config, { size: 50, type: 'image/gif' }),
    ).toBe('file_type_not_allowed');
    expect(
      uploadMod.validateAvatarFile(config, { size: 50, type: 'image/png' }),
    ).toBe(undefined);
  });

  test('uploadAvatarFile 预校验失败：抛 code 与后端一致的 ApiError，文案同源 i18n 字典', async () => {
    const config = create(AvatarUploadConfigSchema, {
      mode: 'proxy',
      maxSize: BigInt(100),
      allowedTypes: ['image/png'],
    });

    const oversize = new File([new Uint8Array(101)], 'a.png', {
      type: 'image/png',
    });
    const tooLargeError = (await captureRejection(
      uploadMod.uploadAvatarFile(config, oversize),
    )) as ApiError;
    expect(tooLargeError).toBeInstanceOf(ApiError);
    expect(tooLargeError.code).toBe('file_too_large');

    const wrongType = new File([new Uint8Array(10)], 'a.gif', {
      type: 'image/gif',
    });
    const typeError = (await captureRejection(
      uploadMod.uploadAvatarFile(config, wrongType),
    )) as ApiError;
    expect(typeError.code).toBe('file_type_not_allowed');

    // §8.2 行 648：预校验文案与后端一致（shared/i18n 同一份字典）。
    expect(t('errors.code.file_too_large')).toBe('文件大小超出限制');
    expect(t('errors.code.file_type_not_allowed')).toBe('文件类型不受支持');
    expect(apiMod.apiErrorText(tooLargeError)).toBe('文件大小超出限制');
  });

  test('direct 模式三步走：presign → PUT（带 headers）→ commit → url（§10.8，真实 avatarUploadDeps）', async () => {
    const order: string[] = [];
    let presignBody: unknown;
    let putHeaders: Headers | undefined;
    let commitBody: unknown;
    server.use(
      http.post(PRESIGN_AVATAR_URL, async ({ request }) => {
        order.push('presign');
        presignBody = await request.json();
        return HttpResponse.json({
          key: 'avatars/k1',
          uploadUrl: 'https://storage.test/put/k1',
          headers: { 'Content-Type': 'image/png' },
          expiresIn: '300',
        });
      }),
      http.put('https://storage.test/put/k1', ({ request }) => {
        order.push('put');
        putHeaders = request.headers;
        return new HttpResponse(null, { status: 200 });
      }),
      http.post(COMMIT_AVATAR_URL, async ({ request }) => {
        order.push('commit');
        commitBody = await request.json();
        return HttpResponse.json({ url: 'https://cdn.test/direct.png' });
      }),
    );

    const config = create(AvatarUploadConfigSchema, {
      mode: 'direct',
      maxSize: BigInt(2097152),
      allowedTypes: ['image/png'],
    });
    const file = new File([new Uint8Array(2048)], 'a.png', {
      type: 'image/png',
    });

    const url = await uploadMod.uploadAvatarFile(config, file);

    expect(url).toBe('https://cdn.test/direct.png');
    expect(order).toEqual(['presign', 'put', 'commit']); // direct 三步（§8.2 行 648）
    expect(presignBody).toEqual({
      filename: 'a.png',
      contentType: 'image/png',
      size: '2048',
    });
    expect(putHeaders?.get('content-type')).toBe('image/png');
    expect(commitBody).toEqual({ key: 'avatars/k1' });
  });

  test('proxy 模式（mock GetConfig）：UploadAvatar bytes 直传得 url（§10.8 / §8.2 行 648）', async () => {
    server.use(
      http.post(CONFIG_URL, () =>
        HttpResponse.json({
          avatarUpload: {
            mode: 'proxy',
            maxSize: '2097152',
            allowedTypes: ['image/png'],
          },
        }),
      ),
    );
    let captured!: Request;
    server.use(
      http.post(UPLOAD_AVATAR_URL, ({ request }) => {
        captured = request;
        return HttpResponse.json({ url: 'https://cdn.test/proxy.png' });
      }),
    );

    const config = await apiMod.getConfig();
    const avatarUpload = config.avatarUpload;
    if (avatarUpload === undefined) {
      throw new Error('GetConfig 未下发 avatarUpload');
    }
    expect(uploadMod.isUploadEntryHidden(avatarUpload)).toBe(false);

    const url = await uploadMod.uploadAvatarFile(
      avatarUpload,
      new File([new Uint8Array(8)], 'a.png', { type: 'image/png' }),
    );

    expect(url).toBe('https://cdn.test/proxy.png');
    const body = (await captured.json()) as {
      filename: string;
      contentType: string;
      content: string;
    };
    expect(body.filename).toBe('a.png');
    expect(body.contentType).toBe('image/png');
    expect(Buffer.from(body.content, 'base64')).toEqual(
      Buffer.from([0, 0, 0, 0, 0, 0, 0, 0]),
    );
  });
});

// ---------------------------------------------------------------------------
// apiErrorText（§1.5 行 202 i18n 优先 + 语境覆盖）
// ---------------------------------------------------------------------------

describe('apiErrorText（§1.5 行 202 i18n 优先 + 语境覆盖）', () => {
  test('ApiError → errors.code.<code> 字典文案', () => {
    expect(
      apiMod.apiErrorText(
        new ApiError({
          httpStatus: 400,
          code: 'password_weak',
          message: 'x',
          requestId: '',
        }),
      ),
    ).toBe('密码强度不足，请调整后重试');
    expect(
      apiMod.apiErrorText(
        new ApiError({
          httpStatus: 409,
          code: 'target_taken',
          message: 'x',
          requestId: '',
        }),
      ),
    ).toBe('该手机号/邮箱已被占用');
  });

  test('语境覆盖优先（改密 invalid_credentials → 当前密码不正确）', () => {
    expect(
      apiMod.apiErrorText(
        new ApiError({
          httpStatus: 401,
          code: 'invalid_credentials',
          message: 'x',
          requestId: '',
        }),
        { invalid_credentials: '当前密码不正确' },
      ),
    ).toBe('当前密码不正确');
  });

  test('未知 code / 非 ApiError → 兜底不透出细节（既定口径）', () => {
    expect(
      apiMod.apiErrorText(
        new ApiError({
          httpStatus: 400,
          code: 'weird_code',
          message: '内部细节',
          requestId: '',
        }),
      ),
    ).toBe('操作失败，请稍后重试');
    expect(apiMod.apiErrorText(new Error('x'))).toBe('操作失败，请稍后重试');
    expect(apiMod.apiErrorText(undefined)).toBe('操作失败，请稍后重试');
  });
});

// ---------------------------------------------------------------------------
// api.getMfa（§3.5 行 903）——msw 走真实 transport 归一链
// ---------------------------------------------------------------------------

describe('api.getMfa（§3.5 行 890-898）', () => {
  test('factors 明细解码（int64 十进制字符串 → bigint）+ recoveryIssuedAt；数组序即渲染序', async () => {
    server.use(
      http.post(GET_MFA_URL, () =>
        HttpResponse.json({
          factors: [
            {
              factor: 'totp',
              bound: true,
              boundAt: '1761800000',
              lastUsedAt: '1761800500',
            },
            {
              factor: 'otp_sms',
              bound: true,
              target: '138****8000',
              lastUsedAt: '1761800500',
            },
            { factor: 'otp_email', bound: false },
            {
              factor: 'webauthn',
              bound: true,
              credentials: '2',
              lastUsedAt: '1761800500',
            },
            { factor: 'recovery_code', bound: true, remaining: '8' },
          ],
          recoveryIssuedAt: '1761700000',
        }),
      ),
    );

    const mfa = await apiMod.getMfa();

    expect(mfa.factors.map((f) => f.factor)).toEqual([
      'totp',
      'otp_sms',
      'otp_email',
      'webauthn',
      'recovery_code',
    ]);
    expect(mfa.factors[0]?.boundAt).toBe(BigInt(1761800000)); // int64 十进制字符串解码（§1.12）
    expect(mfa.factors[0]?.lastUsedAt).toBe(BigInt(1761800500));
    expect(mfa.factors[1]?.target).toBe('138****8000');
    expect(mfa.factors[2]?.bound).toBe(false); // 未绑定因子其余字段零值
    expect(mfa.factors[2]?.boundAt).toBe(BigInt(0));
    expect(mfa.factors[3]?.credentials).toBe(BigInt(2));
    expect(mfa.factors[4]?.remaining).toBe(BigInt(8));
    expect(mfa.recoveryIssuedAt).toBe(BigInt(1761700000));
  });
});

// ---------------------------------------------------------------------------
// api.setMfa + buildSetMfaRequest + deriveMfaToggleView（§3.5 / 两步验证开关）
// ---------------------------------------------------------------------------

describe('api.setMfa / buildSetMfaRequest（§3.5）', () => {
  test('开启：buildSetMfaRequest(true) → wire {enabled:true}，setMfa 成功空响应', async () => {
    let captured!: Request;
    server.use(
      http.post(SET_MFA_URL, ({ request }) => {
        captured = request;
        return HttpResponse.json({});
      }),
    );

    const request = apiMod.buildSetMfaRequest(true);
    expect(request.enabled).toBe(true);

    await apiMod.setMfa(request);

    expect(await captured.json()).toEqual({ enabled: true });
  });

  test('关闭：buildSetMfaRequest(false) → bool 零值省略，wire 输出 {}', async () => {
    let captured!: Request;
    server.use(
      http.post(SET_MFA_URL, ({ request }) => {
        captured = request;
        return HttpResponse.json({});
      }),
    );

    const request = apiMod.buildSetMfaRequest(false);
    expect(request.enabled).toBe(false);

    await apiMod.setMfa(request);

    // protojson 省略 bool 零值（§12.9）→ 关闭在 wire 上即 {}。
    expect(await captured.json()).toEqual({});
  });
});

describe('deriveMfaToggleView（开关可用性 / 禁用原因 / 兜底）', () => {
  /** 构造白名单因子（bound 态按需）；新契约 MfaPolicyMethod 仅 factor / bound。 */
  const methods = (...bound: boolean[]): MfaPolicyMethod[] =>
    bound.map((state, i) =>
      create(MfaPolicyMethodSchema, {
        factor: ['totp', 'otp_sms', 'otp_email', 'webauthn'][i] ?? `f${i}`,
        bound: state,
      }),
    );

  test('methods 为空 → 禁用 + 管理员未启用提示', () => {
    expect(apiMod.deriveMfaToggleView(false, [])).toEqual({
      disabled: true,
      helpKey: 'account.mfaToggleNoMethods',
    });
  });

  test('因子全未绑定 → 禁用 + 请先绑定提示', () => {
    expect(apiMod.deriveMfaToggleView(false, methods(false, false))).toEqual({
      disabled: true,
      helpKey: 'account.mfaToggleNoBound',
    });
  });

  test('存在可用因子：关闭 → 关闭态说明；开启 → 开启态说明（均可切换）', () => {
    expect(apiMod.deriveMfaToggleView(false, methods(true, false))).toEqual({
      disabled: false,
      helpKey: 'account.mfaToggleOffHint',
    });
    expect(apiMod.deriveMfaToggleView(true, methods(true, false))).toEqual({
      disabled: false,
      helpKey: 'account.mfaToggleOnHint',
    });
  });

  test('开关已开但无可用因子（兜底边界）→ 保持可关闭 + 暂不生效提示', () => {
    expect(apiMod.deriveMfaToggleView(true, [])).toEqual({
      disabled: false,
      helpKey: 'account.mfaToggleFallback',
    });
    expect(apiMod.deriveMfaToggleView(true, methods(false, false))).toEqual({
      disabled: false,
      helpKey: 'account.mfaToggleFallback',
    });
  });
});

// ---------------------------------------------------------------------------
// api.bindTotp（§3.5 行 905-906 两步）
// ---------------------------------------------------------------------------

describe('api.bindTotp（§3.5 行 905-906）', () => {
  test('challenge：wire {step:"challenge"}（secret / code 零值省略）→ 解码 {secret, otpauthUrl, qrcodeContent}', async () => {
    let captured!: Request;
    server.use(
      http.post(BIND_TOTP_URL, ({ request }) => {
        captured = request;
        return HttpResponse.json({
          secret: 'JBSWY3DPEHPK3PXP',
          otpauthUrl:
            'otpauth://totp/Authloft:zhang_san?secret=JBSWY3DPEHPK3PXP&issuer=Authloft',
          qrcodeContent:
            'otpauth://totp/Authloft:zhang_san?secret=JBSWY3DPEHPK3PXP&issuer=Authloft',
        });
      }),
    );

    const res = await apiMod.bindTotp(apiMod.buildBindTotpChallengeRequest());

    expect(await captured.json()).toEqual({ step: 'challenge' }); // 行 905 入参空串
    expect(res.secret).toBe('JBSWY3DPEHPK3PXP');
    expect(res.otpauthUrl).toContain('otpauth://');
    expect(res.qrcodeContent).toContain('otpauth://');
    expect(res.recoveryCodes).toEqual([]); // challenge 步未用到的字段为零值
  });

  test('verify：非 6 位数字 → invalid_code；就绪 wire {step, secret, code} → 同一响应解码 10 个恢复码（行 906）', async () => {
    let captured!: Request;
    server.use(
      http.post(BIND_TOTP_URL, ({ request }) => {
        captured = request;
        return HttpResponse.json({ recoveryCodes: TEN_RECOVERY_CODES });
      }),
    );

    expect(apiMod.buildBindTotpVerifyRequest('sec', '12345')).toEqual({
      ok: false,
      error: 'invalid_code',
    });
    expect(apiMod.buildBindTotpVerifyRequest('sec', '12345a')).toEqual({
      ok: false,
      error: 'invalid_code',
    });

    const built = apiMod.buildBindTotpVerifyRequest('sec', '123456');
    expect(built.ok).toBe(true);
    if (!built.ok) {
      throw new Error('unreachable');
    }

    const res = await apiMod.bindTotp(built.request);

    expect(await captured.json()).toEqual({
      step: 'verify',
      secret: 'sec',
      code: '123456',
    });
    expect(res.recoveryCodes).toHaveLength(10); // 一次性下发 10 个恢复码
    expect(res.recoveryCodes[0]).toBe('a10b-c3d0');
  });
});

// ---------------------------------------------------------------------------
// api.regenerateRecoveryCodes（§3.5 行 908；存量码不可回显）
// ---------------------------------------------------------------------------

describe('api.regenerateRecoveryCodes（§3.5 行 908）', () => {
  test('wire {action:"regenerate"} → 一次性下发新码 + createdAt', async () => {
    let captured!: Request;
    server.use(
      http.post(REGEN_RECOVERY_CODES_URL, ({ request }) => {
        captured = request;
        return HttpResponse.json({
          codes: TEN_RECOVERY_CODES.map((c) => `new-${c}`),
          createdAt: '1761900000',
        });
      }),
    );

    const regen = await apiMod.regenerateRecoveryCodes(
      apiMod.buildRegenerateRecoveryCodesRequest(),
    );
    expect(await captured.json()).toEqual({ action: 'regenerate' }); // 行 908
    expect(regen.codes[0]).toBe('new-a10b-c3d0');
    expect(regen.createdAt).toBe(BigInt(1761900000));
  });
});

// ---------------------------------------------------------------------------
// api.getWebauthnCredentials / rename / delete（§3.6 行 914-918）
// ---------------------------------------------------------------------------

describe('api.getWebauthnCredentials / rename / delete（§3.6 行 914-918）', () => {
  test('列表解码：id / createdAt / lastUsedAt → bigint，transports、aaguid 原样', async () => {
    server.use(
      http.post(GET_WEBAUTHN_URL, () =>
        HttpResponse.json({
          items: [
            {
              id: '101',
              label: 'MacBook Touch ID',
              createdAt: '1761800000',
              lastUsedAt: '1761800500',
              transports: ['internal'],
              aaguid: 'adce0006-dbec-b1ed-c1ad-3c0e52f886fa',
            },
          ],
        }),
      ),
    );

    const list = await apiMod.getWebauthnCredentials();

    expect(list.items).toHaveLength(1);
    expect(list.items[0]?.id).toBe(BigInt(101));
    expect(list.items[0]?.label).toBe('MacBook Touch ID');
    expect(list.items[0]?.createdAt).toBe(BigInt(1761800000));
    expect(list.items[0]?.lastUsedAt).toBe(BigInt(1761800500));
    expect(list.items[0]?.transports).toEqual(['internal']);
    expect(list.items[0]?.aaguid).toBe('adce0006-dbec-b1ed-c1ad-3c0e52f886fa');
  });

  test('重命名 wire {id:"101", label}（int64 十进制字符串上送，§1.12）；删除 wire {id}', async () => {
    let renameBody!: unknown;
    let deleteBody!: unknown;
    server.use(
      http.post(RENAME_WEBAUTHN_URL, async ({ request }) => {
        renameBody = await request.json();
        return HttpResponse.json({});
      }),
      http.post(DELETE_WEBAUTHN_URL, async ({ request }) => {
        deleteBody = await request.json();
        return HttpResponse.json({});
      }),
    );

    await apiMod.renameWebauthnCredential(
      apiMod.buildRenameWebauthnRequest(BigInt(101), '新名字'),
    );
    await apiMod.deleteWebauthnCredential(
      apiMod.buildDeleteWebauthnRequest(BigInt(101)),
    );

    expect(renameBody).toEqual({ id: '101', label: '新名字' }); // 行 917 {id, label}
    expect(deleteBody).toEqual({ id: '101' }); // 行 918 {id}
  });
});

// ---------------------------------------------------------------------------
// registerWebauthnCredential（§3.6 行 915-916 三步编排，依赖注入）
// ---------------------------------------------------------------------------

describe('registerWebauthnCredential（§3.6 行 915-916 / §12.9 方案 A）', () => {
  /** challenge 下发的 options（PublicKeyCredentialCreationOptions 形状示例）。 */
  const CREATION_OPTIONS: JsonObject = {
    challenge: 'k9v0x8',
    rp: { name: 'Authloft' },
    user: { id: '10086', name: 'zhang_san', displayName: '张三' },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
  };
  /** @simplewebauthn 注册对象形状（§12.9 行 1783 credential 透传）。 */
  const CREDENTIAL: JsonObject = {
    id: 'cred-1',
    rawId: 'cred-1',
    type: 'public-key',
    response: { clientDataJSON: 'eyJ9', attestationObject: 'o2NmbQ' },
  };

  async function fakeChallengeResponse() {
    return create(RegisterWebauthnResponseSchema, {
      token: 'tok-1',
      challengeData: CREATION_OPTIONS,
      expiresIn: BigInt(120), // §3.6 行 926 默认 120
    });
  }

  test('三步编排：challenge → createCredential（challengeData 引用恒等透传）→ verify {step, token, credential 引用恒等, label}', async () => {
    const order: string[] = [];
    let optionsSeen: JsonObject | undefined;
    let verifyBody: unknown;
    const challengeResponse = await fakeChallengeResponse();

    const result = await apiMod.registerWebauthnCredential('我的手机', {
      challenge: async () => {
        order.push('challenge');
        return challengeResponse;
      },
      createCredential: async (optionsJSON) => {
        order.push('create');
        optionsSeen = optionsJSON;
        return CREDENTIAL;
      },
      verify: async (request) => {
        order.push('verify');
        verifyBody = request;
        // verify 注册成功空响应（行 916）：rpc 响应类型的零值消息。
        return create(RegisterWebauthnResponseSchema, {});
      },
    });

    expect(result).toEqual({ ok: true });
    expect(order).toEqual(['challenge', 'create', 'verify']);
    // §12.9 方案 A：challengeData 整体透传（同一引用、零字段访问）。
    expect(optionsSeen).toBe(challengeResponse.challengeData);
    // token 前端不感知结构仅透传（§3.6 行 930）。
    const request = verifyBody as RegisterWebauthnRequest;
    expect(request.step).toBe('verify');
    expect(request.token).toBe('tok-1');
    expect(request.credential).toBe(CREDENTIAL); // credential 引用恒等透传
    expect(request.label).toBe('我的手机');
  });

  test('NotAllowedError → cancelled（用户关闭浏览器原生 UI），不发包 verify；其他异常 → 失败（§4.3 行 453）', async () => {
    const order: string[] = [];

    const cancelled = await apiMod.registerWebauthnCredential('label', {
      challenge: fakeChallengeResponse,
      createCredential: async () => {
        order.push('create');
        throw new DOMException(
          'The operation either timed out or was not allowed.',
          'NotAllowedError',
        );
      },
      verify: async () => {
        order.push('verify');
        return create(RegisterWebauthnResponseSchema, {});
      },
    });
    expect(cancelled).toEqual({ ok: false, cancelled: true });
    expect(order).toEqual(['create']); // 取消后不发包

    const failed = await apiMod.registerWebauthnCredential('label', {
      challenge: async () => {
        throw new Error('network');
      },
      createCredential: async () => CREDENTIAL,
      verify: async () => create(RegisterWebauthnResponseSchema, {}),
    });
    expect(failed).toEqual({ ok: false, cancelled: false }); // challenge 失败（非用户取消）
  });
});

// ---------------------------------------------------------------------------
// 展示纯函数 formatUnixTime / mfaFactorDetail（§3.5 行 890-897）
// ---------------------------------------------------------------------------

describe('formatUnixTime / mfaFactorDetail（§3.1 零值兜底）', () => {
  test('formatUnixTime：零值 → 占位符；正值 → YYYY-MM-DD HH:mm', () => {
    expect(apiMod.formatUnixTime(BigInt(0))).toBe('—'); // 未使用 / 未签发（§3.5 行 898）
    expect(apiMod.formatUnixTime(BigInt(1761800000))).toMatch(
      /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$/,
    );
  });

  test('mfaFactorDetail：各因子只填相关字段（行 890-895），formatTime 可注入', () => {
    const fmt = (v: bigint): string => `T${v}`;
    expect(
      apiMod.mfaFactorDetail(
        create(MfaFactorSchema, {
          factor: 'totp',
          bound: true,
          boundAt: BigInt(5),
          lastUsedAt: BigInt(9),
        }),
        fmt,
      ),
    ).toBe('绑定于 T5 · 最近使用 T9');
    expect(
      apiMod.mfaFactorDetail(
        create(MfaFactorSchema, {
          factor: 'otp_sms',
          bound: true,
          target: '138****8000',
          lastUsedAt: BigInt(9),
        }),
        fmt,
      ),
    ).toBe('目标 138****8000 · 最近使用 T9');
    expect(
      apiMod.mfaFactorDetail(
        create(MfaFactorSchema, {
          factor: 'webauthn',
          bound: true,
          credentials: BigInt(2),
        }),
        fmt,
      ),
    ).toBe('已绑定 2 个凭据'); // lastUsedAt 零值省略
    expect(
      apiMod.mfaFactorDetail(
        create(MfaFactorSchema, {
          factor: 'recovery_code',
          bound: true,
          remaining: BigInt(8),
        }),
        fmt,
      ),
    ).toBe('剩余 8 个可用');
    expect(
      apiMod.mfaFactorDetail(
        create(MfaFactorSchema, { factor: 'otp_email', bound: false }),
        fmt,
      ),
    ).toBe('尚未绑定'); // 未绑定 → 其余字段不适用
  });
});

// ---------------------------------------------------------------------------
// 三方绑定族封装（§3.7 / §3.7.1，msw 真实 transport 归一链）
// ---------------------------------------------------------------------------

/** 已绑定行夹具（§3.7 行 936 items 条目；Union 行 type='union'）。 */
function bindingRow(over: { providerKey: string; type?: string }) {
  return create(ThirdpartyBindingSchema, {
    providerKey: over.providerKey,
    displayName: over.providerKey,
    type: over.type ?? over.providerKey,
    channel: 'redirect',
    icon: '',
    createdAt: BigInt(1761800000),
  });
}

describe('api.getThirdpartyBindings / unbindThirdparty / getThirdpartyTicket（§3.7 / §3.7.1）', () => {
  test('GetThirdpartyBindings → 双列表解码（items/available；createdAt / sortOrder int64 → bigint）', async () => {
    server.use(
      http.post(GET_THIRDPARTY_BINDINGS_URL, () =>
        HttpResponse.json({
          items: [
            {
              providerKey: 'qq',
              displayName: 'QQ',
              type: 'qq',
              channel: 'redirect',
              icon: '',
              createdAt: '1761800000',
            },
            {
              providerKey: 'wechat_union',
              displayName: '微信联合身份',
              type: 'union',
              channel: 'redirect',
              icon: '',
              createdAt: '1761800001',
            },
          ],
          available: [
            {
              providerKey: 'wechat_mp_scan',
              displayName: '微信扫码',
              type: 'wechat_mp_scan',
              channel: 'qrcode',
              icon: '',
              sortOrder: '20',
            },
          ],
        }),
      ),
    );

    const res = await apiMod.getThirdpartyBindings();

    expect(res.items).toHaveLength(2);
    expect(res.items[0].createdAt).toBe(BigInt(1761800000));
    expect(apiMod.isUnionThirdpartyRow(res.items[1])).toBe(true); // type='union' → Union 行
    expect(res.available[0].channel).toBe('qrcode');
    expect(res.available[0].sortOrder).toBe(BigInt(20));
  });

  test('unbindThirdparty → {providerKey} wire + 成功空响应（OkResponse）', async () => {
    let captured!: Request;
    server.use(
      http.post(UNBIND_THIRDPARTY_URL, ({ request }) => {
        captured = request;
        return HttpResponse.json({});
      }),
    );

    const res = await apiMod.unbindThirdparty(
      apiMod.buildUnbindThirdpartyRequest('qq'),
    );

    expect(await captured.json()).toEqual({ providerKey: 'qq' });
    expect(res.$typeName).toBe('api.account.v1.OkResponse');
  });

  test('getThirdpartyTicket → {ticket, poll:"10"} wire（§2.8 行 714 上限）+ 信封 .bind 解码（行 1024）', async () => {
    let captured!: Request;
    server.use(
      http.post(GET_THIRDPARTY_TICKET_URL, ({ request }) => {
        captured = request;
        return HttpResponse.json({
          status: 'success',
          ticket: { status: 'success', ticketId: 'c7Kx9' },
          bind: { providerKey: 'wechat_mp_scan', displayName: '微信扫码' },
        });
      }),
    );

    const res = await apiMod.getThirdpartyTicket(
      apiMod.buildGetThirdpartyTicketRequest('tk-1'),
    );

    expect(await captured.json()).toEqual({ ticket: 'tk-1', poll: '10' }); // int64 → 十进制字符串（§1.12）
    expect(res.status).toBe('success');
    expect(res.bind?.providerKey).toBe('wechat_mp_scan');
    expect(res.bind?.displayName).toBe('微信扫码');
  });
});

// ---------------------------------------------------------------------------
// shared/api/sso 的 Authorize / CreateQrcode 薄封装（§5 行 479 落位）
// ---------------------------------------------------------------------------

describe('shared/api/sso.authorize / createQrcode（§2.7.2 行 580 / §2.8 行 688）', () => {
  test('authorize：{provider, scene:"bind"} wire 直传，响应 authorizeUrl（scene=bind 需 al_session）', async () => {
    let captured!: Request;
    server.use(
      http.post(SSO_AUTHORIZE_URL, ({ request }) => {
        captured = request;
        return HttpResponse.json({
          authorizeUrl: 'https://qq.example/auth?state=b-x1',
        });
      }),
    );

    const res = await ssoMod.authorize({ provider: 'qq', scene: 'bind' });

    expect(await captured.json()).toEqual({ provider: 'qq', scene: 'bind' });
    expect(res.authorizeUrl).toBe('https://qq.example/auth?state=b-x1');
  });

  test('createQrcode：scene=bind + captcha 必带（行 703），响应 {ticket, ticketId, qrcodeUrl, expiresIn}', async () => {
    let captured!: Request;
    server.use(
      http.post(SSO_CREATE_QRCODE_URL, ({ request }) => {
        captured = request;
        return HttpResponse.json({
          ticket: 'tk-2',
          ticketId: 'c7Kx9',
          qrcodeUrl: 'https://cdn.test/qrcodes_c7Kx9.jpg',
          expiresIn: '600',
        });
      }),
    );

    const captcha = create(CaptchaPayloadSchema, {
      providerKey: 'builtin_image',
      id: 'cap-1',
      answer: '1234',
    });
    const res = await ssoMod.createQrcode(
      apiMod.buildCreateQrcodeBindRequest('wechat_mp_scan', captcha),
    );

    expect(await captured.json()).toEqual({
      providerKey: 'wechat_mp_scan',
      scene: 'bind',
      captcha: { providerKey: 'builtin_image', id: 'cap-1', answer: '1234' }, // token 零值省略（§2.5 行 503-506）
    });
    expect(res.ticket).toBe('tk-2');
    expect(res.ticketId).toBe('c7Kx9');
    expect(res.qrcodeUrl).toBe('https://cdn.test/qrcodes_c7Kx9.jpg');
    expect(res.expiresIn).toBe(BigInt(600));
  });
});

// ---------------------------------------------------------------------------
// 三方绑定纯逻辑（§3.7 / §3.7.1）
// ---------------------------------------------------------------------------

describe('isUnionThirdpartyRow / canUnbindThirdpartyRow（§3.7 行 938/945/947，纯函数）', () => {
  test('hasPassword=true → 非 Union 行全部可解绑（解绑后仍持有 password 凭证）', () => {
    const items = [bindingRow({ providerKey: 'qq' })];
    expect(apiMod.canUnbindThirdpartyRow(true, items, items[0])).toBe(true);
  });

  test('hasPassword=false 且无其他非 Union 绑定 → 置灰（解绑后无任何凭证可用）', () => {
    const items = [bindingRow({ providerKey: 'qq' })];
    expect(apiMod.canUnbindThirdpartyRow(false, items, items[0])).toBe(false);
  });

  test('hasPassword=false 但仍绑定另一非 Union 项 → 可解绑（排除自身行后计数 ≥1）', () => {
    const items = [
      bindingRow({ providerKey: 'qq' }),
      bindingRow({ providerKey: 'feishu' }),
    ];
    expect(apiMod.canUnbindThirdpartyRow(false, items, items[0])).toBe(true);
  });

  test('Union 行不计入已绑定数、不能单独解绑 → 恒 false（行 947）', () => {
    const items = [
      bindingRow({ providerKey: 'qq' }),
      bindingRow({ providerKey: 'wechat_union', type: 'union' }),
    ];
    expect(apiMod.canUnbindThirdpartyRow(true, items, items[1])).toBe(false);
    expect(apiMod.canUnbindThirdpartyRow(false, items, items[1])).toBe(false);
  });

  test('hasPassword=false、仅剩 Union 兄弟行 → 置灰（Union 不计入非 Union 计数）', () => {
    const items = [
      bindingRow({ providerKey: 'qq' }),
      bindingRow({ providerKey: 'wechat_union', type: 'union' }),
    ];
    expect(apiMod.canUnbindThirdpartyRow(false, items, items[0])).toBe(false);
  });
});

describe('hasBindEntry / sortThirdpartyOptions（§3.7 行 943 / 行 936，纯函数）', () => {
  test('redirect / qrcode 渲染绑定入口；api 通道与未知渠道保守不渲染（行 943）', () => {
    expect(apiMod.hasBindEntry('redirect')).toBe(true);
    expect(apiMod.hasBindEntry('qrcode')).toBe(true);
    expect(apiMod.hasBindEntry('api')).toBe(false);
    expect(apiMod.hasBindEntry('')).toBe(false);
  });

  test('available 按 sortOrder 升序兜底（bigint 比较；同值保持稳定）', () => {
    const options = [
      create(ThirdpartyOptionSchema, {
        providerKey: 'b',
        displayName: 'B',
        type: 'b',
        channel: 'qrcode',
        icon: '',
        sortOrder: BigInt(20),
      }),
      create(ThirdpartyOptionSchema, {
        providerKey: 'a',
        displayName: 'A',
        type: 'a',
        channel: 'redirect',
        icon: '',
        sortOrder: BigInt(10),
      }),
      create(ThirdpartyOptionSchema, {
        providerKey: 'c',
        displayName: 'C',
        type: 'c',
        channel: 'redirect',
        icon: '',
        sortOrder: BigInt(20),
      }),
    ];
    const sorted = apiMod.sortThirdpartyOptions(options);
    expect(sorted.map((o) => o.providerKey)).toEqual(['a', 'b', 'c']); // b/c 同值 → 数组序稳定
  });
});

describe('mergeThirdpartyAccounts（全量账号行：无论是否绑定均显示，纯函数）', () => {
  const option = (over: {
    providerKey: string;
    sortOrder: bigint;
    channel?: string;
  }) =>
    create(ThirdpartyOptionSchema, {
      providerKey: over.providerKey,
      displayName: over.providerKey,
      type: over.providerKey,
      channel: over.channel ?? 'redirect',
      icon: '',
      sortOrder: over.sortOrder,
    });

  test('items 原序全保留（含 Union / 已停用 Provider），available 按 sortOrder 追加', () => {
    const rows = apiMod.mergeThirdpartyAccounts(
      [
        bindingRow({ providerKey: 'qq' }),
        bindingRow({ providerKey: 'wechat_union', type: 'union' }),
      ],
      [
        option({ providerKey: 'github', sortOrder: BigInt(20) }),
        option({
          providerKey: 'google',
          sortOrder: BigInt(10),
          channel: 'api',
        }),
      ],
    );
    expect(rows.map((r) => r.providerKey)).toEqual([
      'qq',
      'wechat_union',
      'google',
      'github',
    ]);
    expect(rows.map((r) => r.bound)).toEqual([true, true, false, false]);
    expect(rows[0].createdAt).toBe(BigInt(1761800000));
    expect(rows[1].type).toBe('union');
    expect(rows[2].channel).toBe('api');
    expect(rows[2].createdAt).toBeUndefined();
  });

  test('双列表重叠 / available 内重复 → 按 providerKey 去重，已绑定优先', () => {
    const rows = apiMod.mergeThirdpartyAccounts(
      [bindingRow({ providerKey: 'qq' })],
      [
        option({ providerKey: 'qq', sortOrder: BigInt(1) }),
        option({ providerKey: 'github', sortOrder: BigInt(2) }),
        option({ providerKey: 'github', sortOrder: BigInt(3) }),
      ],
    );
    expect(rows.map((r) => [r.providerKey, r.bound])).toEqual([
      ['qq', true],
      ['github', false],
    ]);
  });

  test('items 为空 → 全部为未绑定行；两列表皆空 → 空数组', () => {
    const rows = apiMod.mergeThirdpartyAccounts(
      [],
      [option({ providerKey: 'github', sortOrder: BigInt(2) })],
    );
    expect(rows.map((r) => r.bound)).toEqual([false]);
    expect(apiMod.mergeThirdpartyAccounts([], [])).toEqual([]);
  });
});

describe('buildCreateQrcodeBindRequest / buildGetThirdpartyTicketRequest / buildUnbindThirdpartyRequest（§3.7.1 B，纯函数）', () => {
  test('CreateQrcode 请求：scene 固定 bind + captcha 透传（行 993 / §2.8 行 703）', () => {
    const captcha = create(CaptchaPayloadSchema, {
      providerKey: 'cf_turnstile',
      token: '0.xxx',
    });
    const request = apiMod.buildCreateQrcodeBindRequest(
      'wechat_mp_scan',
      captcha,
    );
    expect(toJson(CreateQrcodeRequestSchema, request)).toEqual({
      providerKey: 'wechat_mp_scan',
      scene: 'bind',
      captcha: { providerKey: 'cf_turnstile', token: '0.xxx' }, // id/answer 零值省略
    });
  });

  test('CreateQrcode 请求：缺凭据（reactive 首探）不带 captcha 字段裸发（§2.5 条件必填）', () => {
    const request = apiMod.buildCreateQrcodeBindRequest('wechat_mp_scan');
    expect(toJson(CreateQrcodeRequestSchema, request)).toEqual({
      providerKey: 'wechat_mp_scan',
      scene: 'bind',
    });
  });

  test('GetThirdpartyTicket 请求：poll 固定 10（§2.8 行 714 上限，与面板 pollSeconds 同值）', () => {
    expect(
      toJson(
        GetThirdpartyTicketRequestSchema,
        apiMod.buildGetThirdpartyTicketRequest('tk-3'),
      ),
    ).toEqual({
      ticket: 'tk-3',
      poll: '10',
    });
  });

  test('UnbindThirdparty 请求：{providerKey}（行 937）', () => {
    expect(
      toJson(
        UnbindThirdpartyRequestSchema,
        apiMod.buildUnbindThirdpartyRequest('qq'),
      ),
    ).toEqual({
      providerKey: 'qq',
    });
  });
});

describe('startBindRedirect（§3.7.1 A 行 956-960，依赖注入）', () => {
  test('成功 → 返回 authorizeUrl（绑定跳转无 saveOidcContext——依赖集无落盘通道，结构上即「不落盘」）', async () => {
    const url = await apiMod.startBindRedirect('qq', {
      request: async () => 'https://qq.example/auth?state=b-9',
    });
    expect(url).toBe('https://qq.example/auth?state=b-9');
  });

  test('Authorize 失败 → undefined；空 authorizeUrl → undefined（零值兜底不跳转，§9 第 18 条）', async () => {
    expect(
      await apiMod.startBindRedirect('qq', {
        request: async () => {
          throw new ApiError({
            httpStatus: 500,
            code: 'internal',
            message: '',
            requestId: '',
          });
        },
      }),
    ).toBe(undefined);
    expect(
      await apiMod.startBindRedirect('qq', { request: async () => '' }),
    ).toBe(undefined);
  });

  test('缺省依赖走 shared/api/sso 的 Authorize{provider, scene:"bind"}（§5 行 479 落位）', async () => {
    server.use(
      http.post(SSO_AUTHORIZE_URL, () =>
        HttpResponse.json({
          authorizeUrl: 'https://qq.example/auth?state=b-default',
        }),
      ),
    );

    const url = await apiMod.startBindRedirect('qq');

    expect(url).toBe('https://qq.example/auth?state=b-default');
  });
});

describe('readBindParam / bindParamMessage（§3.7.1 A 行 969-971，纯函数）', () => {
  test('readBindParam：?bind= 读取；空串 / 缺省 → undefined', () => {
    expect(apiMod.readBindParam('?bind=success')).toBe('success');
    expect(apiMod.readBindParam('?bind=target_taken&x=1')).toBe('target_taken');
    expect(apiMod.readBindParam('?bind=')).toBe(undefined);
    expect(apiMod.readBindParam('')).toBe(undefined);
    expect(apiMod.readBindParam('?other=1')).toBe(undefined);
  });

  test('bindParamMessage：success → 绑定成功提示（行 969）', () => {
    expect(apiMod.bindParamMessage('success')).toBe('第三方账号绑定成功');
  });

  test('bindParamMessage：target_taken → 绑定语境文案（行 971）', () => {
    expect(apiMod.bindParamMessage('target_taken')).toBe(
      '该账号已被其他账号绑定',
    );
    expect(apiMod.bindParamMessage('target_taken')).not.toBe(
      t('errors.code.target_taken'),
    ); // 非联系方式通用文案
  });

  test('bindParamMessage：其余按 §1.6 位置二出文案；未知码 unknown 兜底（行 272）', () => {
    expect(apiMod.bindParamMessage('state_mismatch')).toBe(
      t('errors.code.state_mismatch'),
    );
    expect(apiMod.bindParamMessage('weird_code')).toBe(
      t('errors.code.unknown'),
    );
  });
});

describe('bindFailureText（target_taken 语境文案；经 QRCodeDialog 的 resolveFailureText 注入）', () => {
  /** 轮询落定信封（结论在信封顶层 status）。 */
  const pollEnvelope = (status: string) =>
    create(LoginFlowResponseSchema, { status });

  test('target_taken 信封 → 绑定语境文案（非联系方式通用字典）', () => {
    expect(apiMod.bindFailureText(pollEnvelope('target_taken'))).toBe(
      '该账号已被其他账号绑定',
    );
    expect(apiMod.bindFailureText(pollEnvelope('target_taken'))).not.toBe(
      t('errors.status.target_taken'),
    );
  });

  test('其余 failed 信封 → 沿用 qrFailureText 通用字典；未知 status 走 unknown 兜底（§1.6 出文案口径）', () => {
    expect(apiMod.bindFailureText(pollEnvelope('provider_disabled'))).toBe(
      t('errors.status.provider_disabled'),
    );
    expect(apiMod.bindFailureText(pollEnvelope('brand_new'))).toBe(
      t('errors.status.unknown'),
    );
  });
});

// ---------------------------------------------------------------------------
// 日志族：GetEvents 封装 + 请求构造（§3.7 安全日志 / §1.7 分页约定）
// ---------------------------------------------------------------------------

/** 受控查询状态样例（EventLogTable 初始态：created_at desc）。 */
const LOG_QUERY = {
  page: 1,
  pageSize: DEFAULT_PAGE_SIZE,
  sort: 'created_at',
  order: 'desc',
  filters: {},
} as const;

describe('api.getEvents（§3.7 安全日志，msw 真实 transport 归一链）', () => {
  test('Connect 协议 POST GetEvents → 请求 wire（§1.7 分页）+ 响应解码（int64 字符串 → bigint）', async () => {
    let requestBody!: unknown;
    server.use(
      http.post(GET_EVENTS_URL, async ({ request }) => {
        requestBody = await request.json();
        return HttpResponse.json({
          items: [
            {
              event: 'login',
              createdAt: '1730000000',
              ip: '203.0.113.7',
              ua: 'Mozilla/5.0 (Windows NT 10.0)',
              amr: 'pwd',
              clientId: 'web-console',
            },
          ],
          total: '128',
          page: '1',
          pageSize: '20',
        });
      }),
    );

    const response = await apiMod.getEvents(
      apiMod.buildGetEventsRequest(LOG_QUERY),
    );

    expect(requestBody).toEqual({
      page: '1',
      pageSize: '20',
      sort: 'created_at',
      order: 'desc',
    });
    expect(response.total).toBe(BigInt(128));
    expect(response.items.length).toBe(1);
    expect(response.items[0]?.createdAt).toBe(BigInt(1730000000));
    expect(response.items[0]?.amr).toBe('pwd');
  });

  test('空页 items 省略（§1.7 行 278：空 repeated 不输出）→ 解码为 []；零值 total → 0n', async () => {
    server.use(
      http.post(GET_EVENTS_URL, () =>
        HttpResponse.json({ total: '0', page: '1', pageSize: '20' }),
      ),
    );

    const response = await apiMod.getEvents(
      apiMod.buildGetEventsRequest(LOG_QUERY),
    );

    expect(response.items).toEqual([]);
    expect(response.total).toBe(BigInt(0));
  });
});

describe('buildGetEventsRequest（§3.7 入参 + §1.7 分页约定，纯函数）', () => {
  test('分页 / 排序 → wire int64 十进制字符串（§1.12）+ sort/order 全量下发', () => {
    expect(
      toJson(
        GetEventsRequestSchema,
        apiMod.buildGetEventsRequest({
          page: 3,
          pageSize: 50,
          sort: 'created_at',
          order: 'asc',
          filters: {},
        }),
      ),
    ).toEqual({ page: '3', pageSize: '50', sort: 'created_at', order: 'asc' });
  });

  test('无排序（order 为空）→ sort/order 零值省略（§1.0 零值缺省）', () => {
    expect(
      toJson(
        GetEventsRequestSchema,
        apiMod.buildGetEventsRequest(initialTableQuery()),
      ),
    ).toEqual({ page: '1', pageSize: '20' });
  });

  test('event 类型过滤透传（§3.7 预留入参）；缺省省略不发', () => {
    expect(
      toJson(
        GetEventsRequestSchema,
        apiMod.buildGetEventsRequest(initialTableQuery(), 'login'),
      ),
    ).toEqual({ page: '1', pageSize: '20', event: 'login' });
  });
});

// ---------------------------------------------------------------------------
// EventLogTable 展示帧静态渲染（安全日志：多事件类型 / 行键防同秒碰撞）
// ---------------------------------------------------------------------------

describe('EventLogTable 安全日志展示帧（多事件类型渲染，ProfilePageView 同口径静态渲染）', () => {
  /** 展示帧纯 props 渲染（query 形态取 LOG_QUERY 初始态）。 */
  const renderView = (rows: UserEventItem[]): string =>
    renderToStaticMarkup(
      createElement(eventLogTableMod.EventLogTableView, {
        query: {
          page: 1,
          pageSize: DEFAULT_PAGE_SIZE,
          sort: 'created_at',
          order: 'desc',
          filters: {},
        },
        onQueryChange: () => {},
        rows,
        total: rows.length,
        loading: false,
        empty: undefined,
      }),
    );

  /** 同秒同源事件样例（仅 event 不同，行键碰撞判定基线）。 */
  const row = (event: string): UserEventItem =>
    create(UserEventItemSchema, {
      event,
      createdAt: BigInt(1730000000),
      ip: '203.0.113.7',
      amr: 'pwd',
    });

  test('多事件类型 → 事件类型列逐行经公用 event.* 键出文案；时间 / 方式 / IP / 设备列保留', () => {
    const html = renderView([
      row('login_success'),
      row('change_password'),
      row('thirdparty_bind'),
    ]);
    // 列标题 + 三类事件文案（event.* 公用键段，与 admin 同源一份映射）。
    expect(html).toContain(t('account.logEventColumn'));
    expect(html).toContain(t('event.login_success'));
    expect(html).toContain(t('event.change_password'));
    expect(html).toContain(t('event.thirdparty_bind'));
    // 既有列保留（标题与数据各抽一处）。
    expect(html).toContain(t('account.logTimeColumn'));
    expect(html).toContain('pwd');
    expect(html).toContain('203.0.113.7');
  });

  test('未知事件值原样兜底展示（§12.9 跨版本新增不粉饰）', () => {
    const html = renderView([row('future_event')]);
    expect(html).toContain('future_event');
  });

  test('行键含 event：同秒同源两类事件键不碰撞；同类重复行键稳定', () => {
    const login = row('login_success');
    const change = row('change_password');
    expect(eventLogTableMod.logRowKey(login)).not.toBe(
      eventLogTableMod.logRowKey(change),
    );
    expect(eventLogTableMod.logRowKey(login)).toBe(
      eventLogTableMod.logRowKey(row('login_success')),
    );
    expect(eventLogTableMod.logRowKey(login)).toContain('login_success');
  });
});

// ---------------------------------------------------------------------------
// DataTable 纯逻辑（前端架构 §3.3 行 348 / §8 行 621；零 Semi 依赖）
// ---------------------------------------------------------------------------

describe('dataTableLogic 分页常量与归一（§1.7 行 275-278）', () => {
  test('缺省 page=1 / pageSize=20；上限 100（行 277）', () => {
    expect(DEFAULT_PAGE_SIZE).toBe(20);
    expect(MAX_PAGE_SIZE).toBe(100);
    expect(initialTableQuery()).toEqual({
      page: 1,
      pageSize: 20,
      sort: '',
      order: '',
      filters: {},
    });
    expect(initialTableQuery(250).pageSize).toBe(100);
    expect(clampPageSize(0)).toBe(20);
    expect(clampPageSize(500)).toBe(100);
  });
});

describe('dataTableLogic.resolveTableQuery（§8 行 621：分页 / 排序 / 筛选回调参数）', () => {
  const prev = initialTableQuery();

  test('分页回调：currentPage / pageSize → §1.7 归一（page ≥1、pageSize ∈ [1,100]）', () => {
    expect(
      resolveTableQuery({ pagination: { currentPage: 2, pageSize: 50 } }, prev),
    ).toEqual({ page: 2, pageSize: 50, sort: '', order: '', filters: {} });
    // 越界夹取（行 277：page 从 1 开始、pageSize 上限 100）
    expect(
      resolveTableQuery(
        { pagination: { currentPage: 0, pageSize: 500 } },
        prev,
      ),
    ).toEqual({ page: 1, pageSize: 100, sort: '', order: '', filters: {} });
  });

  test('分页回调缺省 → 保持 prev（排序 / 筛选变化时仅带 sorter / filters 的防御）', () => {
    const next = resolveTableQuery(
      { sorter: { dataIndex: 'created_at', sortOrder: 'ascend' } },
      { ...prev, page: 4, pageSize: 50 },
    );
    expect(next.page).toBe(4);
    expect(next.pageSize).toBe(50);
  });

  test('排序回调：ascend / descend → asc / desc；清除排序（false）→ order 置空', () => {
    expect(
      resolveTableQuery(
        { sorter: { dataIndex: 'created_at', sortOrder: 'descend' } },
        prev,
      ),
    ).toEqual({
      page: 1,
      pageSize: 20,
      sort: 'created_at',
      order: 'desc',
      filters: {},
    });
    expect(
      resolveTableQuery(
        { sorter: { dataIndex: 'created_at', sortOrder: 'ascend' } },
        prev,
      ),
    ).toEqual({
      page: 1,
      pageSize: 20,
      sort: 'created_at',
      order: 'asc',
      filters: {},
    });
    expect(
      resolveTableQuery(
        { sorter: { dataIndex: 'created_at', sortOrder: false } },
        prev,
      ),
    ).toEqual({
      page: 1,
      pageSize: 20,
      sort: 'created_at',
      order: '',
      filters: {},
    });
  });

  test('筛选回调：filters 数组 → dataIndex → 选中值映射；未带 filteredValue → 空数组', () => {
    const next = resolveTableQuery(
      {
        filters: [
          { dataIndex: 'event', filteredValue: ['login', 'mfa_login'] },
          { dataIndex: 'ip' },
        ],
      },
      prev,
    );
    expect(next.filters).toEqual({ event: ['login', 'mfa_login'], ip: [] });
  });
});

describe('dataTableLogic 行内开关（§8 行 621：乐观更新与回滚）', () => {
  interface FakeRow {
    key: string;
    enabled: boolean;
  }

  const rows: FakeRow[] = [
    { key: 'a', enabled: false },
    { key: 'b', enabled: true },
  ];
  const keyOf = (row: FakeRow): string => row.key;
  const toggle = (row: FakeRow): FakeRow => ({ ...row, enabled: !row.enabled });

  test('patchRowByKey：命中行不可变更新（原数组 / 原行对象不动）；未命中 → 原引用', () => {
    const next = patchRowByKey(rows, keyOf, 'a', (row) => ({
      ...row,
      enabled: true,
    }));
    expect(next).not.toBe(rows);
    expect(rows[0]).toEqual({ key: 'a', enabled: false }); // 原行未动 = 回滚依据
    expect(next[0]).toEqual({ key: 'a', enabled: true });
    expect(next[1]).toBe(rows[1]); // 未命中行原对象复用
    expect(
      patchRowByKey(rows, keyOf, 'zz', (row) => ({ ...row, enabled: true })),
    ).toBe(rows);
  });

  test('runInlineToggle：persist 成功 → 保留乐观行集（ok: true），persist 收到打补丁行', async () => {
    const persisted: unknown[] = [];
    const outcome = await runInlineToggle(
      rows,
      keyOf,
      'a',
      toggle,
      async (patched) => {
        persisted.push(patched);
      },
    );
    expect(outcome.ok).toBe(true);
    expect(outcome.rows[0]).toEqual({ key: 'a', enabled: true });
    expect(persisted).toEqual([{ key: 'a', enabled: true }]);
  });

  test('runInlineToggle：persist 失败 → 回滚原 rows 引用（ok: false）且原数组完好', async () => {
    const outcome = await runInlineToggle(
      rows,
      keyOf,
      'a',
      toggle,
      async () => {
        throw new Error('boom');
      },
    );
    expect(outcome.ok).toBe(false);
    expect(outcome.rows).toBe(rows); // 回滚 = 恢复原引用
    expect(rows[0]).toEqual({ key: 'a', enabled: false });
  });

  test('runInlineToggle：key 未命中 → 不调 persist、原样返回（无可变更项）', async () => {
    let persistCalled = false;
    const outcome = await runInlineToggle(
      rows,
      keyOf,
      'zz',
      toggle,
      async () => {
        persistCalled = true;
      },
    );
    expect(outcome.ok).toBe(true);
    expect(outcome.rows).toBe(rows);
    expect(persistCalled).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// UpdateProfile 资料编辑 + 头像持久化（§3.2 PATCH 语义 + 头像链路接线）
// ---------------------------------------------------------------------------

/** GetProfile 基线样例（§3.1 行 795-815 全字段；diff 基线，头像持久化同用）。 */
const PROFILE_BASE = create(ProfileResponseSchema, {
  id: BigInt(10086),
  username: 'zhang_san',
  nickname: '张三',
  avatarUrl: 'https://cdn.test/a.jpg',
  phone: '138****8000',
  phoneVerified: BigInt(1),
  email: 'a***@example.com',
  emailVerified: BigInt(1),
  userStatus: BigInt(1),
  mfaRequired: BigInt(0),
  epoch: BigInt(3),
  lastLoginAt: BigInt(1761800000),
  createdAt: BigInt(1761700000),
  updatedAt: BigInt(1761800000),
  profile: create(UserProfileSchema, {
    gender: BigInt(0),
    birthday: '1990-01-01',
    locale: 'zh-CN',
    timezone: 'Asia/Shanghai',
    extra: { company: 'acme' },
  }),
});

/** 基线草稿样例（编辑帧预填值 = PROFILE_BASE 原值；patch 覆盖变化字段）。 */
const profileDraft = (
  patch: Partial<import('./api').ProfileEditDraft>,
): import('./api').ProfileEditDraft => ({
  nickname: '张三',
  gender: 0,
  birthday: '1990-01-01',
  locale: 'zh-CN',
  timezone: 'Asia/Shanghai',
  ...patch,
});

describe('api.updateProfile（§3.2 行 837，msw 真实 transport 归一链）', () => {
  test('Connect 协议 POST → OkResponse 空响应 + 请求 wire 全字段（int64 十进制字符串 §1.12）', async () => {
    let captured!: Request;
    server.use(
      http.post(UPDATE_PROFILE_URL, ({ request }) => {
        captured = request;
        // OkResponse 空消息 → protojson 输出 {}（§1.0 行 57 成功响应即响应消息）。
        return HttpResponse.json({});
      }),
    );

    const built = apiMod.buildUpdateProfileRequest(
      PROFILE_BASE,
      profileDraft({
        nickname: '张三丰',
        gender: 2,
        birthday: '1991-02-03',
        locale: 'en-US',
        timezone: 'UTC',
      }),
    );
    expect(built.ok).toBe(true);
    if (!built.ok) {
      throw new Error('unreachable');
    }
    expect(built.changed).toBe(true);

    await apiMod.updateProfile(built.request);

    expect(await captured.json()).toEqual({
      nickname: '张三丰',
      profile: {
        gender: '2',
        birthday: '1991-02-03',
        locale: 'en-US',
        timezone: 'UTC',
      },
    });
  });

  test('头像持久化：buildAvatarPersistRequest → wire 仅 {avatarUrl}（§3.2 行 837）', async () => {
    let captured!: Request;
    server.use(
      http.post(UPDATE_PROFILE_URL, ({ request }) => {
        captured = request;
        return HttpResponse.json({});
      }),
    );

    const persisted = apiMod.buildAvatarPersistRequest(
      'https://cdn.test/b.jpg',
    );
    if (!persisted.ok) {
      throw new Error('unreachable');
    }
    await apiMod.updateProfile(persisted.request);

    expect(await captured.json()).toEqual({
      avatarUrl: 'https://cdn.test/b.jpg',
    });
  });

  test('校验失败：HTTP 400 Connect 错误体 → 归一 ApiError（既定口径：mock 须带错误 JSON 体）', async () => {
    server.use(
      http.post(UPDATE_PROFILE_URL, () =>
        HttpResponse.json(
          { code: 'invalid_argument', message: 'profile invalid' },
          { status: 400 },
        ),
      ),
    );

    const persisted = apiMod.buildAvatarPersistRequest('u');
    if (!persisted.ok) {
      throw new Error('unreachable');
    }
    const caught = await captureRejection(
      apiMod.updateProfile(persisted.request),
    );

    expect(caught).toBeInstanceOf(ApiError);
    expect((caught as ApiError).httpStatus).toBe(400);
    expect((caught as ApiError).code).toBe('invalid_argument');
  });
});

describe('buildUpdateProfileRequest（§3.2 PATCH 语义——缺省保留，纯函数）', () => {
  test('草稿与基线全同 → 零值 request：wire {}（服务端空操作幂等）且 changed=false（无改动跳过提交）', () => {
    const built = apiMod.buildUpdateProfileRequest(
      PROFILE_BASE,
      profileDraft({}),
    );
    expect(built.ok).toBe(true);
    if (!built.ok) {
      throw new Error('unreachable');
    }
    expect(built.changed).toBe(false);
    expect(toJson(UpdateProfileRequestSchema, built.request)).toEqual({});
  });

  test('PATCH 缺省保留：仅 nickname 编辑 → wire 只带 nickname（profile 整体省略）', () => {
    const built = apiMod.buildUpdateProfileRequest(
      PROFILE_BASE,
      profileDraft({ nickname: '李四' }),
    );
    expect(built.ok).toBe(true);
    if (!built.ok) {
      throw new Error('unreachable');
    }
    expect(toJson(UpdateProfileRequestSchema, built.request)).toEqual({
      nickname: '李四',
    });
  });

  test('gender 编辑 0→2：number → bigint，wire 十进制字符串（§1.12）；nickname 未编辑不带', () => {
    const built = apiMod.buildUpdateProfileRequest(
      PROFILE_BASE,
      profileDraft({ gender: 2 }),
    );
    expect(built.ok).toBe(true);
    if (!built.ok) {
      throw new Error('unreachable');
    }
    expect(toJson(UpdateProfileRequestSchema, built.request)).toEqual({
      profile: { gender: '2' },
    });
  });

  test('多字段编辑：profile 只带变化字段，未编辑字段零值省略（§1.0）', () => {
    const built = apiMod.buildUpdateProfileRequest(
      PROFILE_BASE,
      profileDraft({
        birthday: '1991-02-03',
        locale: 'en-US',
        timezone: 'UTC',
      }),
    );
    expect(built.ok).toBe(true);
    if (!built.ok) {
      throw new Error('unreachable');
    }
    expect(toJson(UpdateProfileRequestSchema, built.request)).toEqual({
      profile: { birthday: '1991-02-03', locale: 'en-US', timezone: 'UTC' },
    });
  });

  test('nickname 编辑为空串：wire 显式带空串（proto3 optional has 位，「清空昵称」= 显式设值覆盖，§3.2 行 843）', () => {
    const built = apiMod.buildUpdateProfileRequest(
      PROFILE_BASE,
      profileDraft({ nickname: '' }),
    );
    expect(built.ok).toBe(true);
    if (!built.ok) {
      throw new Error('unreachable');
    }
    expect(toJson(UpdateProfileRequestSchema, built.request)).toEqual({
      nickname: '',
    });
  });

  test('nickname 超限：13 字（汉字）→ nickname_too_long 不发包；12 字正常进 wire（§3.2 上限 12 字，码点口径）', () => {
    expect(
      apiMod.buildUpdateProfileRequest(
        PROFILE_BASE,
        profileDraft({ nickname: '一二三四五六七八九十甲乙丙' }),
      ),
    ).toEqual({ ok: false, error: 'nickname_too_long' });
    const accepted = apiMod.buildUpdateProfileRequest(
      PROFILE_BASE,
      profileDraft({ nickname: '一二三四五六七八九十甲乙' }),
    );
    expect(accepted.ok).toBe(true);
    if (!accepted.ok) {
      throw new Error('unreachable');
    }
    expect(accepted.changed).toBe(true);
    expect(toJson(UpdateProfileRequestSchema, accepted.request)).toEqual({
      nickname: '一二三四五六七八九十甲乙',
    });
    // astral 码点计 1：12 个 emoji（UTF-16 计 24）与后端 rune 口径一致放行。
    const astral = apiMod.buildUpdateProfileRequest(
      PROFILE_BASE,
      profileDraft({ nickname: '😀'.repeat(12) }),
    );
    expect(astral.ok).toBe(true);
  });

  test('birthday 编辑为非法格式 / 真非法日历 → invalid_birthday 不发包（YYYY-MM-DD §3.1；Date 静默归一化的日期必须拒绝）', () => {
    for (const birthday of [
      '1990/01/01',
      '1990-1-1',
      '19901301',
      '1990-13-01',
      // 真非法日历日：JS Date 会归一化为 3 月 1 日 / 2 月 28 日，判 NaN 拦不住。
      '1990-02-30',
      '2021-02-29',
      '1990-04-31',
    ]) {
      expect(
        apiMod.buildUpdateProfileRequest(
          PROFILE_BASE,
          profileDraft({ birthday }),
        ),
      ).toEqual({ ok: false, error: 'invalid_birthday' });
    }
  });

  test('birthday 闰日合法（2020-02-29）→ 正常进 wire 且 changed=true（防过拒）', () => {
    const built = apiMod.buildUpdateProfileRequest(
      PROFILE_BASE,
      profileDraft({ birthday: '2020-02-29' }),
    );
    expect(built.ok).toBe(true);
    if (!built.ok) {
      throw new Error('unreachable');
    }
    expect(built.changed).toBe(true);
    expect(toJson(UpdateProfileRequestSchema, built.request)).toEqual({
      profile: { birthday: '2020-02-29' },
    });
  });

  test('birthday 编辑为空串：wire 显式带空串（proto3 optional has 位，「清空生日」= 显式设值覆盖，§3.2 行 843）', () => {
    const built = apiMod.buildUpdateProfileRequest(
      PROFILE_BASE,
      profileDraft({ birthday: '' }),
    );
    expect(built.ok).toBe(true);
    if (!built.ok) {
      throw new Error('unreachable');
    }
    // 编辑过 → 进 create 入参（has 位建立）；optional string 空串 wire 显式
    // 出现 → 服务端按「显式设值 = 覆盖」清空 birthday（§3.2 行 843）。
    expect(toJson(UpdateProfileRequestSchema, built.request)).toEqual({
      profile: { birthday: '' },
    });
  });

  test('基线无 profile 字段（protojson 省略 → 解码 undefined）→ 按零值基线 diff，编辑即变化', () => {
    const bare = create(ProfileResponseSchema, { username: 'u1' });
    const built = apiMod.buildUpdateProfileRequest(bare, {
      nickname: '',
      gender: 1,
      birthday: '',
      locale: '',
      timezone: '',
    });
    expect(built.ok).toBe(true);
    if (!built.ok) {
      throw new Error('unreachable');
    }
    expect(toJson(UpdateProfileRequestSchema, built.request)).toEqual({
      profile: { gender: '1' },
    });
  });
});

describe('buildAvatarPersistRequest 长度契约（§3.2 avatarUrl 上限 120 字符，纯函数）', () => {
  test('121 字符 → avatar_url_too_long 拒绝构造不发包；120 字符正常构造', () => {
    // 仅测长度口径，不校验 URL 形态（构造函数只计长度，同后端 rune 口径）。
    const rejected = apiMod.buildAvatarPersistRequest('a'.repeat(121));
    expect(rejected).toEqual({ ok: false, error: 'avatar_url_too_long' });
    const accepted = apiMod.buildAvatarPersistRequest('a'.repeat(120));
    expect(accepted.ok).toBe(true);
    if (!accepted.ok) {
      throw new Error('unreachable');
    }
    expect(toJson(UpdateProfileRequestSchema, accepted.request)).toEqual({
      avatarUrl: 'a'.repeat(120),
    });
  });
});

describe('PROFILE_EDIT_FIELD_ERROR_KEY（校验失败形态 → i18n 键表，文案由字典层落）', () => {
  test('两形态各自落键', () => {
    expect(apiMod.PROFILE_EDIT_FIELD_ERROR_KEY.invalid_birthday).toBe(
      'account.birthdayInvalid',
    );
    expect(apiMod.PROFILE_EDIT_FIELD_ERROR_KEY.nickname_too_long).toBe(
      'account.nicknameTooLong',
    );
  });
});

describe('profileGenderText（§3.1 行 811 枚举 0/1/2 展示映射，纯函数）', () => {
  test('0 保密 / 1 男 / 2 女；出域值原样显示数字不粉饰（沿 mfaFactorDetail default 同口径）', () => {
    expect(apiMod.profileGenderText(BigInt(0))).toBe('保密');
    expect(apiMod.profileGenderText(BigInt(1))).toBe('男');
    expect(apiMod.profileGenderText(BigInt(2))).toBe('女');
    expect(apiMod.profileGenderText(BigInt(9))).toBe('9');
  });
});

describe('profileLocaleText / profileTimezoneText（展示态可读文案，与下拉选项 label 同源）', () => {
  test('locale：预设 → 自称 + 原值「简体中文 (zh-CN)」；出域值原样返回', () => {
    expect(apiMod.profileLocaleText('zh-CN')).toBe('简体中文 (zh-CN)');
    expect(apiMod.profileLocaleText('en-US')).toBe('English (en-US)');
    expect(apiMod.profileLocaleText('ja-JP')).toBe('日本語 (ja-JP)');
    // 出域值不在展示名表 → 原样（与 withCurrentOption 补项 label 同式）。
    expect(apiMod.profileLocaleText('en-GB')).toBe('en-GB');
    expect(apiMod.profileLocaleText('')).toBe('');
  });

  test('timezone：IANA 分隔符转可读空格；无分隔符（UTC）与历史别名同式', () => {
    expect(apiMod.profileTimezoneText('Asia/Shanghai')).toBe('Asia / Shanghai');
    expect(apiMod.profileTimezoneText('America/Argentina/Buenos_Aires')).toBe(
      'America / Argentina / Buenos Aires',
    );
    expect(apiMod.profileTimezoneText('UTC')).toBe('UTC');
    expect(apiMod.profileTimezoneText('US/Pacific')).toBe('US / Pacific');
    expect(apiMod.profileTimezoneText('')).toBe('');
  });

  test('下拉选项 label 与展示文案同源：预设项 label = 可读文案，兜底补项 label = 原值', () => {
    const localePresets = apiMod.profileLocaleOptions('');
    expect(localePresets[0]).toEqual({
      value: 'zh-CN',
      label: '简体中文 (zh-CN)',
    });
    // timezone 预设项 label 同式（首项随运行时 tzdata 排序，按值查找）。
    const timezonePresets = apiMod.profileTimezoneOptions('');
    const shanghai = timezonePresets.find(
      (option) => option.value === 'Asia/Shanghai',
    );
    expect(shanghai).toEqual({
      value: 'Asia/Shanghai',
      label: 'Asia / Shanghai',
    });
  });
});

describe('编辑下拉选项集现值兜底（profileLocaleOptions / profileTimezoneOptions / profileGenderOptions，纯函数）', () => {
  test('时区预设：全量 IANA 经 Intl.supportedValuesOf 动态生成（零硬编码，量级 400+，含常用项）', () => {
    const presets = apiMod.profileTimezoneOptions('');
    expect(presets.length).toBeGreaterThanOrEqual(400);
    expect(presets.map((option) => option.value)).toEqual(
      expect.arrayContaining(['Asia/Shanghai', 'America/New_York']),
    );
    // 预设项 label 为可读文案（与展示态同源），搜索按原值 + label 双向匹配。
    expect(presets[0]).toMatchObject({
      value: expect.any(String),
      label: expect.any(String),
    });
  });

  test('timezone 服务端现值兜底：历史别名（US/Pacific 不在全量 IANA 规范集）/ 出域值 → 补一项原值选项防误清空', () => {
    const presets = apiMod.profileTimezoneOptions('');
    // 在集内 / 未设置 → 不补项（列表即预设全集）。
    expect(apiMod.profileTimezoneOptions('Asia/Shanghai')).toHaveLength(
      presets.length,
    );
    expect(apiMod.profileTimezoneOptions('')).toHaveLength(presets.length);
    // 历史时区别名与出域自造值：补项保留现值，保存不丢原值。
    expect(apiMod.profileTimezoneOptions('US/Pacific').at(-1)).toEqual({
      value: 'US/Pacific',
      label: 'US/Pacific',
    });
    expect(apiMod.profileTimezoneOptions('Mars/Olympus').at(-1)).toEqual({
      value: 'Mars/Olympus',
      label: 'Mars/Olympus',
    });
  });

  test('locale 常用预设 + 出域现值补项（en-GB 不在常用集 → 补项保留；在集内 / 未设置 → 不补）', () => {
    const presets = apiMod.profileLocaleOptions('');
    expect(presets.map((option) => option.value)).toEqual([
      'zh-CN',
      'zh-TW',
      'en-US',
      'ja-JP',
      'ko-KR',
    ]);
    const withOutDomain = apiMod.profileLocaleOptions('en-GB');
    expect(withOutDomain).toHaveLength(presets.length + 1);
    expect(withOutDomain.at(-1)).toEqual({ value: 'en-GB', label: 'en-GB' });
    expect(apiMod.profileLocaleOptions('zh-CN')).toHaveLength(presets.length);
    expect(apiMod.profileLocaleOptions('')).toHaveLength(presets.length);
  });

  test('gender 出域现值补项（9 → 补原值选项，文案沿展示映射「原样显示数字」口径；枚举内不补）', () => {
    expect(apiMod.profileGenderOptions(0)).toEqual([
      { value: 0, label: t('account.genderSecret') },
      { value: 1, label: t('account.genderMale') },
      { value: 2, label: t('account.genderFemale') },
    ]);
    const outDomain = apiMod.profileGenderOptions(9);
    expect(outDomain).toHaveLength(4);
    expect(outDomain.at(-1)).toEqual({ value: 9, label: '9' });
    expect(apiMod.profileGenderOptions(2)).toHaveLength(3);
  });
});

describe('avatarPersistFailureMessage（头像持久化失败文案分派，纯函数）', () => {
  test('401 / unauthenticated → undefined（归 requestOptions 集中分派跳登录，不出行内文案）', () => {
    expect(
      apiMod.avatarPersistFailureMessage(
        new ApiError({
          httpStatus: 401,
          code: 'internal',
          message: '',
          requestId: '',
        }),
      ),
    ).toBeUndefined();
    expect(
      apiMod.avatarPersistFailureMessage(
        new ApiError({
          httpStatus: 0,
          code: 'unauthenticated',
          message: '',
          requestId: '',
        }),
      ),
    ).toBeUndefined();
  });

  test('其余失败 → 专属文案（区别于通用「操作失败」，可感知是头像未存上）', () => {
    expect(
      apiMod.avatarPersistFailureMessage(
        new ApiError({
          httpStatus: 400,
          code: 'invalid_argument',
          message: '',
          requestId: '',
        }),
      ),
    ).toBe(t('account.avatarPersistFailed'));
    expect(apiMod.avatarPersistFailureMessage(new Error('network down'))).toBe(
      t('account.avatarPersistFailed'),
    );
  });
});

describe('ProfilePageView 静态渲染（展示帧 override 优先 + 持久化失败文案 + 编辑帧）', () => {
  const noop = () => {};

  function renderProfilePageView(
    overrides: Partial<
      Parameters<typeof profilePageMod.ProfilePageView>[0]
    > = {},
  ): string {
    return renderToStaticMarkup(
      createElement(profilePageMod.ProfilePageView, {
        status: 'success',
        profile: PROFILE_BASE,
        error: undefined,
        avatarPersistError: undefined,
        editing: false,
        draft: undefined,
        editStatus: 'idle',
        fieldError: undefined,
        editError: undefined,
        onEdit: noop,
        onCancelEdit: noop,
        onSaveEdit: noop,
        onDraftChange: noop,
        ...overrides,
      }),
    );
  }

  test('展示帧：只读项 + 编辑入口；extra 不暴露编辑入口（展示态本就没有）', () => {
    const html = renderProfilePageView();
    expect(html).toContain('zhang_san');
    expect(html).toContain('张三');
    expect(html).toContain('138****8000');
    expect(html).toContain('a***@example.com');
    expect(html).toContain('编辑资料');
    expect(html).not.toContain('扩展信息');
    // 头像入口：配置加载中（useRequest 未起 effect → status=idle）渲染禁用
    // 按钮而非隐藏（隐藏仅在配置就绪且零值投影时发生）。
    expect(html).toContain('更换头像');
    expect(html).toMatch(
      /<button[^>]*disabled[^>]*><span[^>]*>更换头像<\/span>/,
    );
  });

  test('展示帧布局：卡片两段（头像合并单一大头像 + 基本信息两列），只读项带标签，locale / timezone 可读文案', () => {
    const html = renderProfilePageView();
    // 卡片两段结构：基本信息段标题 + 头像段 @用户名句柄。
    expect(html).toContain('基本信息');
    expect(html).toContain('@zhang_san');
    // 只读小标签：用户名 / 手机号 / 邮箱三处（按 Tag 元素数断言；Tag 的
    // aria-label 与内容对同文本各渲染一次，按文本计数会翻倍）。
    expect(html.match(/class="semi-tag[ "]/g)?.length).toBe(3);
    expect(html).toContain('只读');
    // locale / timezone 由原值显示为可读文案（与下拉选项同一映射）。
    expect(html).toContain('简体中文 (zh-CN)');
    expect(html).toContain('Asia / Shanghai');
    // 组件内不重复渲染第二个大头像（按 Avatar 元素数断言，其修饰类
    // semi-avatar-extra-large 等共享前缀，按子串计数会翻倍）。
    expect(html.match(/class="semi-avatar[ "]/g)?.length).toBe(1);
  });

  test('头像竞态消除口径：保存成功重取先于持久化落地（服务端旧头像）时 override 保留优先展示，不回退', () => {
    const html = renderProfilePageView({
      avatarOverride: 'https://cdn.test/b.jpg',
    });
    expect(html).toContain('https://cdn.test/b.jpg');
    expect(html).not.toContain('https://cdn.test/a.jpg');
  });

  test('头像持久化失败：行内专属文案（不再复用通用「操作失败」）', () => {
    const html = renderProfilePageView({
      avatarPersistError: t('account.avatarPersistFailed'),
    });
    expect(html).toContain(t('account.avatarPersistFailed'));
  });

  test('编辑帧：Input 受控回显 + 三个下拉触发器渲染（locale / timezone 改可搜索 Select）+ 保存 / 取消；无 extra 编辑框', () => {
    const html = renderProfilePageView({
      editing: true,
      draft: profileDraft({ nickname: '张三丰' }),
    });
    // Input 类字段 SSR 即回显受控值（value 属性）；三个下拉（gender / locale /
    // timezone）触发器选中值在 effect 后回显，静态标记仅含 placeholder——
    // 选项集内容与现值兜底由选项纯函数用例覆盖（profileLocaleOptions 等）。
    expect(html).toContain('value="张三丰"');
    expect(html).not.toContain('value="zh-CN"');
    expect(html).not.toContain('value="Asia/Shanghai"');
    // placeholder 出现 3 处：birthday DatePicker + locale / timezone Select
    //（gender 触发器无 placeholder 文案）。
    expect(html.split('请选择').length - 1).toBe(3);
    expect(html).toContain('保存');
    expect(html).toContain('取消');
    expect(html).not.toContain('扩展信息');
  });

  test('编辑帧错误呈现：本地校验 birthday 专属文案；服务端错误 apiErrorText 归一', () => {
    const field = renderProfilePageView({
      editing: true,
      draft: profileDraft({}),
      fieldError: 'invalid_birthday',
    });
    expect(field).toContain('请输入正确的日期（YYYY-MM-DD）');
    const nickname = renderProfilePageView({
      editing: true,
      draft: profileDraft({}),
      fieldError: 'nickname_too_long',
    });
    expect(nickname).toContain(t('account.nicknameTooLong'));
    const server = renderProfilePageView({
      editing: true,
      draft: profileDraft({}),
      editStatus: 'error',
      editError: new ApiError({
        httpStatus: 400,
        code: 'invalid_argument',
        message: 'profile invalid',
        requestId: '',
      }),
    });
    expect(server).toContain(t('errors.code.invalid_argument'));
  });
});

// ---------------------------------------------------------------------------
// routes：HashRouter 路由表 + path:'*' 兜底（MemoryRouter
// 注入初始路径，模式无关；pathname 兜底断言已随 hash 化重写）
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// SecurityPageView 静态渲染（渠道可用性标志驱动绑定 / 换绑入口显隐）
// ---------------------------------------------------------------------------

describe('SecurityPageView 静态渲染（GetConfig 渠道可用性标志驱动手机号 / 邮箱绑定换绑入口）', () => {
  const noop = () => {};

  function renderSecurityPageView(
    flags: { sms: boolean; email: boolean },
    overrides: { hasPassword?: boolean } = {},
  ): string {
    const config = create(AccountConfigResponseSchema, {
      hasPassword: overrides.hasPassword ?? true,
      smsChannelAvailable: flags.sms,
      emailChannelAvailable: flags.email,
    }) as AccountConfigResponse;
    // SecurityPageView 子件（MfaSetting / ThirdPartyList）消费 useLocation，
    // 静态渲染需注入路由上下文（routes describe 同款 MemoryRouter）。
    return renderToStaticMarkup(
      createElement(
        MemoryRouter,
        { initialEntries: ['/security'] },
        createElement(securityPageMod.SecurityPageView, {
          status: 'success',
          config,
          error: undefined,
          onRefreshConfig: noop,
        }),
      ),
    );
  }

  // rowSegment 取指定行标题所在 <li> 片段：绑定入口断言按行隔离（MFA 因子
  // 行 / 三方账号行复用同一 account.bindAction 文案，全页计数会串扰）。
  function rowSegment(html: string, label: string): string {
    const idx = html.indexOf(`>${label}<`);
    expect(idx).toBeGreaterThan(-1);
    return html.slice(html.lastIndexOf('<li', idx), html.indexOf('</li>', idx));
  }

  test('两渠道均可用 → 手机号 / 邮箱两行各渲染一个绑定入口（未绑定为「去绑定」）', () => {
    const html = renderSecurityPageView({ sms: true, email: true });
    expect(rowSegment(html, '手机号')).toContain(t('account.goBindAction'));
    expect(rowSegment(html, '邮箱')).toContain(t('account.goBindAction'));
  });

  test('短信渠道未配置 → 手机号入口隐藏、邮箱入口保留（行本身仍展示）', () => {
    const html = renderSecurityPageView({ sms: false, email: true });
    expect(rowSegment(html, '手机号')).not.toContain(t('account.goBindAction'));
    expect(rowSegment(html, '邮箱')).toContain(t('account.goBindAction'));
  });

  test('两渠道均未配置 → 绑定 / 换绑入口全隐藏（行保留展示绑定态）', () => {
    const html = renderSecurityPageView({ sms: false, email: false });
    expect(html).toContain('手机号');
    expect(html).toContain('邮箱');
    // 换绑（已绑定态）与绑定共用同一守卫：contactExtra 先于绑定态分支整体
    // 返回 null——profile 由 GetProfile 运行期取，静态渲染链呈未绑定态，
    // 「换绑」文案在渠道可用且已绑定时才出现，故此处按不出现断言。
    expect(rowSegment(html, '手机号')).not.toContain(t('account.goBindAction'));
    expect(rowSegment(html, '邮箱')).not.toContain(t('account.goBindAction'));
    expect(html).not.toContain(t('account.rebindAction'));
  });

  test('未设密码用户在渠道未配置时同样隐藏「请先设置密码」提示（入口整体隐藏）', () => {
    const available = renderSecurityPageView(
      { sms: true, email: true },
      { hasPassword: false },
    );
    expect(rowSegment(available, '手机号')).toContain(
      t('account.setPasswordFirst'),
    );
    const unavailable = renderSecurityPageView(
      { sms: false, email: false },
      { hasPassword: false },
    );
    expect(rowSegment(unavailable, '手机号')).not.toContain(
      t('account.setPasswordFirst'),
    );
    expect(rowSegment(unavailable, '手机号')).not.toContain(
      t('account.goBindAction'),
    );
  });
});

describe("routes：HashRouter 路由表与 path:'*' 兜底", () => {
  function renderAccountApp(initialPath: string): string {
    return renderToStaticMarkup(
      createElement(
        MemoryRouter,
        { initialEntries: [initialPath] },
        createElement(routesMod.AccountApp),
      ),
    );
  }

  test("未知路径 → path:'*' 兜底：Semi Empty 文案 + hash 内返回链接", () => {
    const html = renderAccountApp('/does-not-exist');
    expect(html).toContain('页面不存在');
    expect(html).toContain('返回个人中心');
    expect(html).toContain('href="#/"');
    expect(html).toContain('semi-empty');
  });

  test('已知路径 /security → 不被兜底吞掉（渲染安全中心，无兜底文案）', () => {
    const html = renderAccountApp('/security');
    expect(html).not.toContain('页面不存在');
    expect(html).toContain('安全中心');
  });

  test('hash 内 query 不影响路由匹配（/security?bind=success 仍命中安全中心）', () => {
    const html = renderAccountApp('/security?bind=success');
    expect(html).not.toContain('页面不存在');
    expect(html).toContain('安全中心');
  });
});

// ---------------------------------------------------------------------------
// accountReturnTo（四处 401 跳登录带 returnTo）
// ---------------------------------------------------------------------------

describe('accountReturnTo（401 跳登录 returnTo 白名单形态，纯函数）', () => {
  test('hash 内路径 + query 拼为 /account# 前缀形态', () => {
    expect(apiMod.accountReturnTo('/', '')).toBe('/account#/');
    expect(apiMod.accountReturnTo('/security', '')).toBe('/account#/security');
    expect(apiMod.accountReturnTo('/security', '?bind=success')).toBe(
      '/account#/security?bind=success',
    );
    expect(apiMod.accountReturnTo('/audit', '')).toBe('/account#/audit');
  });

  test('401 跳转 URL：loginUrl 拼装后含编码 returnTo，解码后以 /account# 开头且过白名单', () => {
    const returnTo = apiMod.accountReturnTo('/security', '?bind=x');
    const url = loginUrl('https://uc.example.com', returnTo);
    expect(url).toContain('/sso/login?returnTo=');
    const encoded = url.slice(url.indexOf('returnTo=') + 'returnTo='.length);
    expect(encoded).not.toContain('/account#'); // 已编码（# → %23）
    expect(decodeURIComponent(encoded).startsWith('/account#')).toBe(true);
    // 白名单校验（sanitizeReturnTo 仅放行 /account# / /admin# 前缀）原样放行。
    expect(sanitizeReturnTo(decodeURIComponent(encoded))).toBe(returnTo);
  });
});

// ---------------------------------------------------------------------------
// isRecoveryLow（恢复码低余量行内提示阈值判定，纯函数）
// ---------------------------------------------------------------------------

describe('isRecoveryLow / RECOVERY_LOW_THRESHOLD（纯函数）', () => {
  test('recovery_code 已绑定且剩余 ≤ 2 → true；> 2 → false', () => {
    expect(
      apiMod.isRecoveryLow(
        create(MfaFactorSchema, {
          factor: 'recovery_code',
          bound: true,
          remaining: BigInt(2),
        }),
      ),
    ).toBe(true);
    expect(
      apiMod.isRecoveryLow(
        create(MfaFactorSchema, {
          factor: 'recovery_code',
          bound: true,
          remaining: BigInt(0),
        }),
      ),
    ).toBe(true);
    expect(
      apiMod.isRecoveryLow(
        create(MfaFactorSchema, {
          factor: 'recovery_code',
          bound: true,
          remaining: BigInt(3),
        }),
      ),
    ).toBe(false);
    expect(apiMod.RECOVERY_LOW_THRESHOLD).toBe(2);
  });

  test('未绑定 / 非 recovery_code 因子 → false', () => {
    expect(
      apiMod.isRecoveryLow(
        create(MfaFactorSchema, {
          factor: 'recovery_code',
          bound: false,
          remaining: BigInt(0),
        }),
      ),
    ).toBe(false);
    expect(
      apiMod.isRecoveryLow(
        create(MfaFactorSchema, {
          factor: 'webauthn',
          bound: true,
          credentials: BigInt(1),
        }),
      ),
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// MfaSetting 静态渲染（两步验证开关行 + TOTP 因子行：已绑定 → 解绑 /
// 恢复码查看；未绑定 → 绑定；弹窗条件渲染不挂载）
// ---------------------------------------------------------------------------

describe('MfaSetting 静态渲染（开关行 + TOTP 因子行）', () => {
  const noop = () => {};
  // 组件经 useLocation 取 401 returnTo（集中 onError），静态渲染须包
  // MemoryRouter（HashRouter 下 useLocation 即 hash 内 location）。
  function MfaRow(props: { methods: MfaPolicyMethod[] }) {
    return createElement(SettingList, {
      fields: [
        mfaSettingMod.useMfaToggleField({
          enabled: false,
          methods: props.methods,
          onPolicyRefresh: noop,
        }),
        mfaSettingMod.useMfaSetting({ ...props, onPolicyRefresh: noop }),
      ],
    });
  }
  const renderRow = (methods: MfaPolicyMethod[]): string =>
    renderToStaticMarkup(
      createElement(MemoryRouter, {}, createElement(MfaRow, { methods })),
    );
  const totp = (bound: boolean): MfaPolicyMethod =>
    create(MfaPolicyMethodSchema, { factor: 'totp', bound });

  test('totp 已绑定 → 开关行标题 + 「已绑定」+ 解绑 / 重新生成（行内，无「查看存量码」入口）', () => {
    const html = renderRow([totp(true)]);
    expect(html).toContain('两步验证');
    expect(html).toContain('已绑定');
    expect(html).toContain('解绑');
    expect(html).toContain('重新生成');
    // Popconfirm 确认文案为懒挂载浮层，静态渲染不产出。
    expect(html).not.toContain('恢复码仅一次性展示，不可回显');
  });

  test('totp 未绑定 → 「未绑定」+ 去绑定；不展示重新生成入口与绑定弹窗，开关行禁用提示渲染', () => {
    const html = renderRow([totp(false)]);
    expect(html).toContain('未绑定');
    expect(html).toContain('去绑定');
    expect(html).toContain('请先绑定至少一个可用的验证方式');
    expect(html).not.toContain('重新生成');
    // 结构性断言：TotpBindDialog / 恢复码 Modal 父级条件渲染——未打开不挂载。
    expect(html).not.toContain('绑定 TOTP 动态码');
  });

  test('methods 无 totp 条目 → 因子行按未绑定兜底，开关行系统未开放提示渲染', () => {
    const html = renderRow([]);
    expect(html).toContain('未绑定');
    expect(html).toContain('管理员未启用两步验证');
    expect(html).not.toContain('重新生成');
  });
});

// ---------------------------------------------------------------------------
// 跨端切换：权限点可见性 / 菜单构造纯函数 + 纯视图 SSR
// ---------------------------------------------------------------------------

describe('跨端切换（权限点可见性 + 菜单构造，零 Semi 纯函数）', () => {
  test('canSwitchToAdmin：permissions.length > 0；空 / 缺省为 false；判定不用 isAdmin', () => {
    expect(apiMod.canSwitchToAdmin([])).toBe(false);
    expect(apiMod.canSwitchToAdmin(undefined)).toBe(false);
    expect(apiMod.canSwitchToAdmin(['superadmin'])).toBe(true);
    // 若实现误读 isAdmin 布尔标记，此用例变红。
    expect(
      apiMod.canSwitchToAdmin({ isAdmin: true } as unknown as string[]),
    ).toBe(false);
  });

  test('buildAccountHeaderMenu：空权限 → 仅登出；非空 → 含切换项', () => {
    const empty = apiMod.buildAccountHeaderMenu(
      'https://uc.test',
      [],
      () => {},
    );
    expect(empty).toHaveLength(1);
    expect(empty[0].name).toBe('退出登录');
    const full = apiMod.buildAccountHeaderMenu(
      'https://uc.test',
      ['perm'],
      () => {},
    );
    expect(full).toHaveLength(2);
    expect(full[1].name).toBe('切换到管理后台');
  });

  test('跳转动作经注入记录函数：目标 URL 正确且未跳站外', () => {
    const recorded: string[] = [];
    const redirect = (url: string): void => {
      recorded.push(url);
    };
    const items = apiMod.buildAccountHeaderMenu(
      'https://uc.test',
      ['perm'],
      redirect,
    );
    items[0].onClick();
    items[1].onClick();
    expect(recorded).toEqual([
      'https://uc.test/sso/logout',
      'https://uc.test/admin#/status',
    ]);
    expect(recorded.every((url) => !url.includes('evil.example.com'))).toBe(
      true,
    );
  });
});

describe('跨端切换纯视图 SSR（不对真实 Layout 做 DOM 点击断言）', () => {
  function HeaderMenuView(props: { items: { name: string }[] }) {
    return createElement(
      'ul',
      null,
      ...props.items.map((item) =>
        createElement('li', { key: item.name }, item.name),
      ),
    );
  }

  test('切换文案随 permissions 出现 / 不出现', () => {
    const withPerm = renderToStaticMarkup(
      createElement(HeaderMenuView, {
        items: apiMod.buildAccountHeaderMenu('', ['perm'], () => {}),
      }),
    );
    expect(withPerm).toContain('切换到管理后台');
    const noPerm = renderToStaticMarkup(
      createElement(HeaderMenuView, {
        items: apiMod.buildAccountHeaderMenu('', [], () => {}),
      }),
    );
    expect(noPerm).not.toContain('切换到管理后台');
    expect(noPerm).toContain('退出登录');
  });
});

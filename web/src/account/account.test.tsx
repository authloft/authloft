// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化后移除）。
// @ts-ignore
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, rs, test } from 'rstack/test';
import * as React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { create, toJson, type JsonObject } from '@bufbuild/protobuf';
import {
  AvatarUploadConfigSchema,
  CommitAvatarRequestSchema,
  MfaPolicyMethodSchema,
  PresignAvatarRequestSchema,
  ProfileResponseSchema,
  UpdateProfileRequestSchema,
  UserProfileSchema,
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
import { CaptchaPayloadSchema } from '../gen/proto/api/sso/v1/login_pb';
import { CreateQrcodeRequestSchema } from '../gen/proto/api/sso/v1/ticket_pb';
import {
  GetEventsRequestSchema,
  GetThirdpartyTicketRequestSchema,
  ThirdpartyBindingSchema,
  ThirdpartyOptionSchema,
  UnbindThirdpartyRequestSchema,
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
import type { QRPanelPhase } from '../shared/components/QRCodePanel';
import { ApiError } from '../shared/api/errors';
import { t } from '../shared/i18n';

/**
 * account 底座 + 安全中心测试。覆盖边界（既定口径「覆盖
 * 路由渲染 + api 封装 msw」的当前可运行子集）：
 * - bootstrap：注入变量读取 / 归一 / loginUrl / logoutUrl（§5 行 478 / §8）；
 * - api.getProfile：msw 走真实 transport 归一链（§3.2 行 819）；
 * - isUnauthenticatedError：401 判定纯函数（§5 行 480）；
 * - 安全中心族：GetConfig / ChangePassword / BindPhone / BindEmail /
 *   PresignAvatar / CommitAvatar 封装（msw 真实 transport 归一链）、
 *   proxy 直传 uploadAvatarProxy（FakeXhr，复用 shared/api/http.test.ts 桩
 *   模式）、头像两模式编排 uploadAvatarFile（§10.8：direct 三步走 + proxy
 *   得 url + 超限 / 类型预校验文案与后端一致，前端架构 §8.2 行 648）、表单
 *   请求构造纯函数（buildChangePasswordRequest / buildBind 系）、apiErrorText。
 *   薄封装经 account/api 转发自 shared/api/account（getConfig
 *   等仍走 apiMod）；上传编排 / 预校验直引新落位 shared/hooks/useUpload
 *   （uploadMod，被测对象移位、断言零改动）。
 * - MFA + 通行密钥族：GetMfa / SetMfa（buildSetMfaRequest：追加 /
 *   移除 / required 锁死）/ BindTotp 两步（challenge wire 省略零值 + verify
 *   回传 secret）/ GetRecoveryCodes / RegenerateRecoveryCodes（action=
 *   regenerate）/ GetWebauthnCredentials 解码；registerWebauthnCredential
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
 * - UpdateProfile 资料编辑 + 头像持久化（§3.2 行 837；后端 account 域
 *   桩未实装，契约先行口径：按接口契约消费 + msw mock，不因 mock 放宽契约）：
 *   updateProfile 封装 msw（成功 OkResponse 空响应 / 校验失败 400 Connect
 *   错误体归一 ApiError）+ buildUpdateProfileRequest PATCH 语义纯函数（diff
 *   基线 → 只带编辑过字段 / wire 零值省略契约限制 / birthday + extra 本地
 *   校验）+ buildAvatarPersistRequest（头像持久化接线：AvatarUploader
 *   onUploaded 后 {avatarUrl} 单字段提交）+ profileGenderText 展示映射；
 *   ProfilePageView 编辑帧渲染测试受工具链 blocker（本文件头【Blocker】
 *   段），表单交互的可测逻辑即构造函数（本段）。
 *
 * 【Blocker·已解除】routes / AppLayout / ProfilePage / SecurityPage / 表单组件的渲染
 * 测试曾在本工具链下无法落地：@douyinfe/semi-ui-19 的 lib/es 内部为无扩展名
 * import，node 原生 ESM 无法加载，rstest 0.12.5 对其 externalize（rs.mock /
 * __mocks__ 均为运行时机制，拦不住编译图对 external 包的链接期加载）→ 任何
 * 模块图含 semi import 的测试文件都在加载期崩（实测：rs.mock 全组件 /
 * __mocks__ 目录 / 子路径 import 三路都试过）。**测试链已修复**
 * （rstack.config.mts define.test bundleDependencies + ProvidePlugin，Semi 经
 * rspack 管线加载），路由兜底真渲染断言见文末 routes describe；表单组件的
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
const GET_MFA_URL = `${BASE}/api.account.v1.AccountService/GetMfa`;
const SET_MFA_URL = `${BASE}/api.account.v1.AccountService/SetMfa`;
const BIND_TOTP_URL = `${BASE}/api.account.v1.AccountService/BindTotp`;
const GET_RECOVERY_CODES_URL = `${BASE}/api.account.v1.AccountService/GetRecoveryCodes`;
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
const TEN_RECOVERY_CODES = Array.from({ length: 10 }, (_, i) => `a1${i}b-c3d${i}`);

const server = setupServer();

/**
 * 极简 XHR 桩（复用 shared/api/http.test.ts 模式）：proxy 直传分支
 * （postForm 走 XMLHttpRequest，node 无原生实现）；send 同步回放
 * nextResponse 并补 upload progress 回放。
 */
class FakeXhr {
  static nextResponse: { status: number; body: string } | null = null;

  static respondWith(status: number, body: string): void {
    FakeXhr.nextResponse = { status, body };
  }

  onabort: (() => void) | null = null;
  ontimeout: (() => void) | null = null;
  onerror: (() => void) | null = null;
  onload: (() => void) | null = null;
  upload: { onprogress: ((event: unknown) => void) | null } = { onprogress: null };
  withCredentials = false;
  timeout = 0;
  status = 0;
  statusText = '';
  responseText = '';

  getResponseHeader(_name: string): string | null {
    return null;
  }

  abort(): void {
    this.onabort?.();
  }

  open(_method: string, _url: string): void {}

  send(_formData: FormData): void {
    this.upload.onprogress?.({ loaded: 1, total: 2, lengthComputable: true });
    const response = FakeXhr.nextResponse;
    if (!response) {
      this.onerror?.();
      return;
    }
    this.status = response.status;
    this.responseText = response.body;
    this.onload?.();
  }
}

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
let uploadMod: typeof import('../shared/hooks/useUpload');
let routesMod: typeof import('./routes');

beforeAll(async () => {
  server.listen({ onUnhandledRequest: 'error' });
  bootstrapMod = await import('./bootstrap');
  apiMod = await import('./api');
  ssoMod = await import('../shared/api/sso');
  uploadMod = await import('../shared/hooks/useUpload');
  routesMod = await import('./routes');
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
  FakeXhr.nextResponse = null;
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
        new ApiError({ httpStatus: 401, code: 'unauthenticated', message: '', requestId: '' }),
      ),
    ).toBe(true);
    expect(
      apiMod.isUnauthenticatedError(
        new ApiError({ httpStatus: 401, code: 'session_required', message: '', requestId: '' }),
      ),
    ).toBe(true);
    expect(
      apiMod.isUnauthenticatedError(
        new ApiError({ httpStatus: 403, code: 'unauthenticated', message: '', requestId: '' }),
      ),
    ).toBe(true);
  });

  test('其他 ApiError / 非错误对象 → false', () => {
    expect(
      apiMod.isUnauthenticatedError(
        new ApiError({ httpStatus: 403, code: 'permission_denied', message: '', requestId: '' }),
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
            required: false,
            trustedDeviceDays: '0',
            methods: [
              { factor: 'totp', enabled: true, bound: true },
              { factor: 'otp_email', enabled: false, bound: false },
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
    expect(config.avatarUpload?.allowedTypes).toEqual(['image/png', 'image/jpeg']);
    expect(config.mfaPolicy?.enabled).toBe(true);
    expect(config.mfaPolicy?.required).toBe(false);
    expect(config.mfaPolicy?.trustedDeviceDays).toBe(BigInt(0)); // 预留恒 0（§3.2 行 847）
    expect(config.mfaPolicy?.methods[0]?.factor).toBe('totp');
    expect(config.mfaPolicy?.methods[0]?.enabled).toBe(true);
    expect(config.mfaPolicy?.methods[0]?.bound).toBe(true);
    expect(config.mfaPolicy?.methods[1]?.factor).toBe('otp_email');
    expect(config.captcha?.providerKey).toBe('builtin_image');
    expect(config.captcha?.type).toBe('image');
    expect(config.captcha?.siteKey).toBe('');
    expect(config.hasPassword).toBe(true);
  });

  test('零值投影（§3.2 行 826）：protojson 省略零值 → maxSize 0n / allowedTypes [] → 隐藏上传入口', async () => {
    server.use(
      http.post(CONFIG_URL, () =>
        HttpResponse.json({ avatarUpload: { mode: 'proxy' }, hasPassword: false }),
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

    const built = apiMod.buildChangePasswordRequest(true, 'OldPass12', 'NewPass12');
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
  test('challenge：{step, payload:{phone, captcha}}——自绘 captcha 三元组零值省略 token（§2.5 行 503-506）', async () => {
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
    const built = apiMod.buildBindChallengeRequest('phone', '13800138000', captcha);
    expect(built.ok).toBe(true);
    if (!built.ok) {
      throw new Error('unreachable');
    }

    await apiMod.bindPhone(built.request as BindPhoneRequest);

    expect(await captured.json()).toEqual({
      step: 'challenge',
      payload: {
        phone: '13800138000',
        captcha: { providerKey: 'builtin_image', id: 'cap-1', answer: '1234' },
      },
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

    const built = apiMod.buildBindVerifyRequest('email', 'a@example.com', '123456');
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
// api.uploadAvatarProxy（§3.2 行 821 proxy 直传，REST 豁免）
// ---------------------------------------------------------------------------

describe('api.uploadAvatarProxy（§3.2 行 821 proxy 直传，REST 豁免）', () => {
  test('postForm multipart → AvatarResponse 解码 + onUploadProgress 透传', async () => {
    rs.stubGlobal('XMLHttpRequest', FakeXhr);
    FakeXhr.respondWith(200, JSON.stringify({ url: 'https://cdn.test/proxy.png' }));

    const progress: Array<{ loaded: number; total: number }> = [];
    const result = await apiMod.uploadAvatarProxy(new FormData(), (p) => progress.push(p));

    expect(result.url).toBe('https://cdn.test/proxy.png');
    expect(progress).toEqual([{ loaded: 1, total: 2 }]);
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
    const built = apiMod.buildChangePasswordRequest(false, 'whatever', 'Abcdef12');
    expect(built.ok).toBe(true);
    if (!built.ok) {
      throw new Error('unreachable');
    }
    expect(built.request.currentPassword).toBe('');
    expect(built.request.newPassword).toBe('Abcdef12');
  });

  test('hasPassword=true 通过：两字段齐备', () => {
    const built = apiMod.buildChangePasswordRequest(true, 'OldPass12', 'NewPass12');
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
    expect(apiMod.buildBindChallengeRequest('email', 'not-an-email', captcha)).toEqual({
      ok: false,
      error: 'invalid_target',
    });
  });

  test('captcha 未就绪 → captcha_missing（§3.4 行 880 challenge 必过，不发包）', () => {
    expect(apiMod.buildBindChallengeRequest('phone', '13800138000', undefined)).toEqual({
      ok: false,
      error: 'captcha_missing',
    });
  });

  test('phone challenge 就绪：step / payload 透传（captcha 引用恒等）', () => {
    const built = apiMod.buildBindChallengeRequest('phone', '13800138000', captcha);
    expect(built.ok).toBe(true);
    if (!built.ok) {
      throw new Error('unreachable');
    }
    expect(built.request.$typeName).toBe('api.account.v1.BindPhoneRequest');
    const request = built.request as BindPhoneRequest;
    expect(request.step).toBe('challenge');
    expect(request.payload?.phone).toBe('13800138000');
    expect(request.payload?.captcha).toBe(captcha);
  });

  test('email challenge 就绪：payload.email', () => {
    const built = apiMod.buildBindChallengeRequest('email', 'a@example.com', captcha);
    expect(built.ok).toBe(true);
    if (!built.ok) {
      throw new Error('unreachable');
    }
    expect(built.request.$typeName).toBe('api.account.v1.BindEmailRequest');
    expect((built.request as BindEmailRequest).payload?.email).toBe('a@example.com');
  });

  test('verify：非 6 位 / 非数字 → invalid_code；就绪回传相同 target + code（行 881-882）', () => {
    expect(apiMod.buildBindVerifyRequest('phone', '13800138000', '12345')).toEqual({
      ok: false,
      error: 'invalid_code',
    });
    expect(apiMod.buildBindVerifyRequest('phone', '13800138000', '12345a')).toEqual({
      ok: false,
      error: 'invalid_code',
    });
    const built = apiMod.buildBindVerifyRequest('phone', '13800138000', '123456');
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
    expect(uploadMod.isUploadEntryHidden(create(AvatarUploadConfigSchema, { mode: 'proxy' }))).toBe(
      true,
    );
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
    expect(uploadMod.validateAvatarFile(config, { size: 101, type: 'image/png' })).toBe(
      'file_too_large',
    );
    expect(uploadMod.validateAvatarFile(config, { size: 50, type: 'image/gif' })).toBe(
      'file_type_not_allowed',
    );
    expect(uploadMod.validateAvatarFile(config, { size: 50, type: 'image/png' })).toBe(undefined);
  });

  test('uploadAvatarFile 预校验失败：抛 code 与后端一致的 ApiError，文案同源 i18n 字典', async () => {
    const config = create(AvatarUploadConfigSchema, {
      mode: 'proxy',
      maxSize: BigInt(100),
      allowedTypes: ['image/png'],
    });

    const oversize = new File([new Uint8Array(101)], 'a.png', { type: 'image/png' });
    const tooLargeError = (await captureRejection(
      uploadMod.uploadAvatarFile(config, oversize),
    )) as ApiError;
    expect(tooLargeError).toBeInstanceOf(ApiError);
    expect(tooLargeError.code).toBe('file_too_large');

    const wrongType = new File([new Uint8Array(10)], 'a.gif', { type: 'image/gif' });
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
    const file = new File([new Uint8Array(2048)], 'a.png', { type: 'image/png' });

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

  test('proxy 模式（mock GetConfig）：postForm 得 url + 进度透传（§10.8 / §8.2 行 648）', async () => {
    server.use(
      http.post(CONFIG_URL, () =>
        HttpResponse.json({
          avatarUpload: { mode: 'proxy', maxSize: '2097152', allowedTypes: ['image/png'] },
        }),
      ),
    );
    rs.stubGlobal('XMLHttpRequest', FakeXhr);
    FakeXhr.respondWith(200, JSON.stringify({ url: 'https://cdn.test/proxy.png' }));

    const config = await apiMod.getConfig();
    const avatarUpload = config.avatarUpload;
    if (avatarUpload === undefined) {
      throw new Error('GetConfig 未下发 avatarUpload');
    }
    expect(uploadMod.isUploadEntryHidden(avatarUpload)).toBe(false);

    const progress: Array<{ loaded: number; total: number }> = [];
    const url = await uploadMod.uploadAvatarFile(
      avatarUpload,
      new File([new Uint8Array(8)], 'a.png', { type: 'image/png' }),
      undefined,
      (p) => progress.push(p),
    );

    expect(url).toBe('https://cdn.test/proxy.png');
    expect(progress).toEqual([{ loaded: 1, total: 2 }]);
  });
});

// ---------------------------------------------------------------------------
// apiErrorText（§1.5 行 202 i18n 优先 + 语境覆盖）
// ---------------------------------------------------------------------------

describe('apiErrorText（§1.5 行 202 i18n 优先 + 语境覆盖）', () => {
  test('ApiError → errors.code.<code> 字典文案', () => {
    expect(
      apiMod.apiErrorText(
        new ApiError({ httpStatus: 400, code: 'password_weak', message: 'x', requestId: '' }),
      ),
    ).toBe('密码强度不足，请调整后重试');
    expect(
      apiMod.apiErrorText(
        new ApiError({ httpStatus: 409, code: 'target_taken', message: 'x', requestId: '' }),
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
        new ApiError({ httpStatus: 400, code: 'weird_code', message: '内部细节', requestId: '' }),
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
            { factor: 'totp', bound: true, boundAt: '1761800000', lastUsedAt: '1761800500' },
            { factor: 'otp_sms', bound: true, target: '138****8000', lastUsedAt: '1761800500' },
            { factor: 'otp_email', bound: false },
            { factor: 'webauthn', bound: true, credentials: '2', lastUsedAt: '1761800500' },
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
// api.setMfa + buildSetMfaRequest（§3.5 行 904 / §3.2 行 833）
// ---------------------------------------------------------------------------

describe('api.setMfa / buildSetMfaRequest（§3.5 行 904）', () => {
  /** 摘要样例：totp 启用已绑、otp_sms 未启用已绑、otp_email 均否。 */
  const methods = [
    create(MfaPolicyMethodSchema, { factor: 'totp', enabled: true, bound: true }),
    create(MfaPolicyMethodSchema, { factor: 'otp_sms', enabled: false, bound: true }),
    create(MfaPolicyMethodSchema, { factor: 'otp_email', enabled: false, bound: false }),
  ];

  test('勾选启用 → 追加到启用集尾（保持其余因子既有顺序，行 904 勾选启用一项或多项）', async () => {
    let captured!: Request;
    server.use(
      http.post(SET_MFA_URL, ({ request }) => {
        captured = request;
        return HttpResponse.json({});
      }),
    );

    const built = apiMod.buildSetMfaRequest(methods, 'otp_sms', true, false);
    expect(built.ok).toBe(true);
    if (!built.ok) {
      throw new Error('unreachable');
    }

    await apiMod.setMfa(built.request);

    expect(await captured.json()).toEqual({ methods: ['totp', 'otp_sms'] });
  });

  test('取消最后一个启用因子（required=false）→ 空数组=关闭：wire 省略零值输出 {}', async () => {
    let captured!: Request;
    server.use(
      http.post(SET_MFA_URL, ({ request }) => {
        captured = request;
        return HttpResponse.json({});
      }),
    );

    const single = [
      create(MfaPolicyMethodSchema, { factor: 'totp', enabled: true, bound: true }),
    ];
    const built = apiMod.buildSetMfaRequest(single, 'totp', false, false);
    expect(built.ok).toBe(true);
    if (!built.ok) {
      throw new Error('unreachable');
    }

    await apiMod.setMfa(built.request);

    // protojson 省略空 repeated（§12.9 行 1752）→ 空数组=关闭在 wire 上即 {}。
    expect(await captured.json()).toEqual({});
    expect(built.request.methods).toEqual([]);
  });

  test('required=true：结果为空 → 本地拒绝不发包（§3.2 行 833 不可关闭）；结果非空 → 放行', () => {
    const single = [
      create(MfaPolicyMethodSchema, { factor: 'totp', enabled: true, bound: true }),
    ];
    expect(apiMod.buildSetMfaRequest(single, 'totp', false, true)).toEqual({
      ok: false,
      error: 'mfa_required_locked',
    });
    // required 下换因子（先启用 otp_sms 再关 totp 的第一步）：结果非空 → 放行
    const two = [
      create(MfaPolicyMethodSchema, { factor: 'totp', enabled: true, bound: true }),
      create(MfaPolicyMethodSchema, { factor: 'otp_sms', enabled: false, bound: true }),
    ];
    const swap = apiMod.buildSetMfaRequest(two, 'otp_sms', true, true);
    expect(swap.ok).toBe(true);
    if (!swap.ok) {
      throw new Error('unreachable');
    }
    expect(swap.request.methods).toEqual(['totp', 'otp_sms']);
  });

  test('重复启用 → 启用集不重复', () => {
    const built = apiMod.buildSetMfaRequest(methods, 'totp', true, false);
    expect(built.ok).toBe(true);
    if (!built.ok) {
      throw new Error('unreachable');
    }
    expect(built.request.methods).toEqual(['totp']);
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
          otpauthUrl: 'otpauth://totp/Authloft:zhang_san?secret=JBSWY3DPEHPK3PXP&issuer=Authloft',
          qrcodeContent: 'otpauth://totp/Authloft:zhang_san?secret=JBSWY3DPEHPK3PXP&issuer=Authloft',
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

    expect(await captured.json()).toEqual({ step: 'verify', secret: 'sec', code: '123456' });
    expect(res.recoveryCodes).toHaveLength(10); // 一次性下发 10 个恢复码
    expect(res.recoveryCodes[0]).toBe('a10b-c3d0');
  });
});

// ---------------------------------------------------------------------------
// api.getRecoveryCodes / regenerateRecoveryCodes（§3.5 行 907-908）
// ---------------------------------------------------------------------------

describe('api.getRecoveryCodes / regenerateRecoveryCodes（§3.5 行 907-908）', () => {
  test('查看解码 {codes, createdAt}；重新生成 wire {action:"regenerate"} → 新码同格式', async () => {
    let captured!: Request;
    server.use(
      http.post(GET_RECOVERY_CODES_URL, () =>
        HttpResponse.json({ codes: TEN_RECOVERY_CODES, createdAt: '1761700000' }),
      ),
      http.post(REGEN_RECOVERY_CODES_URL, ({ request }) => {
        captured = request;
        return HttpResponse.json({
          codes: TEN_RECOVERY_CODES.map((c) => `new-${c}`),
          createdAt: '1761900000',
        });
      }),
    );

    const view = await apiMod.getRecoveryCodes();
    expect(view.codes).toHaveLength(10);
    expect(view.createdAt).toBe(BigInt(1761700000));

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

    await apiMod.renameWebauthnCredential(apiMod.buildRenameWebauthnRequest(BigInt(101), '新名字'));
    await apiMod.deleteWebauthnCredential(apiMod.buildDeleteWebauthnRequest(BigInt(101)));

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
    expect(apiMod.formatUnixTime(BigInt(1761800000))).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$/);
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
        create(MfaFactorSchema, { factor: 'webauthn', bound: true, credentials: BigInt(2) }),
        fmt,
      ),
    ).toBe('已绑定 2 个凭据'); // lastUsedAt 零值省略
    expect(
      apiMod.mfaFactorDetail(
        create(MfaFactorSchema, { factor: 'recovery_code', bound: true, remaining: BigInt(8) }),
        fmt,
      ),
    ).toBe('剩余 8 个可用');
    expect(
      apiMod.mfaFactorDetail(create(MfaFactorSchema, { factor: 'otp_email', bound: false }), fmt),
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
            { providerKey: 'qq', displayName: 'QQ', type: 'qq', channel: 'redirect', icon: '', createdAt: '1761800000' },
            { providerKey: 'wechat_union', displayName: '微信联合身份', type: 'union', channel: 'redirect', icon: '', createdAt: '1761800001' },
          ],
          available: [
            { providerKey: 'wechat_mp_scan', displayName: '微信扫码', type: 'wechat_mp_scan', channel: 'qrcode', icon: '', uiGroup: 'social', sortOrder: '20' },
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

    const res = await apiMod.unbindThirdparty(apiMod.buildUnbindThirdpartyRequest('qq'));

    expect(await captured.json()).toEqual({ providerKey: 'qq' });
    expect(res.$typeName).toBe('api.account.v1.OkResponse');
  });

  test('getThirdpartyTicket → {ticket, poll:"15"} wire（§2.8 行 714 上限）+ 信封 .bind 解码（行 1024）', async () => {
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

    expect(await captured.json()).toEqual({ ticket: 'tk-1', poll: '15' }); // int64 → 十进制字符串（§1.12）
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
        return HttpResponse.json({ authorizeUrl: 'https://qq.example/auth?state=b-x1' });
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
    const items = [bindingRow({ providerKey: 'qq' }), bindingRow({ providerKey: 'feishu' })];
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
      create(ThirdpartyOptionSchema, { providerKey: 'b', displayName: 'B', type: 'b', channel: 'qrcode', icon: '', uiGroup: 'social', sortOrder: BigInt(20) }),
      create(ThirdpartyOptionSchema, { providerKey: 'a', displayName: 'A', type: 'a', channel: 'redirect', icon: '', uiGroup: 'social', sortOrder: BigInt(10) }),
      create(ThirdpartyOptionSchema, { providerKey: 'c', displayName: 'C', type: 'c', channel: 'redirect', icon: '', uiGroup: 'social', sortOrder: BigInt(20) }),
    ];
    const sorted = apiMod.sortThirdpartyOptions(options);
    expect(sorted.map((o) => o.providerKey)).toEqual(['a', 'b', 'c']); // b/c 同值 → 数组序稳定
  });
});

describe('buildCreateQrcodeBindRequest / buildGetThirdpartyTicketRequest / buildUnbindThirdpartyRequest（§3.7.1 B，纯函数）', () => {
  test('CreateQrcode 请求：scene 固定 bind + captcha 透传（行 993 / §2.8 行 703）', () => {
    const captcha = create(CaptchaPayloadSchema, {
      providerKey: 'cf_turnstile',
      token: '0.xxx',
    });
    const request = apiMod.buildCreateQrcodeBindRequest('wechat_mp_scan', captcha);
    expect(toJson(CreateQrcodeRequestSchema, request)).toEqual({
      providerKey: 'wechat_mp_scan',
      scene: 'bind',
      captcha: { providerKey: 'cf_turnstile', token: '0.xxx' }, // id/answer 零值省略
    });
  });

  test('GetThirdpartyTicket 请求：poll 固定 15（§2.8 行 714 上限，与面板 pollSeconds 同值）', () => {
    expect(
      toJson(GetThirdpartyTicketRequestSchema, apiMod.buildGetThirdpartyTicketRequest('tk-3')),
    ).toEqual({
      ticket: 'tk-3',
      poll: '15',
    });
  });

  test('UnbindThirdparty 请求：{providerKey}（行 937）', () => {
    expect(
      toJson(UnbindThirdpartyRequestSchema, apiMod.buildUnbindThirdpartyRequest('qq')),
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
          throw new ApiError({ httpStatus: 500, code: 'internal', message: '', requestId: '' });
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
        HttpResponse.json({ authorizeUrl: 'https://qq.example/auth?state=b-default' }),
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
    expect(apiMod.bindParamMessage('target_taken')).toBe('该账号已被其他账号绑定');
    expect(apiMod.bindParamMessage('target_taken')).not.toBe(t('errors.code.target_taken')); // 非联系方式通用文案
  });

  test('bindParamMessage：其余按 §1.6 位置二出文案；未知码 unknown 兜底（行 272）', () => {
    expect(apiMod.bindParamMessage('state_mismatch')).toBe(t('errors.code.state_mismatch'));
    expect(apiMod.bindParamMessage('weird_code')).toBe(t('errors.code.unknown'));
  });
});

describe('bindPollPhase（§3.7.1 B 行 1028，纯函数）', () => {
  test('failed + 最近轮询 status=target_taken → 语境文案替换通用文案', () => {
    const phase: QRPanelPhase = { kind: 'failed', message: t('errors.status.target_taken') };
    expect(apiMod.bindPollPhase(phase, 'target_taken')).toEqual({
      kind: 'failed',
      message: '该账号已被其他账号绑定',
    });
  });

  test('failed + 其他 status → 原样透传（qrFailureText 通用文案，§1.6 出文案口径）', () => {
    const phase: QRPanelPhase = { kind: 'failed', message: t('errors.status.provider_disabled') };
    expect(apiMod.bindPollPhase(phase, 'provider_disabled')).toBe(phase);
  });

  test('非 failed 帧原样引用返回——pending / scanned / expired / success 流转不受影响（面板四态流转约束）', () => {
    const phases: QRPanelPhase[] = [
      { kind: 'fetching' },
      { kind: 'active', qrcodeUrl: 'https://cdn.test/qr.jpg', ticketStatus: 'scanned' },
      { kind: 'success' },
      { kind: 'expired' },
    ];
    for (const phase of phases) {
      expect(apiMod.bindPollPhase(phase, 'target_taken')).toBe(phase);
    }
  });
});

// ---------------------------------------------------------------------------
// 日志族：GetEvents 封装 + 请求构造（§3.7 行 1041 / §1.7 行 275-278）
// ---------------------------------------------------------------------------

/** 受控查询状态样例（EventLogTable 初始态：created_at desc）。 */
const LOG_QUERY = {
  page: 1,
  pageSize: DEFAULT_PAGE_SIZE,
  sort: 'created_at',
  order: 'desc',
  filters: {},
} as const;

describe('api.getEvents（§3.7 行 1041，msw 真实 transport 归一链）', () => {
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

    const response = await apiMod.getEvents(apiMod.buildGetEventsRequest(LOG_QUERY));

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

    const response = await apiMod.getEvents(apiMod.buildGetEventsRequest(LOG_QUERY));

    expect(response.items).toEqual([]);
    expect(response.total).toBe(BigInt(0));
  });
});

describe('buildGetEventsRequest（§3.7 行 1041 入参 + §1.7 行 275-278，纯函数）', () => {
  test('分页 / 排序 → wire int64 十进制字符串（§1.12）+ sort/order 全量下发', () => {
    expect(
      toJson(GetEventsRequestSchema, apiMod.buildGetEventsRequest({
        page: 3,
        pageSize: 50,
        sort: 'created_at',
        order: 'asc',
        filters: {},
      })),
    ).toEqual({ page: '3', pageSize: '50', sort: 'created_at', order: 'asc' });
  });

  test('无排序（order 为空）→ sort/order 零值省略（§1.0 零值缺省）', () => {
    expect(
      toJson(GetEventsRequestSchema, apiMod.buildGetEventsRequest(
        initialTableQuery(),
      )),
    ).toEqual({ page: '1', pageSize: '20' });
  });

  test('event 类型过滤透传（行 1041 入参）；缺省省略不发', () => {
    expect(
      toJson(GetEventsRequestSchema, apiMod.buildGetEventsRequest(initialTableQuery(), 'login')),
    ).toEqual({ page: '1', pageSize: '20', event: 'login' });
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
      resolveTableQuery({ pagination: { currentPage: 0, pageSize: 500 } }, prev),
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
      resolveTableQuery({ sorter: { dataIndex: 'created_at', sortOrder: 'descend' } }, prev),
    ).toEqual({ page: 1, pageSize: 20, sort: 'created_at', order: 'desc', filters: {} });
    expect(
      resolveTableQuery({ sorter: { dataIndex: 'created_at', sortOrder: 'ascend' } }, prev),
    ).toEqual({ page: 1, pageSize: 20, sort: 'created_at', order: 'asc', filters: {} });
    expect(
      resolveTableQuery({ sorter: { dataIndex: 'created_at', sortOrder: false } }, prev),
    ).toEqual({ page: 1, pageSize: 20, sort: 'created_at', order: '', filters: {} });
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
    readonly key: string;
    readonly enabled: boolean;
  }

  const rows: readonly FakeRow[] = [
    { key: 'a', enabled: false },
    { key: 'b', enabled: true },
  ];
  const keyOf = (row: FakeRow): string => row.key;
  const toggle = (row: FakeRow): FakeRow => ({ ...row, enabled: !row.enabled });

  test('patchRowByKey：命中行不可变更新（原数组 / 原行对象不动）；未命中 → 原引用', () => {
    const next = patchRowByKey(rows, keyOf, 'a', (row) => ({ ...row, enabled: true }));
    expect(next).not.toBe(rows);
    expect(rows[0]).toEqual({ key: 'a', enabled: false }); // 原行未动 = 回滚依据
    expect(next[0]).toEqual({ key: 'a', enabled: true });
    expect(next[1]).toBe(rows[1]); // 未命中行原对象复用
    expect(patchRowByKey(rows, keyOf, 'zz', (row) => ({ ...row, enabled: true }))).toBe(rows);
  });

  test('runInlineToggle：persist 成功 → 保留乐观行集（ok: true），persist 收到打补丁行', async () => {
    const persisted: unknown[] = [];
    const outcome = await runInlineToggle(rows, keyOf, 'a', toggle, async (patched) => {
      persisted.push(patched);
    });
    expect(outcome.ok).toBe(true);
    expect(outcome.rows[0]).toEqual({ key: 'a', enabled: true });
    expect(persisted).toEqual([{ key: 'a', enabled: true }]);
  });

  test('runInlineToggle：persist 失败 → 回滚原 rows 引用（ok: false）且原数组完好', async () => {
    const outcome = await runInlineToggle(rows, keyOf, 'a', toggle, async () => {
      throw new Error('boom');
    });
    expect(outcome.ok).toBe(false);
    expect(outcome.rows).toBe(rows); // 回滚 = 恢复原引用
    expect(rows[0]).toEqual({ key: 'a', enabled: false });
  });

  test('runInlineToggle：key 未命中 → 不调 persist、原样返回（无可变更项）', async () => {
    let persistCalled = false;
    const outcome = await runInlineToggle(rows, keyOf, 'zz', toggle, async () => {
      persistCalled = true;
    });
    expect(outcome.ok).toBe(true);
    expect(outcome.rows).toBe(rows);
    expect(persistCalled).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// UpdateProfile 资料编辑 + 头像持久化（§3.2 行 837；后端 account 域桩
// 未实装——契约先行口径：按接口契约消费 + msw mock，不因 mock 放宽契约）
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

    const built = apiMod.buildUpdateProfileRequest(PROFILE_BASE, profileDraft({
      nickname: '张三丰',
      gender: 2,
      birthday: '1991-02-03',
      locale: 'en-US',
      timezone: 'UTC',
      extraText: '{"company": "acme", "level": 3}',
    }));
    expect(built.ok).toBe(true);
    if (!built.ok) {
      throw new Error('unreachable');
    }

    await apiMod.updateProfile(built.request);

    expect(await captured.json()).toEqual({
      nickname: '张三丰',
      profile: {
        gender: '2',
        birthday: '1991-02-03',
        locale: 'en-US',
        timezone: 'UTC',
        extra: { company: 'acme', level: 3 },
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

    await apiMod.updateProfile(apiMod.buildAvatarPersistRequest('https://cdn.test/b.jpg'));

    expect(await captured.json()).toEqual({ avatarUrl: 'https://cdn.test/b.jpg' });
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

    const caught = await captureRejection(
      apiMod.updateProfile(apiMod.buildAvatarPersistRequest('u')),
    );

    expect(caught).toBeInstanceOf(ApiError);
    expect((caught as ApiError).httpStatus).toBe(400);
    expect((caught as ApiError).code).toBe('invalid_argument');
  });
});

describe('buildUpdateProfileRequest（§3.2 行 837 PATCH 语义——缺省保留，纯函数）', () => {
  test('草稿与基线全同（extra 未编辑）→ 零值 request：wire {}（服务端空操作幂等）', () => {
    const built = apiMod.buildUpdateProfileRequest(PROFILE_BASE, profileDraft({}));
    expect(built.ok).toBe(true);
    if (!built.ok) {
      throw new Error('unreachable');
    }
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
    expect(toJson(UpdateProfileRequestSchema, built.request)).toEqual({ nickname: '李四' });
  });

  test('gender 编辑 0→2：number → bigint，wire 十进制字符串（§1.12）；nickname 未编辑不带', () => {
    const built = apiMod.buildUpdateProfileRequest(PROFILE_BASE, profileDraft({ gender: 2 }));
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
      profileDraft({ birthday: '1991-02-03', locale: 'en-US', timezone: 'UTC' }),
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
    expect(toJson(UpdateProfileRequestSchema, built.request)).toEqual({ nickname: '' });
  });

  test('extra 未编辑（undefined）→ 不带 extra；编辑为合法 JSON 对象 → 全量透传（§3.1 行 813）', () => {
    const edited = apiMod.buildUpdateProfileRequest(
      PROFILE_BASE,
      profileDraft({ extraText: '{"city": "北京"}' }),
    );
    expect(edited.ok).toBe(true);
    if (!edited.ok) {
      throw new Error('unreachable');
    }
    expect(toJson(UpdateProfileRequestSchema, edited.request)).toEqual({
      profile: { extra: { city: '北京' } },
    });
  });

  test('extra 编辑为非法 JSON / 数组 / 原始值 / null → invalid_extra_json 不发包（JSON 对象语义）', () => {
    for (const extraText of ['{oops', '[1, 2]', '"text"', '123', 'null', '']) {
      expect(
        apiMod.buildUpdateProfileRequest(PROFILE_BASE, profileDraft({ extraText })),
      ).toEqual({ ok: false, error: 'invalid_extra_json' });
    }
  });

  test('birthday 编辑为非法格式 / 非法日历 → invalid_birthday 不发包（YYYY-MM-DD §3.1 行 811）', () => {
    for (const birthday of ['1990/01/01', '1990-1-1', '19901301', '1990-13-01', '1990-02-40']) {
      expect(
        apiMod.buildUpdateProfileRequest(PROFILE_BASE, profileDraft({ birthday })),
      ).toEqual({ ok: false, error: 'invalid_birthday' });
    }
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
    expect(toJson(UpdateProfileRequestSchema, built.request)).toEqual({ profile: { birthday: '' } });
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

describe('profileGenderText（§3.1 行 811 枚举 0/1/2 展示映射，纯函数）', () => {
  test('0 保密 / 1 男 / 2 女；出域值原样显示数字不粉饰（沿 mfaFactorDetail default 同口径）', () => {
    expect(apiMod.profileGenderText(BigInt(0))).toBe('保密');
    expect(apiMod.profileGenderText(BigInt(1))).toBe('男');
    expect(apiMod.profileGenderText(BigInt(2))).toBe('女');
    expect(apiMod.profileGenderText(BigInt(9))).toBe('9');
  });
});

// ---------------------------------------------------------------------------
// routes：未知路径兜底真渲染（测试链解锁 Semi 加载）
// ---------------------------------------------------------------------------

describe('routes：未知路径兜底真渲染', () => {
  function renderAccountApp(pathname: string): string {
    rs.stubGlobal('window', {
      location: { pathname },
      __AUTHLOFT_INIT__: (globalThis as { __AUTHLOFT_INIT__?: unknown })
        .__AUTHLOFT_INIT__,
    });
    return renderToStaticMarkup(createElement(routesMod.AccountApp));
  }

  test('未知路径 /account/does-not-exist → Semi Empty 兜底文案 + 回首页链接', () => {
    const html = renderAccountApp('/account/does-not-exist');
    expect(html).toContain('页面不存在');
    expect(html).toContain('返回个人中心');
    expect(html).toContain('href="/account/profile"');
    expect(html).toContain('semi-empty');
  });

  test('已知路径 /account/security → 不被兜底吞掉（渲染安全中心，无兜底文案）', () => {
    const html = renderAccountApp('/account/security');
    expect(html).not.toContain('页面不存在');
    expect(html).toContain('安全中心');
  });
});

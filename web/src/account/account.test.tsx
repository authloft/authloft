// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化后移除）。
// @ts-ignore
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, rs, test } from 'rstack/test';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { create } from '@bufbuild/protobuf';
import {
  AvatarUploadConfigSchema,
  CommitAvatarRequestSchema,
  PresignAvatarRequestSchema,
} from '../gen/proto/api/account/v1/profile_pb';
import type {
  BindEmailRequest,
  BindPhoneRequest,
} from '../gen/proto/api/account/v1/security_pb';
import { CaptchaPayloadSchema } from '../gen/proto/api/sso/v1/login_pb';
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
 *   得 url + 超限 / 类型预校验文案与后端一致，前端架构 §8 行 626）、表单
 *   请求构造纯函数（buildChangePasswordRequest / buildBind 系）、apiErrorText。
 *
 * 【Blocker】routes / AppLayout / ProfilePage / SecurityPage / 表单组件的渲染
 * 测试在本工具链下无法落地：@douyinfe/semi-ui 的 lib/es 内部为无扩展名
 * import，node 原生 ESM 无法加载，rstest 0.12.5 对其 externalize（rs.mock /
 * __mocks__ 均为运行时机制，拦不住编译图对 external 包的链接期加载）→ 任何
 * 模块图含 semi import 的测试文件都在加载期崩（实测：rs.mock 全组件 /
 * __mocks__ 目录 / 子路径 import 三路都试过）。唯一工具级解法是
 * rstack.config.mts 的 define.test 配置（Rstest deps inline），该文件本次
 * 不改。渲染测试待工具链修复后补齐；表单 / 上传的可测逻辑因此落在 api.ts
 * （零 Semi 依赖），本文件只 import api / bootstrap。
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

beforeAll(async () => {
  server.listen({ onUnhandledRequest: 'error' });
  bootstrapMod = await import('./bootstrap');
  apiMod = await import('./api');
});

beforeEach(() => {
  // routes / AppLayout 渲染不可测（见文件头 Blocker），本文件无 JSX 渲染；
  // stub window 供 getInit（shared/types/init.ts）读取注入块。
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
    expect(apiMod.isUploadEntryHidden(config.avatarUpload)).toBe(true);
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
// 头像上传纯逻辑 + 两模式编排（§3.2 / §10.8 / 前端架构 §8 行 626）
// ---------------------------------------------------------------------------

describe('头像上传（§3.2 / §10.8 / 前端架构 §8 行 626）', () => {
  test('isUploadEntryHidden：未加载 / 零值投影 → true；正常配置 → false（行 826）', () => {
    expect(apiMod.isUploadEntryHidden(undefined)).toBe(true);
    expect(apiMod.isUploadEntryHidden(create(AvatarUploadConfigSchema, { mode: 'proxy' }))).toBe(
      true,
    );
    expect(
      apiMod.isUploadEntryHidden(
        create(AvatarUploadConfigSchema, {
          mode: 'proxy',
          maxSize: BigInt(2097152),
          allowedTypes: ['image/png'],
        }),
      ),
    ).toBe(false);
  });

  test('validateAvatarFile：超限 / 类型不符（code 与后端一致，行 852）', () => {
    const config = create(AvatarUploadConfigSchema, {
      mode: 'proxy',
      maxSize: BigInt(100),
      allowedTypes: ['image/png'],
    });
    expect(apiMod.validateAvatarFile(config, { size: 101, type: 'image/png' })).toBe(
      'file_too_large',
    );
    expect(apiMod.validateAvatarFile(config, { size: 50, type: 'image/gif' })).toBe(
      'file_type_not_allowed',
    );
    expect(apiMod.validateAvatarFile(config, { size: 50, type: 'image/png' })).toBe(undefined);
  });

  test('uploadAvatarFile 预校验失败：抛 code 与后端一致的 ApiError，文案同源 i18n 字典', async () => {
    const config = create(AvatarUploadConfigSchema, {
      mode: 'proxy',
      maxSize: BigInt(100),
      allowedTypes: ['image/png'],
    });

    const oversize = new File([new Uint8Array(101)], 'a.png', { type: 'image/png' });
    const tooLargeError = (await captureRejection(
      apiMod.uploadAvatarFile(config, oversize),
    )) as ApiError;
    expect(tooLargeError).toBeInstanceOf(ApiError);
    expect(tooLargeError.code).toBe('file_too_large');

    const wrongType = new File([new Uint8Array(10)], 'a.gif', { type: 'image/gif' });
    const typeError = (await captureRejection(
      apiMod.uploadAvatarFile(config, wrongType),
    )) as ApiError;
    expect(typeError.code).toBe('file_type_not_allowed');

    // §8 行 626：预校验文案与后端一致（shared/i18n 同一份字典）。
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

    const url = await apiMod.uploadAvatarFile(config, file);

    expect(url).toBe('https://cdn.test/direct.png');
    expect(order).toEqual(['presign', 'put', 'commit']); // direct 三步（§8 行 626）
    expect(presignBody).toEqual({
      filename: 'a.png',
      contentType: 'image/png',
      size: '2048',
    });
    expect(putHeaders?.get('content-type')).toBe('image/png');
    expect(commitBody).toEqual({ key: 'avatars/k1' });
  });

  test('proxy 模式（mock GetConfig）：postForm 得 url + 进度透传（§10.8 / §8 行 626）', async () => {
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
    expect(apiMod.isUploadEntryHidden(avatarUpload)).toBe(false);

    const progress: Array<{ loaded: number; total: number }> = [];
    const url = await apiMod.uploadAvatarFile(
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

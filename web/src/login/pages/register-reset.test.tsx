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
} from 'rstack/test';
import * as React from 'react';
// 本仓 rstest 为 node 环境（无 DOM）：静态渲染走 react-dom/server 的
// renderToStaticMarkup（沿 login-container.test.tsx / routes.test.tsx 边界
// 惯例），交互 / 提交编排经页面族纯函数（RegisterPage 导出）+ msw 拦截
// api 层覆盖；状态帧视图（RegisterPageView / ResetPageView）可注入任意
// status 帧（LoginFlowView 同款模式）。
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from '@modern-js/runtime/router';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { create, toBinary } from '@bufbuild/protobuf';
import { clearLoginToken, getLoginToken } from '../loginTokenStore';
import { CaptchaConfigSchema } from '../../gen/proto/api/common/v1/captcha_pb';
import { ErrorInfoSchema } from '../../gen/proto/api/common/v1/error_info_pb';
import {
  LoginFlowResponseSchema,
  NextStepSchema,
  type LoginFlowResponse,
} from '../../gen/proto/api/sso/v1/envelope_pb';
import {
  CaptchaPayloadSchema,
  type CaptchaPayload,
} from '../../gen/proto/api/sso/v1/login_pb';
import {
  runCaptchaGate,
  type CaptchaGateMode,
  type CaptchaGateResult,
  type CaptchaPrompt,
} from '../../shared/captcha/captchaGate';
import type {
  CaptchaGate,
  CaptchaGateRunOptions,
} from '../../shared/captcha/useCaptchaGate';
import type { MethodsSnapshot } from '../../shared/types/init';

const { createElement } = React;

/**
 * al_root 在 transport（http.ts）模块求值时读取，故页面 / routes / api 模块
 * 经 beforeAll 动态 import（沿 login-container.test.tsx 模式）；BASE 与既有
 * 测试文件取同值防跨文件竞争。
 */
const BASE = 'https://uc.test';
(globalThis as { __AUTHLOFT_INIT__?: unknown }).__AUTHLOFT_INIT__ = {
  al_root: `${BASE}/`,
};

const REGISTER_URL = `${BASE}/api.sso.v1.SsoService/Register`;
const RESET_URL = `${BASE}/api.sso.v1.SsoService/ResetPassword`;

const server = setupServer();

let pagesMod: typeof import('./RegisterPage');
let resetMod: typeof import('./ResetPage');
let routesMod: typeof import('../routes');
let apiMod: typeof import('../api');

beforeAll(async () => {
  server.listen({ onUnhandledRequest: 'error' });
  pagesMod = await import('./RegisterPage');
  resetMod = await import('./ResetPage');
  routesMod = await import('../routes');
  apiMod = await import('../api');
});

beforeEach(() => {
  // rstest 对 .tsx 走 classic JSX runtime：渲染前 stub 全局 React（仅测试进程）。
  rs.stubGlobal('React', React);
});

afterEach(() => {
  server.resetHandlers();
  rs.unstubAllGlobals();
  clearLoginToken(); // loginTokenStore 模块级变量跨用例复位
});

afterAll(() => {
  server.close();
  (globalThis as { __AUTHLOFT_INIT__?: unknown }).__AUTHLOFT_INIT__ = undefined;
});

// ---------------------------------------------------------------------------
// 测试数据（§2.1 注入结构；flow=register / flow=reset 快照形状）
// ---------------------------------------------------------------------------

const IMAGE_CAPTCHA = create(CaptchaConfigSchema, {
  providerKey: 'builtin_image',
  type: 'image',
});

/** flow=register 快照：用户名密码 + 手机号 / 邮箱验证码三方式（§2.1 行 411）。 */
const REGISTER_SNAPSHOT: MethodsSnapshot = {
  flags: { registration: true },
  captcha: IMAGE_CAPTCHA,
  methods: [
    {
      method: 'password',
      usage: ['primary'],
      steps: ['form'],
      fields: [
        {
          name: 'username',
          label: 'login.field.username',
          type: 'text',
          required: true,
        },
        {
          name: 'password',
          label: 'login.field.password',
          type: 'password',
          required: true,
        },
        { name: 'captcha', label: 'login.field.captcha', type: 'captcha' },
      ],
    },
    {
      method: 'otp_sms',
      usage: ['primary'],
      steps: ['challenge', 'form'],
      challengeFields: [
        {
          name: 'phone',
          label: 'login.field.phone',
          type: 'phone',
          required: true,
        },
      ],
      codeLength: '6',
      resendAfter: '60',
      expiresIn: '300',
    },
    {
      method: 'otp_email',
      usage: ['primary'],
      steps: ['challenge', 'form'],
      challengeFields: [
        {
          name: 'email',
          label: 'login.field.email',
          type: 'email',
          required: true,
        },
      ],
      codeLength: '6',
      resendAfter: '60',
      expiresIn: '300',
    },
  ],
};

/** flow=reset 快照：只保留 otp_sms / otp_email（§2.1 行 412）。 */
const RESET_SNAPSHOT: MethodsSnapshot = {
  flags: { passwordReset: true },
  captcha: IMAGE_CAPTCHA,
  methods: [REGISTER_SNAPSHOT.methods[1], REGISTER_SNAPSHOT.methods[2]],
};

function envelope(init: Record<string, unknown>): LoginFlowResponse {
  return create(LoginFlowResponseSchema, init);
}

function viewProps(init: Record<string, unknown>): Record<string, unknown> {
  return {
    status: 'idle',
    envelope: undefined,
    method: 'otp_email',
    step: 'challenge',
    loading: false,
    otpCode: '',
    username: '',
    password: '',
    onSelectMethod: () => {},
    onSubmit: () => {},
    onOtpCodeChange: () => {},
    onUsernameChange: () => {},
    onPasswordChange: () => {},
    onResend: () => {},
    ...init,
  };
}

function renderRegisterView(init: Record<string, unknown> = {}): string {
  return renderToStaticMarkup(
    createElement(
      pagesMod.RegisterPageView,
      viewProps({ snapshot: REGISTER_SNAPSHOT, ...init }) as never,
    ),
  );
}

function renderResetView(init: Record<string, unknown> = {}): string {
  // success 帧的登录页链接经 Link 渲染，消费 router 上下文。
  return renderToStaticMarkup(
    createElement(
      MemoryRouter,
      { initialEntries: ['/sso/reset'] },
      createElement(
        resetMod.ResetPageView,
        viewProps({ snapshot: RESET_SNAPSHOT, ...init }) as never,
      ),
    ),
  );
}

/**
 * gate 替身：跑真 runCaptchaGate 循环、只把「弹窗询问」换成脚本化作答
 *（确认 → 凭据；用尽 / undefined → 取消），并记录每次询问。空脚本 = 不弹窗。
 */
function scriptedGate(answers: (CaptchaPayload | undefined)[] = []) {
  const prompts: CaptchaPrompt[] = [];
  // .tsx 走 classic JSX runtime：泛型箭头须写 <T,> 消歧。
  const run = <T,>(
    options: CaptchaGateRunOptions<T>,
  ): Promise<CaptchaGateResult<T>> =>
    runCaptchaGate<T>({
      ...options,
      prompt: async (next) => {
        prompts.push(next);
        return answers[prompts.length - 1];
      },
    });
  const gate: CaptchaGate['run'] = run;
  return { run: gate, prompts };
}

/** details.value 的 base64（Connect 错误体 detail 为 base64 的 Protobuf 字节，§1.5 行 207）。 */
function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

/**
 * captcha 失败的非 200 Connect 错误体（§1.5 行 228 / §2.5 / §1.6 行 257-258）：
 * ErrorInfo.code = captcha_required / captcha_invalid，details 并列 CaptchaConfig。
 */
function captchaError(
  code: 'captcha_required' | 'captcha_invalid',
  config: { providerKey: string; type?: string },
): HttpResponse {
  const info = create(ErrorInfoSchema, { domain: 'sso', code });
  return HttpResponse.json(
    {
      code: 'invalid_argument',
      message: code,
      details: [
        {
          type: 'api.common.v1.ErrorInfo',
          value: bytesToBase64(toBinary(ErrorInfoSchema, info)),
        },
        {
          type: 'api.common.v1.CaptchaConfig',
          value: bytesToBase64(
            toBinary(CaptchaConfigSchema, create(CaptchaConfigSchema, config)),
          ),
        },
      ],
    },
    { status: 400 },
  );
}

/**
 * 固定 payload 的 runFlowStep 适配（既有链路用例只验请求体与信封，不随 gate
 * 轮次重建 payload）；需要验弹窗循环的用例直接调 pagesMod.runFlowStep。
 */
function runStep<P extends object>(
  request: (input: {
    method: string;
    step: string;
    payload: P;
    captcha?: CaptchaPayload;
  }) => Promise<LoginFlowResponse>,
  input: {
    method: string;
    step: string;
    payload: P;
    captcha?: CaptchaPayload;
  },
  mode: CaptchaGateMode = 'reactive',
) {
  return pagesMod.runFlowStep(
    request,
    {
      method: input.method,
      step: input.step,
      payloadFor: () => input.payload,
    },
    // 预置凭据的 gate：captcha 走请求顶层（§2.5 / §2.6 行 672）。
    input.captcha === undefined
      ? scriptedGate().run
      : scriptedGate([input.captcha]).run,
    input.captcha === undefined
      ? { mode }
      : { mode: 'upfront', config: IMAGE_CAPTCHA },
  );
}

// ---------------------------------------------------------------------------
// 纯函数：方式过滤 / 首步 / step 推进 / payload 组装 / 终点
// ---------------------------------------------------------------------------

describe('registerOptionsFor / resetOptionsFor（§2.1 行 411-412 白名单防御）', () => {
  test('注册：password / otp_sms / otp_email 保留，其余（thirdparty 等）过滤', () => {
    expect(
      pagesMod.registerOptionsFor(REGISTER_SNAPSHOT).map((m) => m.method),
    ).toEqual(['password', 'otp_sms', 'otp_email']);
    expect(
      pagesMod
        .registerOptionsFor({
          methods: [
            {
              method: 'thirdparty',
              usage: ['primary'],
              providers: [],
            },
          ],
        })
        .map((m) => m.method),
    ).toEqual([]);
  });

  test('重置：只保留 otp_sms / otp_email，password 过滤', () => {
    expect(
      resetMod.resetOptionsFor(REGISTER_SNAPSHOT).map((m) => m.method),
    ).toEqual(['otp_sms', 'otp_email']);
  });
});

describe('registerFirstStep / advanceAfterStep（§2.3 行 451 / §10.3-10.4 序列）', () => {
  test('password → set_password 直入；otp 系 → challenge 起（§2.3 行 451）', () => {
    expect(pagesMod.registerFirstStep('password')).toBe('set_password');
    expect(pagesMod.registerFirstStep('otp_email')).toBe('challenge');
    expect(pagesMod.registerFirstStep('otp_sms')).toBe('challenge');
  });

  test('status=next 推进：challenge → verify → set_password（§10.3 行 1525-1527）', () => {
    const next = envelope({ status: 'next' });
    expect(pagesMod.advanceAfterStep('challenge', next)).toBe('verify');
    expect(pagesMod.advanceAfterStep('verify', next)).toBe('set_password');
    // 非 next（失败态 / captcha_required）不推进；set_password 后的 next 防御不推进。
    expect(
      pagesMod.advanceAfterStep(
        'challenge',
        envelope({ status: 'captcha_required' }),
      ),
    ).toBeUndefined();
    expect(pagesMod.advanceAfterStep('set_password', next)).toBeUndefined();
  });
});

describe('registerPayloadFor / resetPayloadFor（§2.3 行 444-451 / §2.4 行 462-466）', () => {
  test('注册 challenge：目标（行 447 必须 captcha，走请求顶层）；verify：{code}；set_password：{username, password}', () => {
    expect(
      pagesMod.registerPayloadFor('challenge', { email: 'a@b.com' }),
    ).toEqual({ email: 'a@b.com', phone: '' });
    expect(pagesMod.registerPayloadFor('verify', { code: '123456' })).toEqual({
      code: '123456',
    });
    expect(
      pagesMod.registerPayloadFor('set_password', {
        username: 'alice',
        password: 'Abcdef12',
      }),
    ).toEqual({ username: 'alice', password: 'Abcdef12' });
  });

  test('重置 set_password 只提交 password（§10.4 行 1532）；challenge 只含目标（captcha 走请求顶层）', () => {
    expect(
      resetMod.resetPayloadFor('set_password', { password: 'NewAbc12' }),
    ).toEqual({ password: 'NewAbc12' });
    expect(
      resetMod.resetPayloadFor('challenge', { phone: '13800000000' }),
    ).toEqual({ email: '', phone: '13800000000' });
  });
});

describe('setPasswordIssues（评审 P0-2 + P1-3：set_password 段前置校验）', () => {
  test('注册（requireUsername）：必填 / 用户名格式 / 确认密码本地比对', () => {
    // 全空：三字段齐错（用户名必填 + 密码必填 + 确认必填）。
    expect(
      pagesMod.setPasswordIssues({
        username: '',
        password: '',
        confirm: '',
        requireUsername: true,
      }),
    ).toEqual({
      username: '请填写此项',
      password: '请填写此项',
      confirm: '请填写此项',
    });
    // 用户名格式未过（§2.3 行 449 唯一定义）。
    expect(
      pagesMod.setPasswordIssues({
        username: 'ab',
        password: 'Abcdef12',
        confirm: 'Abcdef12',
        requireUsername: true,
      }),
    ).toEqual({ username: '用户名须为 5-20 位字母、数字或下划线' });
    // 确认密码不一致（只本地比对，不进 payload）。
    expect(
      pagesMod.setPasswordIssues({
        username: 'alice',
        password: 'Abcdef12',
        confirm: 'Abcdef13',
        requireUsername: true,
      }),
    ).toEqual({ confirm: '两次输入的密码不一致' });
    // 全过 → 空对象。
    expect(
      pagesMod.setPasswordIssues({
        username: 'alice',
        password: 'Abcdef12',
        confirm: 'Abcdef12',
        requireUsername: true,
      }),
    ).toEqual({});
  });

  test('重置（requireUsername=false）：不校验用户名，只密码 + 确认', () => {
    expect(
      pagesMod.setPasswordIssues({
        username: '',
        password: 'NewAbc12',
        confirm: 'NewAbc12',
        requireUsername: false,
      }),
    ).toEqual({});
    expect(
      pagesMod.setPasswordIssues({
        username: '',
        password: 'NewAbc12',
        confirm: '',
        requireUsername: false,
      }),
    ).toEqual({ confirm: '请填写此项' });
  });
});

describe('flowTerminalUrl / isFlowErrorStatus / ssoPath', () => {
  test('syncCookieUrl 非空优先；双空 → 默认落点 DEFAULT_ACCOUNT_HOME（§1.3 行 158-162）', () => {
    expect(
      pagesMod.flowTerminalUrl(
        envelope({
          syncCookieUrl: 'https://sync.test/first',
          redirectTo: 'https://app.test/home',
        }),
      ),
    ).toBe('https://sync.test/first');
    expect(
      pagesMod.flowTerminalUrl(
        envelope({ redirectTo: 'https://app.test/home' }),
      ),
    ).toBe('https://app.test/home');
    expect(pagesMod.flowTerminalUrl(envelope({}))).toBe('/account#/profile');
  });

  test('returnTo 消费：双空时合法值放行、站外值拒绝回落；信封终点字段优先', () => {
    // 合法 returnTo（/account# 前缀白名单）→ 放行。
    expect(pagesMod.flowTerminalUrl(envelope({}), '/account#/security')).toBe(
      '/account#/security',
    );
    // 站外值 → 回落默认落点（防开放重定向）。
    expect(
      pagesMod.flowTerminalUrl(envelope({}), 'https://evil.example.com/x'),
    ).toBe('/account#/profile');
    // redirectTo / syncCookieUrl 优先于 returnTo（§1.3 三级优先级）。
    expect(
      pagesMod.flowTerminalUrl(
        envelope({ redirectTo: 'https://app.test/home' }),
        '/account#/security',
      ),
    ).toBe('https://app.test/home');
  });

  test('流程 / captcha 中间态非失败；signup_disabled / username_taken 等为失败', () => {
    for (const status of [
      'idle',
      'next',
      'success',
      'captcha_required',
      'captcha_invalid',
    ]) {
      expect(pagesMod.isFlowErrorStatus(status)).toBe(false);
    }
    for (const status of [
      'signup_disabled',
      'username_taken',
      'password_weak',
      'user_not_found',
      'reset_disabled',
    ]) {
      expect(pagesMod.isFlowErrorStatus(status)).toBe(true);
    }
  });

  test('ssoPath：al_root 剥尾斜杠拼接；缺省回落同源根路径', () => {
    rs.stubGlobal('window', {
      __AUTHLOFT_INIT__: { al_root: 'https://uc.test/' },
    });
    expect(pagesMod.ssoPath('/sso/register')).toBe(
      'https://uc.test/sso/register',
    );
    rs.stubGlobal('window', { __AUTHLOFT_INIT__: { al_root: '/authloft' } });
    expect(pagesMod.ssoPath('/sso/reset')).toBe('/authloft/sso/reset');
    rs.stubGlobal('window', {});
    expect(pagesMod.ssoPath('/sso/login')).toBe('/sso/login');
  });
});

// ---------------------------------------------------------------------------
// RegisterPageView 状态帧渲染（§4.4 行 464）
// ---------------------------------------------------------------------------

describe('RegisterPageView 状态帧渲染', () => {
  test('flags.registration=false → 整页提示注册已关闭（§4.4 行 464），不渲染表单', () => {
    const markup = renderToStaticMarkup(
      createElement(
        pagesMod.RegisterPageView,
        viewProps({
          snapshot: {
            flags: { registration: false },
            methods: REGISTER_SNAPSHOT.methods,
          },
        }) as never,
      ),
    );
    expect(markup).toContain('<h1>注册</h1>');
    expect(markup).toContain('注册未开放');
    expect(markup).not.toContain('<form');
    expect(markup).not.toContain('<input');
  });

  test('任一 step 收到 signup_disabled → 提示并停止流程（§4.4 行 464）', () => {
    const markup = renderRegisterView({
      status: 'signup_disabled',
      envelope: envelope({ status: 'signup_disabled' }),
    });
    expect(markup).toContain('注册未开放');
    expect(markup).not.toContain('<form');
  });

  test('otp_email 首帧：方式 tab + challenge 段（目标输入，captcha 由弹窗承接不内联，§2.3 行 447）', () => {
    const markup = renderRegisterView();
    expect(markup).toContain('用户名密码');
    expect(markup).toContain('手机号');
    expect(markup).toContain('邮箱');
    expect(markup).toContain('邮箱'); // challengeFields label
    expect(markup).toContain('发送验证码'); // OTPForm challenge 段（复用，§4.4 行 464）
    expect(markup).not.toContain('<div></div>'); // 不再内联 CaptchaWidget 容器
    expect(markup).not.toContain('安全验证'); // 弹窗文案不在状态帧视图里
    expect(markup).toContain('aria-current="true"'); // 当前方式高亮
  });

  test('password 方式首帧：set_password 直入（username + password，captcha 走弹窗，§2.3 行 451）', () => {
    const markup = renderRegisterView({
      method: 'password',
      step: 'set_password',
    });
    expect(markup).toContain('name="username"');
    expect(markup).toContain('type="password"');
    expect(markup).toContain('autoComplete="new-password"');
    expect(markup).not.toContain('<div></div>'); // captcha 必填但由弹窗承接（§2.3 行 451）
    expect(markup).toContain('注册</button>');
    // 密码为空 → Meter 不渲染（未输入不提示）。
    expect(markup).not.toContain('长度至少 8 位');
  });

  test('otp 流程 set_password 帧：username + password + Meter（无 captcha，payload 无该字段）', () => {
    const markup = renderRegisterView({
      step: 'set_password',
      password: 'abc',
      username: 'ab',
    });
    expect(markup).toContain('name="username"');
    expect(markup).toContain('✗ 长度至少 8 位'); // Meter 实时提示（§5.6）
    expect(markup).not.toContain('<div></div>'); // otp 流程 set_password 不渲染 captcha
    // 用户名格式体验性预校验（§2.3 行 449 唯一定义；服务端权威）。
    expect(markup).toContain('用户名须为 5-20 位字母、数字或下划线');
  });

  test('verify 帧：CodeInput + 下一步 + 重发倒计时 + 容器持值回填（§10.3 行 1526）', () => {
    const markup = renderRegisterView({
      step: 'verify',
      otpCode: '123456',
      envelope: envelope({
        status: 'next',
        nextStep: create(NextStepSchema, {
          kind: 'form',
          method: 'otp_email',
          retryAfter: BigInt(60),
        }),
      }),
    });
    expect(markup).toContain('autoComplete="one-time-code"');
    expect(markup).toContain('下一步');
    expect(markup).toContain('60 秒后可重发');
    expect(markup).toContain('value="1"'); // CodeInput 首格回填（受控）
  });

  test('username_taken / password_weak：ErrorBanner + 表单保留原地重试（§1.6 行 256/255）', () => {
    const taken = renderRegisterView({
      method: 'password',
      step: 'set_password',
      status: 'username_taken',
      envelope: envelope({ status: 'username_taken' }),
    });
    expect(taken).toContain('role="alert"');
    expect(taken).toContain('用户名已被占用'); // t('errors.status.username_taken')
    expect(taken).toContain('<form'); // 可重试：表单保留

    const weak = renderRegisterView({
      method: 'password',
      step: 'set_password',
      status: 'password_weak',
      envelope: envelope({ status: 'password_weak' }),
      password: 'abc',
    });
    expect(weak).toContain('密码强度不足'); // t('errors.status.password_weak')
    expect(weak).toContain('✗ 长度至少 8 位'); // 强度条提示（§1.6 行 255）
    expect(weak).toContain('<form');
  });

  test('captcha_* 不再内联渲染 widget（弹窗承接）：表单保留、不出 ErrorBanner', () => {
    for (const status of ['captcha_required', 'captcha_invalid'] as const) {
      const markup = renderRegisterView({
        status,
        envelope: envelope({
          status,
          captcha: create(CaptchaConfigSchema, {
            providerKey: 'builtin_image2',
            type: 'image',
          }),
        }),
      });
      expect(markup).toContain('<form'); // OTPForm challenge 段保留
      expect(markup).not.toContain('<div></div>'); // 无内联 widget 容器
      expect(markup).not.toContain('安全验证'); // 弹窗文案不在状态帧视图里
      expect(markup).not.toContain('role="alert"'); // 非失败态（防御：正常由 gate 吸收）
    }
  });

  test('success：跳转中文案（终点由 api 层信封处理）', () => {
    const markup = renderRegisterView({
      status: 'success',
      envelope: envelope({
        status: 'success',
        redirectTo: 'https://app.test/',
      }),
    });
    expect(markup).toContain('注册成功，正在跳转');
    expect(markup).not.toContain('<form');
  });

  test('P1-3：set_password 段确认密码 + 密码显隐（PasswordField）', () => {
    const markup = renderRegisterView({
      method: 'password',
      step: 'set_password',
    });
    expect(markup).toContain('确认密码'); // login.confirmPasswordLabel
    expect(markup).toContain('name="password_confirm"');
    expect(markup).toContain('>显示</button>'); // 显隐切换（common.reveal）
    expect(markup).toContain('autoComplete="new-password"'); // PasswordField 缺省
  });

  test('P1-5：challengeValues 经 OTPForm initialValues 回填 challenge 段', () => {
    const markup = renderRegisterView({
      method: 'otp_sms',
      step: 'challenge',
      challengeValues: { phone: '13800000000' },
    });
    expect(markup).toContain('value="13800000000"');
  });

  test('P1-4：internal_error + onRetry → banner「重试」；verify 段剩余次数 banner 不重复', () => {
    const retryMarkup = renderRegisterView({
      status: 'internal_error',
      envelope: envelope({ status: 'internal_error' }),
      onRetry: () => {},
    });
    expect(retryMarkup).toContain('>重试</button>');

    const verifyMarkup = renderRegisterView({
      step: 'verify',
      otpCode: '123456',
      status: 'invalid_code',
      envelope: envelope({
        status: 'invalid_code',
        error: { message: '验证码错误', attemptsLeft: '3' },
      }),
      onRetry: () => {},
    });
    expect(verifyMarkup).toContain('还可尝试 3 次'); // 字段旁内联
    expect(verifyMarkup).not.toContain('次尝试机会'); // banner 不重复
    expect(verifyMarkup).not.toContain('>重试</button>'); // 非白名单不接 onRetry
  });
});

// ---------------------------------------------------------------------------
// ResetPageView 状态帧渲染（§4.4 行 465）
// ---------------------------------------------------------------------------

describe('ResetPageView 状态帧渲染', () => {
  test('flags.passwordReset=false → 整页提示「找回密码未开放」（§4.4 行 465）', () => {
    const markup = renderToStaticMarkup(
      createElement(
        resetMod.ResetPageView,
        viewProps({
          snapshot: {
            flags: { passwordReset: false },
            methods: RESET_SNAPSHOT.methods,
          },
        }) as never,
      ),
    );
    expect(markup).toContain('<h1>重置密码</h1>');
    expect(markup).toContain('找回密码未开放');
    expect(markup).not.toContain('<form');
  });

  test('methods 空数组（§2.1 行 412）→ 同关闭态提示', () => {
    const markup = renderToStaticMarkup(
      createElement(
        resetMod.ResetPageView,
        viewProps({
          snapshot: { flags: { passwordReset: true }, methods: [] },
        }) as never,
      ),
    );
    expect(markup).toContain('找回密码未开放');
  });

  test('reset_disabled：同文案提示并停止流程（§4.4 行 465 / §2.4 行 471）', () => {
    const markup = renderResetView({
      status: 'reset_disabled',
      envelope: envelope({ status: 'reset_disabled' }),
    });
    expect(markup).toContain('找回密码未开放');
    expect(markup).not.toContain('<form');
  });

  test('challenge 帧：目标输入（captcha 由弹窗承接不内联，§2.5 行 528 重置下发必须）', () => {
    const markup = renderResetView();
    expect(markup).toContain('邮箱');
    expect(markup).toContain('发送验证码');
    expect(markup).not.toContain('<div></div>');
    expect(markup).not.toContain('安全验证');
  });

  test('set_password 帧：只渲染新密码（无 username / 无 captcha，§10.4 行 1532）', () => {
    const markup = renderResetView({
      step: 'set_password',
      password: 'NewAbc12',
    });
    expect(markup).toContain('name="password"');
    expect(markup).toContain('新密码');
    expect(markup).not.toContain('name="username"');
    expect(markup).not.toContain('<div></div>'); // 无 captcha
    // Meter：全部满足（§5.6 默认策略）。
    expect(markup).toContain('✓ 长度至少 8 位');
    expect(markup).not.toContain('✗');
  });

  test('user_not_found：ErrorBanner + challenge 表单保留可换目标重试（§1.6 行 254）', () => {
    const markup = renderResetView({
      status: 'user_not_found',
      envelope: envelope({
        status: 'user_not_found',
        error: { message: '未绑定' },
      }),
    });
    expect(markup).toContain('role="alert"');
    expect(markup).toContain('账号不存在，或该手机号/邮箱未绑定账号');
    expect(markup).toContain('<form');
  });

  test('success：提示用新密码登录 + 登录页链接（§2.4 行 469 会话全失效）', () => {
    const markup = renderResetView({
      status: 'success',
      envelope: envelope({ status: 'success' }),
    });
    expect(markup).toContain('密码重置成功，请使用新密码登录');
    expect(markup).toContain('href="/sso/login"');
    expect(markup).toContain('去登录');
  });

  test('P1-3：set_password 段确认密码 + 显隐（重置无用户名字段，§10.4）', () => {
    const markup = renderResetView({ step: 'set_password' });
    expect(markup).toContain('确认密码');
    expect(markup).toContain('新密码');
    expect(markup).toContain('>显示</button>');
    expect(markup).not.toContain('name="username"');
  });

  test('P1-5：challengeValues 经 OTPForm initialValues 回填 challenge 段', () => {
    const markup = renderResetView({
      challengeValues: { email: 'alice@example.com' },
    });
    expect(markup).toContain('value="alice@example.com"');
  });
});

// ---------------------------------------------------------------------------
// runFlowStep + api 层（msw 拦截；§2.3 / §2.4 / §1.3 信封）
// ---------------------------------------------------------------------------

describe('注册链路（msw 全链，§10.3）', () => {
  test('otp_email：challenge → verify → set_password → success，请求体逐段断言', async () => {
    const raws: string[] = [];
    // msw handler 栈后注册的先匹配：每步响应都经同一捕获点（沿 login-container
    // .test.tsx 的 server.use 逐段覆盖模式，捕获与响应合并为一个 handler）。
    const respond = (body: Record<string, unknown>) =>
      server.use(
        http.post(REGISTER_URL, async ({ request }) => {
          raws.push(await request.text());
          return HttpResponse.json(body);
        }),
      );

    // 1. challenge（§10.3 行 1525）：首次不带 loginToken（protojson 省略零值）。
    respond({
      status: 'next',
      loginToken: 'reg-tok-1',
      nextStep: {
        kind: 'form',
        method: 'otp_email',
        fields: [
          {
            name: 'code',
            label: 'login.field.otpCode',
            type: 'otp',
            length: '6',
          },
        ],
        retryAfter: '60',
      },
    });
    const first = await runStep(apiMod.register, {
      method: 'otp_email',
      step: 'challenge',
      payload: pagesMod.registerPayloadFor('challenge', {
        email: 'alice@example.com',
      }),
    });
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    expect(first.envelope.status).toBe('next');
    expect(getLoginToken()).toBe('reg-tok-1'); // §1.3 行 145 无条件覆盖
    expect(pagesMod.advanceAfterStep('challenge', first.envelope)).toBe(
      'verify',
    );
    expect(JSON.parse(raws[0])).toEqual({
      method: 'otp_email',
      step: 'challenge',
      payload: { email: 'alice@example.com' },
    });

    // 2. verify（§10.3 行 1526）：loginToken 顶层注入（§1.8）。
    respond({
      status: 'next',
      loginToken: 'reg-tok-2',
      nextStep: { kind: 'form', method: 'otp_email' },
    });
    const second = await runStep(apiMod.register, {
      method: 'otp_email',
      step: 'verify',
      payload: pagesMod.registerPayloadFor('verify', { code: '123456' }),
    });
    expect(second.ok).toBe(true);
    if (!second.ok) return;
    expect(pagesMod.advanceAfterStep('verify', second.envelope)).toBe(
      'set_password',
    );
    expect(JSON.parse(raws[1])).toEqual({
      loginToken: 'reg-tok-1',
      method: 'otp_email',
      step: 'verify',
      payload: { code: '123456' },
    });

    // 3. set_password（§10.3 行 1527）：{username, password}（otp 流程无 captcha）→ success。
    respond({
      status: 'success',
      syncCookieUrl: 'https://sync.test/first',
      redirectTo: 'https://app.test/home',
    });
    const third = await runStep(apiMod.register, {
      method: 'otp_email',
      step: 'set_password',
      payload: pagesMod.registerPayloadFor('set_password', {
        username: 'alice',
        password: 'Abcdef12',
      }),
    });
    expect(third.ok).toBe(true);
    if (!third.ok) return;
    expect(third.envelope.status).toBe('success');
    expect(getLoginToken()).toBe(''); // §1.3 行 145：success 清空
    expect(pagesMod.flowTerminalUrl(third.envelope)).toBe(
      'https://sync.test/first',
    );
    expect(JSON.parse(raws[2])).toEqual({
      loginToken: 'reg-tok-2',
      method: 'otp_email',
      step: 'set_password',
      payload: { username: 'alice', password: 'Abcdef12' },
    });
  });

  test('用户名 + 密码直入：set_password 一步带 captcha（§2.3 行 451）', async () => {
    let raw = '';
    server.use(
      http.post(REGISTER_URL, async ({ request }) => {
        raw = await request.text();
        return HttpResponse.json({
          status: 'success',
          redirectTo: 'https://app.test/home',
        });
      }),
    );
    const result = await runStep(apiMod.register, {
      method: 'password',
      step: 'set_password',
      payload: pagesMod.registerPayloadFor('set_password', {
        username: 'alice',
        password: 'Abcdef12',
      }),
      captcha: create(CaptchaPayloadSchema, {
        providerKey: 'builtin_image',
        id: 'b7f3',
        answer: '123',
      }),
    });
    expect(result.ok).toBe(true);
    expect(JSON.parse(raw)).toEqual({
      method: 'password',
      step: 'set_password',
      payload: { username: 'alice', password: 'Abcdef12' },
      captcha: { providerKey: 'builtin_image', id: 'b7f3', answer: '123' },
    });
  });

  test('signup_disabled / 传输失败（500）', async () => {
    server.use(
      http.post(REGISTER_URL, () =>
        HttpResponse.json({ status: 'signup_disabled' }),
      ),
    );
    const disabled = await runStep(apiMod.register, {
      method: 'otp_email',
      step: 'challenge',
      payload: pagesMod.registerPayloadFor('challenge', {
        email: 'alice@example.com',
      }),
    });
    expect(disabled.ok).toBe(true);
    if (!disabled.ok) return;
    expect(disabled.envelope.status).toBe('signup_disabled');
    expect(pagesMod.isFlowErrorStatus('signup_disabled')).toBe(true);

    server.use(
      http.post(REGISTER_URL, () => new HttpResponse(null, { status: 500 })),
    );
    const failed = await runStep(apiMod.register, {
      method: 'otp_email',
      step: 'challenge',
      payload: pagesMod.registerPayloadFor('challenge', {
        email: 'alice@example.com',
      }),
    });
    expect(failed.ok).toBe(false); // 不伪造信封（§1.6 行 272）
  });
});

describe('重置链路（msw 全链，§10.4）', () => {
  test('otp_email：challenge（captcha）→ verify → set_password {password} → success', async () => {
    const raws: string[] = [];
    const respond = (body: Record<string, unknown>) =>
      server.use(
        http.post(RESET_URL, async ({ request }) => {
          raws.push(await request.text());
          return HttpResponse.json(body);
        }),
      );

    // 1. challenge：必须 captcha（§2.5 行 528）。
    respond({
      status: 'next',
      loginToken: 'reset-tok-1',
      nextStep: { kind: 'form' },
    });
    const first = await runStep(apiMod.resetPassword, {
      method: 'otp_email',
      step: 'challenge',
      payload: resetMod.resetPayloadFor('challenge', {
        email: 'alice@example.com',
      }),
      captcha: create(CaptchaPayloadSchema, {
        providerKey: 'builtin_image',
        id: 'c9d2',
        answer: '456',
      }),
    });
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    expect(getLoginToken()).toBe('reset-tok-1');
    expect(JSON.parse(raws[0])).toEqual({
      method: 'otp_email',
      step: 'challenge',
      payload: { email: 'alice@example.com' },
      captcha: { providerKey: 'builtin_image', id: 'c9d2', answer: '456' },
    });

    // 2. verify。
    respond({
      status: 'next',
      loginToken: 'reset-tok-2',
      nextStep: { kind: 'form' },
    });
    const second = await runStep(apiMod.resetPassword, {
      method: 'otp_email',
      step: 'verify',
      payload: resetMod.resetPayloadFor('verify', { code: '654321' }),
    });
    expect(second.ok).toBe(true);
    if (!second.ok) return;
    expect(pagesMod.advanceAfterStep('verify', second.envelope)).toBe(
      'set_password',
    );
    expect(JSON.parse(raws[1])).toEqual({
      loginToken: 'reset-tok-1',
      method: 'otp_email',
      step: 'verify',
      payload: { code: '654321' },
    });

    // 3. set_password：只提交 password（§10.4 行 1532）→ success（loginToken 清空）。
    respond({ status: 'success' });
    const third = await runStep(apiMod.resetPassword, {
      method: 'otp_email',
      step: 'set_password',
      payload: resetMod.resetPayloadFor('set_password', {
        password: 'NewAbc12',
      }),
    });
    expect(third.ok).toBe(true);
    expect(getLoginToken()).toBe('');
    expect(JSON.parse(raws[2])).toEqual({
      loginToken: 'reset-tok-2',
      method: 'otp_email',
      step: 'set_password',
      payload: { password: 'NewAbc12' },
    });
  });

  test('user_not_found：可重试失败态（表单保留换目标重试的判据，§1.6 行 254）', async () => {
    server.use(
      http.post(RESET_URL, () =>
        HttpResponse.json({ status: 'user_not_found' }),
      ),
    );
    const result = await runStep(apiMod.resetPassword, {
      method: 'otp_email',
      step: 'challenge',
      payload: resetMod.resetPayloadFor('challenge', { email: 'ghost@b.com' }),
    });
    expect(result.ok).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// captcha 弹窗编排（页族 runFlowStep + gate；§2.5 / §1.6 行 240-241）
// ---------------------------------------------------------------------------

describe('注册 / 重置 captcha 弹窗编排（upfront 先问再发 / 窗内换凭据 / 取消）', () => {
  /** 自绘图形码凭据（§2.5 行 503-506 三元组）。 */
  const token = (id: string, answer: string) =>
    create(CaptchaPayloadSchema, { providerKey: 'builtin_image', id, answer });

  test('registerCaptchaMode：challenge 与 password 直入 set_password → upfront，其余 reactive', () => {
    expect(pagesMod.registerCaptchaMode('challenge', 'otp_email')).toBe(
      'upfront',
    );
    expect(pagesMod.registerCaptchaMode('challenge', 'otp_sms')).toBe(
      'upfront',
    );
    expect(pagesMod.registerCaptchaMode('set_password', 'password')).toBe(
      'upfront',
    );
    expect(pagesMod.registerCaptchaMode('verify', 'otp_email')).toBe(
      'reactive',
    );
    expect(pagesMod.registerCaptchaMode('set_password', 'otp_email')).toBe(
      'reactive',
    );
  });

  test('upfront：注册 challenge 先弹窗再发，只发一次带凭据的请求（payloadFor 每轮重建）', async () => {
    const raws: string[] = [];
    server.use(
      http.post(REGISTER_URL, async ({ request }) => {
        raws.push(await request.text());
        return HttpResponse.json({
          status: 'next',
          loginToken: 'reg-tok-1',
          nextStep: { kind: 'form', method: 'otp_email' },
        });
      }),
    );
    const gate = scriptedGate([token('r1', '123')]);
    const result = await pagesMod.runFlowStep(
      apiMod.register,
      {
        method: 'otp_email',
        step: 'challenge',
        payloadFor: () =>
          pagesMod.registerPayloadFor('challenge', { email: 'a@b.com' }),
      },
      gate.run,
      { mode: 'upfront', config: IMAGE_CAPTCHA },
    );

    expect(gate.prompts).toHaveLength(1);
    expect(gate.prompts[0].config.providerKey).toBe('builtin_image');
    expect(raws).toHaveLength(1); // 没有注定被拦的裸请求
    expect(JSON.parse(raws[0])).toEqual({
      method: 'otp_email',
      step: 'challenge',
      payload: { email: 'a@b.com' },
      captcha: { providerKey: 'builtin_image', id: 'r1', answer: '123' },
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.envelope.status).toBe('next');
    expect(getLoginToken()).toBe('reg-tok-1');
  });

  test('captcha_invalid：窗内换凭据循环（attempt 递增 + 错误体降级配置），不落页面状态', async () => {
    const raws: string[] = [];
    let calls = 0;
    server.use(
      http.post(RESET_URL, async ({ request }) => {
        raws.push(await request.text());
        calls += 1;
        if (calls === 1) {
          return captchaError('captcha_invalid', {
            providerKey: 'builtin_image',
            type: 'image',
          });
        }
        return HttpResponse.json({ status: 'next', loginToken: 'reset-tok-1' });
      }),
    );
    const gate = scriptedGate([token('c1', 'aaa'), token('c2', 'bbb')]);
    const result = await pagesMod.runFlowStep(
      apiMod.resetPassword,
      {
        method: 'otp_email',
        step: 'challenge',
        payloadFor: () =>
          resetMod.resetPayloadFor('challenge', { email: 'a@b.com' }),
      },
      gate.run,
      { mode: 'upfront', config: IMAGE_CAPTCHA },
    );

    expect(gate.prompts).toHaveLength(2);
    expect(gate.prompts[0].invalid).toBe(false);
    expect(gate.prompts[1].invalid).toBe(true); // §1.6 行 258：窗内出错误文案
    expect(gate.prompts[1].attempt).toBe(1); // widget key 换新 → 新凭据
    expect(JSON.parse(raws[1]).captcha).toEqual({
      providerKey: 'builtin_image',
      id: 'c2',
      answer: 'bbb',
    });
    expect(result.ok).toBe(true); // captcha_invalid 被吸收，不逃逸成页面失败态
    if (!result.ok) return;
    expect(result.envelope.status).toBe('next');
  });

  test('用户取消弹窗：ok:false + cancelled:true（不是传输失败，页面不回第一步）', async () => {
    let calls = 0;
    server.use(
      http.post(REGISTER_URL, () => {
        calls += 1;
        return HttpResponse.json({ status: 'next' });
      }),
    );
    const gate = scriptedGate([undefined]); // 取消
    const result = await pagesMod.runFlowStep(
      apiMod.register,
      {
        method: 'otp_email',
        step: 'challenge',
        payloadFor: () =>
          pagesMod.registerPayloadFor('challenge', { email: 'a@b.com' }),
      },
      gate.run,
      { mode: 'upfront', config: IMAGE_CAPTCHA },
    );
    expect(result).toEqual({ ok: false, cancelled: true });
    expect(calls).toBe(0); // upfront 取消 → 一个请求都没发
  });

  test('传输层失败（500）：ok:false + cancelled:false（与取消区分，页面回第一步）', async () => {
    server.use(
      http.post(RESET_URL, () => new HttpResponse(null, { status: 500 })),
    );
    const result = await pagesMod.runFlowStep(
      apiMod.resetPassword,
      {
        method: 'otp_email',
        step: 'challenge',
        payloadFor: () =>
          resetMod.resetPayloadFor('challenge', { email: 'a@b.com' }),
      },
      scriptedGate([token('c1', 'aaa')]).run,
      { mode: 'upfront', config: IMAGE_CAPTCHA },
    );
    expect(result).toEqual({ ok: false, cancelled: false });
  });

  test('reactive 无首屏配置：先裸探一次，不凭空弹窗（服务端未启用 captcha 的部署）', async () => {
    const raws: string[] = [];
    server.use(
      http.post(REGISTER_URL, async ({ request }) => {
        raws.push(await request.text());
        return HttpResponse.json({ status: 'next' });
      }),
    );
    const gate = scriptedGate([token('x', '1')]);
    const result = await pagesMod.runFlowStep(
      apiMod.register,
      {
        method: 'otp_email',
        step: 'verify',
        payloadFor: () =>
          pagesMod.registerPayloadFor('verify', { code: '123456' }),
      },
      gate.run,
      { mode: 'upfront' }, // 无 config → 退化为先探一次
    );
    expect(gate.prompts).toHaveLength(0);
    expect(raws).toHaveLength(1);
    expect(JSON.parse(raws[0]).payload).toEqual({ code: '123456' });
    expect(result.ok).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 路由分派（routes.tsx 新增；沿 routes.test.tsx 的 window stub 模式）
// ---------------------------------------------------------------------------

describe('LoginApp 路由分派：/sso/register、/sso/reset', () => {
  // 路由表经 MemoryRouter 注入初始路径（BrowserRouter 挂 entry 顶层）。
  function renderLoginApp(pathname: string, methods: MethodsSnapshot): string {
    rs.stubGlobal('window', {
      __AUTHLOFT_INIT__: {
        al_root: `${BASE}/`,
        static_base: '/assets/',
        methods,
      },
    });
    return renderToStaticMarkup(
      createElement(
        MemoryRouter,
        { initialEntries: [pathname] },
        createElement(routesMod.LoginApp),
      ),
    );
  }

  test('/sso/register → RegisterPage（首方式 password → set_password 直入帧）', () => {
    const html = renderLoginApp('/sso/register', REGISTER_SNAPSHOT);
    expect(html).toContain('<h1>注册</h1>');
    expect(html).toContain('name="username"'); // §2.3 行 451 直入帧
    expect(html).toContain('用户名密码');
  });

  test('/sso/reset → ResetPage（challenge 帧）', () => {
    const html = renderLoginApp('/sso/reset', RESET_SNAPSHOT);
    expect(html).toContain('<h1>重置密码</h1>');
    expect(html).toContain('发送验证码');
  });

  test('尾斜杠归一：/sso/register/ 同页', () => {
    const html = renderLoginApp('/sso/register/', REGISTER_SNAPSHOT);
    expect(html).toContain('<h1>注册</h1>');
  });
});

// ---------------------------------------------------------------------------
// 页面壳静态 smoke（编排壳组合渲染不炸；effects 不执行，renderToStaticMarkup 语义）
// ---------------------------------------------------------------------------

describe('RegisterPage / ResetPage 静态 smoke', () => {
  test('注册壳：默认方式首帧渲染（flags.registration=true）', () => {
    // RegisterPage 壳消费 useSearchParams（returnTo 终点），需 MemoryRouter。
    const markup = renderToStaticMarkup(
      createElement(
        MemoryRouter,
        { initialEntries: ['/sso/register'] },
        createElement(pagesMod.RegisterPage, { snapshot: REGISTER_SNAPSHOT }),
      ),
    );
    expect(markup).toContain('<h1>注册</h1>');
    expect(markup).toContain('name="username"');
  });

  test('重置壳：challenge 首帧渲染', () => {
    const markup = renderToStaticMarkup(
      createElement(resetMod.ResetPage, { snapshot: RESET_SNAPSHOT }),
    );
    expect(markup).toContain('<h1>重置密码</h1>');
    expect(markup).toContain('发送验证码');
  });
});

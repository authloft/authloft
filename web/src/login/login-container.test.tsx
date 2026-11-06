// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化后移除）。
// @ts-ignore
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, rs, test } from 'rstack/test';
import * as React from 'react';
// 本仓 rstest 为 node 环境（无 DOM）：静态渲染走 react-dom/server 的
// renderToStaticMarkup（沿 CaptchaWidget.test.ts / components.test.ts 边界惯例），
// 交互 / 副作用生命周期在纯逻辑层覆盖（runSubmit / executeEffects /
// groupProviders 等容器层纯函数 + msw 拦截 api 层）。
import { renderToStaticMarkup } from 'react-dom/server';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { create } from '@bufbuild/protobuf';
import { clearLoginToken, getLoginToken } from './loginTokenStore';
import { flowReducer } from './flow/reducer';
import { INITIAL_FLOW_STATE, type FlowState } from './flow/machine';
import { selectShowCaptcha, selectSubmitDisabled } from './flow/selectors';
import { OTPForm } from './factors/OTPForm';
import { PasswordForm } from './factors/PasswordForm';
import { RecoveryCodeForm } from './factors/RecoveryCodeForm';
import { WebAuthnButton } from './factors/WebAuthnButton';
import { lookupFactor } from './factors/registry';
import { groupProviders, MethodTabs } from './MethodTabs';
import {
  CaptchaConfigSchema,
} from '../gen/proto/api/common/v1/captcha_pb';
import {
  BindingSchema,
  FieldSchema,
  LoginFlowResponseSchema,
  MfaMethodSchema,
  MfaSchema,
  NextStepSchema,
  type LoginFlowResponse,
  type MfaMethod,
} from '../gen/proto/api/sso/v1/envelope_pb';
import { CaptchaPayloadSchema } from '../gen/proto/api/sso/v1/login_pb';
import type {
  MethodsSnapshot,
  SnapshotProvider,
} from '../shared/types/init';

const { createElement } = React;

/**
 * al_root 在 transport（http.ts）模块求值时读取，故 ./LoginContainer（拉起
 * ./api → shared/api/http 链）经 beforeAll 动态 import（沿 api.test.ts 模式）；
 * BASE 与既有测试文件取同值防跨文件竞争。本实现链路不依赖 oidc 快照（注入逻辑
 * 已在 api.test.ts 覆盖），不设 oidc。
 */
const BASE = 'https://uc.test';
(globalThis as { __AUTHLOFT_INIT__?: unknown }).__AUTHLOFT_INIT__ = {
  al_root: `${BASE}/`,
};

const LOGIN_DEFAULT = `${BASE}/api.sso.v1.SsoService/LoginDefault`;

const server = setupServer();

let container: typeof import('./LoginContainer');
let apiMod: typeof import('./api');

beforeAll(async () => {
  server.listen({ onUnhandledRequest: 'error' });
  container = await import('./LoginContainer');
  apiMod = await import('./api');
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
// 测试数据（§2.1 注入结构示例形状）
// ---------------------------------------------------------------------------

const SNAPSHOT: MethodsSnapshot = {
  methods: [
    {
      method: 'password',
      usage: ['primary'],
      steps: ['form'],
      fields: [
        { name: 'username', label: '用户名/邮箱/手机号', type: 'text', required: true },
        { name: 'password', label: '密码', type: 'password', required: true },
        { name: 'captcha', label: '人机校验', type: 'captcha', required: false },
      ],
    },
    {
      method: 'webauthn',
      usage: ['primary', 'secondary'],
      steps: ['challenge', 'form'],
      capability: 'window.PublicKeyCredential',
    },
    {
      method: 'otp_sms',
      usage: ['primary', 'secondary'],
      steps: ['challenge', 'form'],
      challengeFields: [{ name: 'phone', label: '手机号', type: 'phone', required: true }],
      codeLength: '6',
      resendAfter: '60',
      expiresIn: '300',
    },
    { method: 'totp', usage: ['secondary'], steps: ['form'], codeLength: '6' },
    {
      method: 'thirdparty',
      usage: ['primary'],
      providers: [
        { providerKey: 'qq', displayName: 'QQ', type: 'qq', channel: 'redirect', icon: 'https://ex.test/qq.png', uiGroup: 'social', sortOrder: '10' },
        { providerKey: 'scan', displayName: '微信扫码', type: 'wechat_mp_scan', channel: 'qrcode', uiGroup: 'social', sortOrder: '20' },
        { providerKey: 'wxmp', displayName: '微信', type: 'wechat_mp', channel: 'api', uiGroup: 'social', sortOrder: '30' },
        { providerKey: 'ent', displayName: '企业SSO', type: 'cas', channel: 'redirect', uiGroup: 'enterprise', sortOrder: '5' },
      ],
    },
  ],
};

function stateWith(init: Partial<FlowState>): FlowState {
  return { ...INITIAL_FLOW_STATE, ...init };
}

function envelope(init: Record<string, unknown>): LoginFlowResponse {
  return create(LoginFlowResponseSchema, init);
}

function renderView(state: FlowState, notice?: string): string {
  return renderToStaticMarkup(
    createElement(container.LoginFlowView, {
      snapshot: SNAPSHOT,
      state,
      notice,
      onSelect: () => {},
      onSubmit: () => {},
    }),
  );
}

// ---------------------------------------------------------------------------
// 容器层纯函数
// ---------------------------------------------------------------------------

describe('firstStepFor（kind→step 映射；§1.10）', () => {
  test('form → verify（login 域；set_password 属注册 / 重置，§2.2 行 422）', () => {
    expect(container.firstStepFor(['form'])).toBe('verify');
  });

  test('challenge → challenge（otp_* / webauthn 首步，§1.10）', () => {
    expect(container.firstStepFor(['challenge', 'form'])).toBe('challenge');
  });

  test('空 / 未知 kind 兜底 verify（§9 第 18 条零值兜底）', () => {
    expect(container.firstStepFor([])).toBe('verify');
    expect(container.firstStepFor(['poll'])).toBe('verify');
  });
});

describe('snapshotFieldToField / toPayloadInit（§2.1 快照 → 渲染 / 请求模型）', () => {
  test('快照字段 → 生成物 Field：int64 十进制字符串 → bigint，非法兜底 0', () => {
    const field = container.snapshotFieldToField({
      name: 'code',
      type: 'otp',
      required: true,
      length: '6',
      maxAttempts: '5',
    });
    expect(field.name).toBe('code');
    expect(field.required).toBe(true);
    expect(field.length).toBe(BigInt(6));
    expect(field.maxAttempts).toBe(BigInt(5));

    const minimal = container.snapshotFieldToField({ name: 'x', type: 'text' });
    expect(minimal.required).toBe(false);
    expect(minimal.length).toBe(BigInt(0));
    expect(container.snapshotFieldToField({ name: 'x', type: 'text', length: 'abc' }).length).toBe(BigInt(0));
  });

  test('表单值 → payload：白名单 string 字段、captcha 与白名单外排除（§1.3 行 114 / §2.6）', () => {
    const fields = [
      create(FieldSchema, { name: 'username', label: 'u', type: 'text', required: true }),
      create(FieldSchema, { name: 'password', label: 'p', type: 'password', required: true }),
      create(FieldSchema, { name: 'captcha', label: 'c', type: 'captcha' }),
      create(FieldSchema, { name: 'evil', label: 'e', type: 'text' }),
    ];
    expect(
      container.toPayloadInit({ username: 'alice', password: 'pw', evil: 'x' }, fields),
    ).toEqual({ username: 'alice', password: 'pw' });
    // 未填字段按零值兜底（§9 第 18 条）。
    expect(container.toPayloadInit({}, fields)).toEqual({ username: '', password: '' });
  });
});

describe('fieldsFor（纯函数：提交白名单字段源；§1.3 行 121-127 / §2.6 行 546）', () => {
  const MFA_METHODS: MfaMethod[] = [
    // 后端 mfa.go 对 otp 系 mfa 条目不填 fields / challengeFields。
    create(MfaMethodSchema, {
      method: 'otp_sms',
      steps: ['challenge', 'form'],
      maskedTarget: '138****8000',
    }),
    create(MfaMethodSchema, {
      method: 'recovery_code',
      steps: ['form'],
      fields: [create(FieldSchema, { name: 'code', label: '恢复码', type: 'text', required: true })],
    }),
  ];

  test('mfa otp_sms verify：mfaEntry.fields 空 + OTP 系 → 补 code 白名单 → 提交 payload {code}', () => {
    const fields = container.fieldsFor('otp_sms', 'verify', SNAPSHOT, MFA_METHODS);
    expect(fields.map((f) => f.name)).toEqual(['code']);
    expect(fields[0].length).toBe(BigInt(6)); // codeLength 取快照（§2.1 行 391）
    // 容器 submit 链路：fieldsFor 结果 → toPayloadInit → 请求 payload（§2.6 行 546）。
    expect(container.toPayloadInit({ code: '123456' }, fields)).toEqual({ code: '123456' });
  });

  test('mfa otp_sms challenge：challengeFields 空（MFA 不传目标，§2.6 行 545）→ payload {}', () => {
    const fields = container.fieldsFor('otp_sms', 'challenge', SNAPSHOT, MFA_METHODS);
    expect(fields).toEqual([]);
    expect(container.toPayloadInit({}, fields)).toEqual({});
  });

  test('mfa recovery_code verify：下发 fields 非空 → 优先用下发字段，不补白名单', () => {
    const fields = container.fieldsFor('recovery_code', 'verify', SNAPSHOT, MFA_METHODS);
    expect(fields.map((f) => f.name)).toEqual(['code']);
    expect(fields[0].type).toBe('text'); // 恢复码下发字段，非 otp 补位
  });

  test('主因子 otp_sms verify：快照无 form 步字段 → 补 code（既有语义回归）；challenge → challengeFields', () => {
    expect(
      container.fieldsFor('otp_sms', 'verify', SNAPSHOT, undefined).map((f) => f.name),
    ).toEqual(['code']);
    expect(
      container.fieldsFor('otp_sms', 'challenge', SNAPSHOT, undefined).map((f) => f.name),
    ).toEqual(['phone']);
  });

  test('主因子 password：快照 fields 原样（含 captcha，由 toPayloadInit 按类型排除）', () => {
    expect(
      container.fieldsFor('password', 'verify', SNAPSHOT, undefined).map((f) => f.name),
    ).toEqual(['username', 'password', 'captcha']);
  });

  test('mfa 方式不在镜像中（未选方式防御）→ 回落主因子分支', () => {
    // mfaMethods 有 otp_sms、无 totp：totp 走主因子分支——快照无 fields 且
    // 非 OTPForm（isOtpForm false），不补位、返回空。
    const fields = container.fieldsFor('totp', 'verify', SNAPSHOT, MFA_METHODS);
    expect(fields).toEqual([]); // totp 非 OTPForm（isOtpForm false），不补位
  });
});

describe('terminalUrl / executeEffects（终点，§4.1 行 383）', () => {
  test('syncCookieUrl 非空优先（后端拼好的首跳完整 URL，§1.3 行 136）', () => {
    expect(
      container.terminalUrl(
        envelope({ syncCookieUrl: 'https://sync.test/first', redirectTo: 'https://app.test/home' }),
      ),
    ).toBe('https://sync.test/first');
  });

  test('syncCookieUrl 省略 → redirectTo；双空 → 不跳转', () => {
    expect(container.terminalUrl(envelope({ redirectTo: 'https://app.test/home' }))).toBe('https://app.test/home');
    expect(container.terminalUrl(envelope({}))).toBe('');
  });

  test('complete → 跳转回调（双空目标不调用）；restart → 回第一步回调', () => {
    const redirects: string[] = [];
    const restarts: string[] = [];
    const handlers = {
      complete: (url: string) => redirects.push(url),
      restart: (status: string) => restarts.push(status),
    };
    container.executeEffects(
      [{ type: 'complete', envelope: envelope({ syncCookieUrl: 'https://sync.test/first' }) }],
      handlers,
    );
    container.executeEffects(
      [{ type: 'complete', envelope: envelope({}) }],
      handlers,
    );
    container.executeEffects([{ type: 'restart', status: 'token_expired' }], handlers);
    expect(redirects).toEqual(['https://sync.test/first']);
    expect(restarts).toEqual(['token_expired']);
  });
});

describe('qrResultEvent（扫码结论分派，§2.8 行 739-743：登录结论在内层 login 信封）', () => {
  test('内层 binding_required / 失败态 → response 事件（信封=内层，交状态机分派）', () => {
    for (const innerStatus of ['binding_required', 'target_taken', 'failed']) {
      const login = envelope({ status: innerStatus, loginToken: 'lt-bind' });
      const event = container.qrResultEvent(
        envelope({ status: 'success', login }),
      );
      expect(event).toEqual({ type: 'response', envelope: login });
    }
  });

  test('内层 success / 内层缺失 → undefined（终点已由 QRCodeStep completeLogin 跳，不镜像防二次 replace）', () => {
    expect(
      container.qrResultEvent(
        envelope({
          status: 'success',
          login: envelope({ status: 'success', redirectTo: 'https://app/h' }),
        }),
      ),
    ).toBeUndefined();
    expect(
      container.qrResultEvent(envelope({ status: 'success' })),
    ).toBeUndefined(); // 防御：外层 success 必附 login（pollResult 契约）
  });
});

describe('isErrorStatus（§4.1 行 395：非 success 即失败，轮询进行中除外）', () => {
  test('流程 / 轮询 / captcha 中间态不作失败处理', () => {
    for (const status of [
      'idle', 'next', 'mfa_required', 'binding_required', 'success',
      'captcha_required', 'captcha_invalid', 'pending', 'scanned', 'expired',
    ] as const) {
      expect(container.isErrorStatus(status)).toBe(false);
    }
  });

  test('失败态渲染 ErrorBanner（failed / locked / invalid_credentials…）', () => {
    for (const status of ['failed', 'locked', 'invalid_credentials', 'too_many_requests'] as const) {
      expect(container.isErrorStatus(status)).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// factors/registry（§4.3）
// ---------------------------------------------------------------------------

describe('lookupFactor（§4.3 行 434：映射表三态）', () => {
  test('password → PasswordForm；totp → null（通用 FormStep 语义）；webauthn → WebAuthnButton；其余缺映射 → undefined', () => {
    expect(lookupFactor('password')).toBe(PasswordForm);
    expect(lookupFactor('totp')).toBeNull();
    expect(lookupFactor('otp_sms')).toBe(OTPForm);
    expect(lookupFactor('webauthn')).toBe(WebAuthnButton);
    expect(lookupFactor('recovery_code')).toBe(RecoveryCodeForm);
    expect(lookupFactor('thirdparty')).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// MethodTabs（§4.1 行 384；需求 §4.1.6 capability 自动隐藏）
// ---------------------------------------------------------------------------

describe('groupProviders（§2.7.1：uiGroup 分组 + sortOrder 排序 + channel=api 过滤）', () => {
  const providers: SnapshotProvider[] = [
    { providerKey: 'wxmp', displayName: '微信', type: 'wechat_mp', channel: 'api', uiGroup: 'social', sortOrder: '30' },
    { providerKey: 'qq', displayName: 'QQ', type: 'qq', channel: 'redirect', uiGroup: 'social', sortOrder: '10' },
    { providerKey: 'ent', displayName: '企业SSO', type: 'cas', channel: 'redirect', uiGroup: 'enterprise', sortOrder: '5' },
    { providerKey: 'scan', displayName: '微信扫码', type: 'wechat_mp_scan', channel: 'qrcode', uiGroup: 'social', sortOrder: '20' },
  ];

  test('api 渠道过滤 + 组内 sortOrder 升序 + uiGroup 分组（组序按排序后首元素）', () => {
    const groups = groupProviders(providers);
    expect([...groups.keys()]).toEqual(['enterprise', 'social']);
    expect(groups.get('enterprise')?.map((p) => p.providerKey)).toEqual(['ent']);
    expect(groups.get('social')?.map((p) => p.providerKey)).toEqual(['qq', 'scan']);
  });

  test('sortOrder 缺失 / 非法兜底 0（§1.12 / §9 第 18 条）', () => {
    const groups = groupProviders([
      { providerKey: 'b', type: 't', channel: 'redirect', sortOrder: '10' },
      { providerKey: 'a', type: 't', channel: 'redirect' },
      { providerKey: 'c', type: 't', channel: 'redirect', sortOrder: 'abc' },
    ]);
    expect(groups.get('')?.map((p) => p.providerKey)).toEqual(['a', 'c', 'b']);
  });

  test('空列表 → 空分组', () => {
    expect(groupProviders([]).size).toBe(0);
  });
});

describe('MethodTabs 静态渲染', () => {
  function renderTabs(methods = SNAPSHOT.methods, current = ''): string {
    return renderToStaticMarkup(
      createElement(MethodTabs, { methods, current, onSelect: () => {} }),
    );
  }

  test('主因子 tab（数组序 = 后端 sort_order 排序结果）+ 因子名取 i18n 字典', () => {
    const markup = renderTabs();
    expect(markup).toContain('密码登录');
    expect(markup).toContain('短信验证码');
  });

  test('usage 不含 primary 的方式不展示（§2.1：login 页只展示主因子方式）', () => {
    expect(renderTabs()).not.toContain('动态口令');
  });

  test('capability 不满足自动隐藏（需求 §4.1.6；node 无 window.PublicKeyCredential）', () => {
    expect(renderTabs()).not.toContain('通行密钥');
  });

  test('capability 满足时展示（stub window.PublicKeyCredential）', () => {
    rs.stubGlobal('window', { PublicKeyCredential: {} });
    expect(renderTabs()).toContain('通行密钥');
  });

  test('图标墙：channel=api 不渲染、uiGroup 分组、组内 sortOrder 排序、icon 渲染', () => {
    const markup = renderTabs();
    expect(markup).not.toContain('微信</span>'); // wechat_mp（channel=api）不渲染
    expect(markup.indexOf('data-group="enterprise"')).toBeLessThan(
      markup.indexOf('data-group="social"'),
    );
    expect(markup.indexOf('QQ')).toBeLessThan(markup.indexOf('微信扫码')); // 组内 10 < 20
    expect(markup).toContain('src="https://ex.test/qq.png"');
  });

  test('空列表 → 空状态提示（§8.2 行 582）', () => {
    expect(renderTabs([])).toContain('暂无可用登录方式');
  });
});

// ---------------------------------------------------------------------------
// PasswordForm 静态渲染（CapsLock 交互为浏览器事件，node 边界外）
// ---------------------------------------------------------------------------

describe('PasswordForm 静态渲染（§4.3 行 435）', () => {
  const fields = [
    create(FieldSchema, { name: 'username', label: '用户名/邮箱/手机号', type: 'text', required: true }),
    create(FieldSchema, { name: 'password', label: '密码', type: 'password', required: true }),
  ];

  function renderForm(props?: { loading?: boolean; disabled?: boolean }): string {
    return renderToStaticMarkup(
      createElement(PasswordForm, {
        fields,
        loading: props?.loading ?? false,
        disabled: props?.disabled ?? false,
        onSubmit: () => {},
      }),
    );
  }

  test('字段驱动渲染（§2.1 下发为准）：label + 密码框 + 提交按钮', () => {
    const markup = renderForm();
    expect(markup).toContain('<form');
    expect(markup).toContain('用户名/邮箱/手机号');
    expect(markup).toContain('type="password"');
    expect(markup).toContain('登录');
  });

  test('CapsLock 默认关闭不提示；loading / disabled 禁用提交（§3.2）', () => {
    expect(renderForm()).not.toContain('Caps Lock');
    expect(renderForm({ loading: true })).toContain('disabled=""');
    expect(renderForm({ disabled: true })).toContain('disabled=""');
  });
});

// ---------------------------------------------------------------------------
// runSubmit 编排全链（msw 拦截 api 层；§2.2 / §1.6 / §2.5）
// ---------------------------------------------------------------------------

describe('runSubmit 编排全链（idle → captcha_required → 带 captcha 重交 → success 终点）', () => {
  test('首次提交（无 captcha）→ captcha_required：权威 captcha 对象落信封 + loginToken 覆盖', async () => {
    server.use(
      http.post(LOGIN_DEFAULT, () =>
        HttpResponse.json({
          status: 'captcha_required',
          loginToken: 'tok-1',
          captcha: { providerKey: 'builtin_image', type: 'image' },
        }),
      ),
    );

    let state = flowReducer(INITIAL_FLOW_STATE, {
      type: 'select_method',
      method: 'password',
      firstStep: 'verify',
    });
    state = flowReducer(state, { type: 'request_started', step: 'verify' });

    const first = await container.runSubmit(
      state,
      { username: 'alice', password: 'pw' },
      () => undefined, // 首次无 captcha 凭据（§3.5：未完成 → undefined 不带）
      apiMod.loginDefault,
    );
    expect(first.failed).toBe(false);
    state = first.events.reduce(flowReducer, state);

    // §1.6 行 240：按响应顶层 captcha 渲染并重提（权威来源，§2.5 行 518）。
    expect(state.status).toBe('captcha_required');
    expect(state.envelope?.captcha?.providerKey).toBe('builtin_image');
    expect(state.envelope?.captcha?.type).toBe('image');
    expect(selectShowCaptcha(state)).toBe(true);
    expect(getLoginToken()).toBe('tok-1'); // §1.3 行 145：无条件覆盖
  });

  test('带 captcha 三元组重交 → success：请求体含 §2.5 提交格式 + 终点跳 syncCookieUrl', async () => {
    // 前置：先到 captcha_required（loginToken = tok-1）。
    server.use(
      http.post(LOGIN_DEFAULT, () =>
        HttpResponse.json({
          status: 'captcha_required',
          loginToken: 'tok-1',
          captcha: { providerKey: 'builtin_image', type: 'image' },
        }),
      ),
    );
    let state = flowReducer(INITIAL_FLOW_STATE, {
      type: 'select_method',
      method: 'password',
      firstStep: 'verify',
    });
    state = (
      await container.runSubmit(
        state,
        { username: 'alice', password: 'pw' },
        () => undefined,
        apiMod.loginDefault,
      )
    ).events.reduce(flowReducer, state);
    expect(state.status).toBe('captcha_required');

    // 重交：断言请求体 + success 终点。
    let raw = '';
    server.use(
      http.post(LOGIN_DEFAULT, async ({ request }) => {
        raw = await request.text();
        return HttpResponse.json({
          status: 'success',
          syncCookieUrl: 'https://sync.test/first',
          redirectTo: 'https://app.test/home',
        });
      }),
    );
    const second = await container.runSubmit(
      state,
      { username: 'alice', password: 'pw' },
      () =>
        create(CaptchaPayloadSchema, {
          providerKey: 'builtin_image',
          id: 'b7f3',
          answer: '123',
        }),
      apiMod.loginDefault,
    );
    expect(second.failed).toBe(false);
    state = second.events.reduce(flowReducer, state);
    expect(state.status).toBe('success');

    // 请求体：loginToken 顶层注入（§1.8）+ payload.captcha 自绘三元组（§2.5 行 503-506，token 零值省略）。
    expect(JSON.parse(raw)).toEqual({
      loginToken: 'tok-1',
      method: 'password',
      step: 'verify',
      payload: {
        username: 'alice',
        password: 'pw',
        captcha: { providerKey: 'builtin_image', id: 'b7f3', answer: '123' },
      },
    });

    // 终点（§4.1 行 383）：complete 副作用 → syncCookieUrl 优先（首跳完整 URL）。
    const redirects: string[] = [];
    const restarts: string[] = [];
    container.executeEffects(state.effects, {
      complete: (url) => redirects.push(url),
      restart: (status) => restarts.push(status),
    });
    expect(redirects).toEqual(['https://sync.test/first']);
    expect(restarts).toEqual([]);
    expect(getLoginToken()).toBe(''); // §1.3 行 145：success 清空（五条之 3）
  });

  test('locked 失败态：不可重试禁用提交 + 信封 error 展示字段（§1.6 行 244）', async () => {
    server.use(
      http.post(LOGIN_DEFAULT, () =>
        HttpResponse.json({
          status: 'locked',
          error: { message: '暂时锁定', retryAfter: '21600' },
        }),
      ),
    );
    let state = flowReducer(INITIAL_FLOW_STATE, {
      type: 'select_method',
      method: 'password',
      firstStep: 'verify',
    });
    const result = await container.runSubmit(
      state,
      { username: 'alice', password: 'pw' },
      () => undefined,
      apiMod.loginDefault,
    );
    state = result.events.reduce(flowReducer, state);
    expect(state.status).toBe('locked');
    expect(container.isErrorStatus(state.status)).toBe(true);
    expect(selectSubmitDisabled(state)).toBe(true); // §1.6「可重试 = 否」
    expect(state.envelope?.error?.retryAfter).toBe(BigInt(21600));
    expect(state.envelope?.error?.message).toBe('暂时锁定');
  });

  test('restart 类（token_expired）：副标记回第一步（§1.6 行 251）', async () => {
    server.use(
      http.post(LOGIN_DEFAULT, () =>
        HttpResponse.json({ status: 'token_expired' }),
      ),
    );
    let state = flowReducer(INITIAL_FLOW_STATE, {
      type: 'select_method',
      method: 'password',
      firstStep: 'verify',
    });
    const result = await container.runSubmit(
      state,
      { username: 'alice', password: 'pw' },
      () => undefined,
      apiMod.loginDefault,
    );
    state = result.events.reduce(flowReducer, state);
    const restarts: string[] = [];
    container.executeEffects(state.effects, {
      complete: () => {
        restarts.push('should-not-complete');
      },
      restart: (status) => restarts.push(status),
    });
    expect(restarts).toEqual(['token_expired']);
  });

  test('传输层失败（非 200）→ 回第一步 + failed 兜底（§1.6 行 272，不暴露细节）', async () => {
    server.use(
      http.post(LOGIN_DEFAULT, () => new HttpResponse(null, { status: 500 })),
    );
    let state = flowReducer(INITIAL_FLOW_STATE, {
      type: 'select_method',
      method: 'password',
      firstStep: 'verify',
    });
    const result = await container.runSubmit(
      state,
      { username: 'alice', password: 'pw' },
      () => undefined,
      apiMod.loginDefault,
    );
    expect(result.failed).toBe(true);
    state = result.events.reduce(flowReducer, state);
    expect(state.status).toBe('idle'); // reset → 回到第一步
  });

  test('OTP challenge → next(kind=form)：advance 推进 step 到 verify（§1.10 行 306-307）', async () => {
    let raw = '';
    server.use(
      http.post(LOGIN_DEFAULT, async ({ request }) => {
        raw = await request.text();
        return HttpResponse.json({
          status: 'next',
          loginToken: 'tok-2',
          nextStep: {
            kind: 'form',
            method: 'otp_sms',
            fields: [{ name: 'code', label: '验证码', type: 'otp', length: '6' }],
            retryAfter: '60',
          },
        });
      }),
    );
    let state = flowReducer(INITIAL_FLOW_STATE, {
      type: 'select_method',
      method: 'otp_sms',
      firstStep: 'challenge',
    });
    state = flowReducer(state, { type: 'request_started', step: 'challenge' });
    const result = await container.runSubmit(
      state,
      { phone: '13800000000' },
      () => undefined,
      apiMod.loginDefault,
    );
    expect(result.failed).toBe(false);
    // 请求体：challenge 步 payload 带 phone（§2.6 行 544）；loginToken 空为
    // 零值、protojson 省略（§1.1），故不出现。
    expect(JSON.parse(raw)).toEqual({
      method: 'otp_sms',
      step: 'challenge',
      payload: { phone: '13800000000' },
    });
    state = result.events.reduce(flowReducer, state);
    expect(state.status).toBe('next');
    expect(state.step).toBe('verify'); // advance 推进（form 步 → 请求侧 verify）
    expect(state.envelope?.nextStep?.kind).toBe('form');
    expect(state.envelope?.nextStep?.retryAfter).toBe(BigInt(60)); // 重发冷却（bigint）
  });

  test('mfa recovery_code verify 提交：payload {code}（§2.6 行 550）→ success 终点', async () => {
    let raw = '';
    server.use(
      http.post(LOGIN_DEFAULT, async ({ request }) => {
        raw = await request.text();
        return HttpResponse.json({
          status: 'success',
          loginToken: 'tok-3',
          redirectTo: 'https://app.test/home',
        });
      }),
    );
    let state = flowReducer(INITIAL_FLOW_STATE, {
      type: 'select_method',
      method: 'recovery_code',
      firstStep: 'verify', // mfa 场景：form 步首步 → 请求侧 verify
    });
    state = flowReducer(state, { type: 'request_started', step: 'verify' });
    const result = await container.runSubmit(
      state,
      { code: 'abcd-1234' },
      () => undefined,
      apiMod.loginDefault,
    );
    expect(result.failed).toBe(false);
    expect(JSON.parse(raw)).toEqual({
      method: 'recovery_code',
      step: 'verify',
      payload: { code: 'abcd-1234' }, // xxxx-xxxx 原样提交（不做格式化）
    });
    state = result.events.reduce(flowReducer, state);
    expect(state.status).toBe('success'); // 二次因子过 → 终点
  });

  test('webauthn challenge → next(kind=form)：payload {}（§2.6 行 547）+ advance 推进 + challengeData 信封下发（§1.3 行 117）', async () => {
    let raw = '';
    server.use(
      http.post(LOGIN_DEFAULT, async ({ request }) => {
        raw = await request.text();
        return HttpResponse.json({
          status: 'next',
          loginToken: 'tok-4',
          nextStep: {
            kind: 'form',
            method: 'webauthn',
            challengeData: { challenge: 'k9v0x8', rpId: 'example.test' },
          },
        });
      }),
    );
    let state = flowReducer(INITIAL_FLOW_STATE, {
      type: 'select_method',
      method: 'webauthn',
      firstStep: 'challenge', // §1.10 行 308：challenge → form
    });
    state = flowReducer(state, { type: 'request_started', step: 'challenge' });
    const result = await container.runSubmit(
      state,
      {}, // challenge 步空 payload（usernameless 不收集用户名，§2.6 行 547）
      () => undefined,
      apiMod.loginDefault,
    );
    expect(result.failed).toBe(false);
    expect(JSON.parse(raw)).toEqual({
      method: 'webauthn',
      step: 'challenge',
      payload: {},
    });
    state = result.events.reduce(flowReducer, state);
    expect(state.status).toBe('next');
    expect(state.step).toBe('verify'); // advance 推进（§1.10 行 306-307 同款）
    // Struct 不解析、整体透传到信封（§12.9 行 1784）。
    expect(state.envelope?.nextStep?.challengeData).toEqual({
      challenge: 'k9v0x8',
      rpId: 'example.test',
    });
  });

  test('webauthn verify 提交：payload {credential}（§2.6 行 548 断言原样）→ success 终点', async () => {
    let raw = '';
    server.use(
      http.post(LOGIN_DEFAULT, async ({ request }) => {
        raw = await request.text();
        return HttpResponse.json({
          status: 'success',
          loginToken: 'tok-5',
          redirectTo: 'https://app.test/home',
        });
      }),
    );
    const ASSERTION = {
      id: 'cred-1',
      rawId: 'cred-1',
      type: 'public-key',
      response: { clientDataJSON: 'eyJ9', authenticatorData: 'o2NmbQ' },
    };
    let state = flowReducer(INITIAL_FLOW_STATE, {
      type: 'select_method',
      method: 'webauthn',
      firstStep: 'verify', // verify 段断言提交（challenge 步 advance 后）
    });
    state = flowReducer(state, { type: 'request_started', step: 'verify' });
    const result = await container.runSubmit(
      state,
      { credential: ASSERTION }, // Struct JSON 不走表单值通道（容器 submitCredential 组装）
      () => undefined,
      apiMod.loginDefault,
    );
    expect(result.failed).toBe(false);
    // @simplewebauthn 断言对象原样提交（§12.9 行 1783 credential 透传）。
    expect(JSON.parse(raw)).toEqual({
      method: 'webauthn',
      step: 'verify',
      payload: { credential: ASSERTION },
    });
    state = result.events.reduce(flowReducer, state);
    expect(state.status).toBe('success'); // 断言过 → 终点
  });
});

// ---------------------------------------------------------------------------
// LoginFlowView 状态分支静态渲染（§4.1 行 386-395 状态机图）
// ---------------------------------------------------------------------------

describe('LoginFlowView 状态分支静态渲染', () => {
  test('idle 未选方式：MethodTabs + 引导提示', () => {
    const markup = renderView(INITIAL_FLOW_STATE);
    expect(markup).toContain('密码登录');
    expect(markup).toContain('请选择登录方式');
    expect(markup).not.toContain('<form'); // 未选方式不渲染因子表单
  });

  test('选中 password：因子表单渲染（字段驱动，§2.1）', () => {
    const markup = renderView(stateWith({ method: 'password', step: 'verify' }));
    expect(markup).toContain('<form');
    expect(markup).toContain('用户名/邮箱/手机号');
    expect(markup).toContain('登录');
  });

  test('captcha_required：表单保留原地 + 原地插入 CaptchaWidget（§4.1 行 391）', () => {
    const markup = renderView(
      stateWith({
        method: 'password',
        step: 'verify',
        status: 'captcha_required',
        envelope: envelope({
          status: 'captcha_required',
          captcha: create(CaptchaConfigSchema, {
            providerKey: 'builtin_image',
            type: 'image',
          }),
        }),
      }),
    );
    expect(markup).toContain('<form'); // 不刷新页面、表单保留
    expect(markup).toContain('<div></div>'); // CaptchaWidget 容器（type=image）
    expect(markup).not.toContain('role="alert"'); // captcha_required 非失败态
  });

  test('mfa_required：原地渲染选择器（不跳页，§4.1 行 407）+ 未选择引导 + 因子名字典', () => {
    const markup = renderView(
      stateWith({
        method: 'password',
        status: 'mfa_required',
        envelope: envelope({
          status: 'mfa_required',
          mfa: create(MfaSchema, {
            methods: [
              create(MfaMethodSchema, {
                method: 'totp',
                steps: ['form'],
                fields: [create(FieldSchema, { name: 'code', label: '动态口令', type: 'totp', required: true, length: BigInt(6) })],
              }),
              create(MfaMethodSchema, { method: 'otp_sms', steps: ['challenge', 'form'], maskedTarget: '138****8000' }),
              create(MfaMethodSchema, { method: 'recovery_code', steps: ['form'], fields: [create(FieldSchema, { name: 'code', label: '恢复码', type: 'text', required: true })] }),
            ],
          }),
        }),
      }),
    );
    expect(markup).toContain('请选择二次验证方式');
    expect(markup).toContain('动态口令'); // t('factors.totp')
    expect(markup).toContain('短信验证码'); // t('factors.otp_sms')
    expect(markup).toContain('恢复码'); // t('factors.recovery_code')
    // 未选择二次方式：只渲染选择器，不渲染因子表单。
    expect(markup).not.toContain('<form');
  });

  test('mfa_required webauthn 条目 → 选择器显示 hint 提示文案（§1.3 行 125）', () => {
    const markup = renderView(
      stateWith({
        method: 'password',
        status: 'mfa_required',
        envelope: envelope({
          status: 'mfa_required',
          mfa: create(MfaSchema, {
            methods: [
              // hint 零值（其余因子）：不渲染提示 span。
              create(MfaMethodSchema, { method: 'totp', steps: ['form'] }),
              create(MfaMethodSchema, {
                method: 'webauthn',
                steps: ['challenge', 'form'],
                hint: '请触摸已绑定的通行密钥设备',
              }),
            ],
          }),
        }),
      }),
    );
    expect(markup).toContain('通行密钥'); // t('factors.webauthn')
    expect(markup).toContain('请触摸已绑定的通行密钥设备'); // §1.3 行 125 hint
    // hint 零值条目（totp）不出现空提示。
    expect(markup).not.toContain('动态口令</span>');
  });

  test('binding_required：原地渲染 BindingPage 两选项（§4.1 行 406 / §2.7.5）；轮询态占位保留', () => {
    const markup = renderView(
      stateWith({
        status: 'binding_required',
        envelope: envelope({
          status: 'binding_required',
          binding: create(BindingSchema, {
            providerKey: 'qq',
            displayName: 'QQ',
            allowSignup: true,
          }),
        }),
      }),
    );
    expect(markup).toContain('创建新账号'); // §2.7.5 两选项
    expect(markup).toContain('退出并使用其他账号登录');
    expect(markup).toContain('该第三方身份尚未绑定账号'); // t('errors.status.binding_required')
    expect(markup).not.toContain('绑定已有账号'); // §2.7.5 行 676：不渲染绑定已有账号分支
    // 信封 binding 零值兜底（§9 第 18 条）：缺失时兜底提示，仅保留退出。
    expect(
      renderView(
        stateWith({
          status: 'binding_required',
          envelope: envelope({ status: 'binding_required' }),
        }),
      ),
    ).toContain('请刷新重试');
    // 轮询态占位不变（扫码组件归后续实现）。
    expect(
      renderView(stateWith({ status: 'pending', envelope: envelope({ status: 'pending' }) })),
    ).toContain('扫码流程即将支持');
  });

  test('locked 失败态：ErrorBanner（i18n 文案 + 信封兜底字段，§1.6）', () => {
    const markup = renderView(
      stateWith({
        method: 'password',
        status: 'locked',
        envelope: envelope({
          status: 'locked',
          error: { message: '暂时锁定', retryAfter: '21600' },
        }),
      }),
    );
    expect(markup).toContain('role="alert"');
    expect(markup).toContain('密码登录已被暂时锁定'); // t('errors.status.locked')
    expect(markup).toContain('disabled=""'); // selectSubmitDisabled → 提交禁用
  });

  test('restart 提示（notice）：errors.status.* 文案（§4.1 行 403）', () => {
    const markup = renderView(
      stateWith({ method: 'password' }),
      'errors.status.token_expired',
    );
    expect(markup).toContain('登录已超时，请重新登录');
  });

  test('选中 webauthn（challenge 步）：PublicKeyCredential 缺失 → 隐藏；满足 → WebAuthnButton 发起按钮（§4.3 行 453）', () => {
    // node 无 window：组件渲染空（需求 §4.1.6 行 105 不支持自动不展示；
    // MethodTabs 的 webauthn tab 同因 capability 隐藏）。
    expect(
      renderView(stateWith({ method: 'webauthn', step: 'challenge' })),
    ).not.toContain('使用通行密钥登录');
    rs.stubGlobal('window', { PublicKeyCredential: {} });
    const markup = renderView(stateWith({ method: 'webauthn', step: 'challenge' }));
    expect(markup).toContain('使用通行密钥登录');
    expect(markup).not.toContain('<form'); // 不走通用字段渲染器（§4.3 行 453）
  });

  test('缺映射（未注册 method）→ 兜底错误态，不静默回退（§4.3 行 434）', () => {
    const markup = renderView(stateWith({ method: 'nosuchfactor', step: 'challenge' }));
    expect(markup).toContain('请刷新重试');
    expect(markup).not.toContain('<form');
  });

  test('totp（显式 null）→ FormStep 通用渲染（§4.3 行 434 语义落地）', () => {
    const markup = renderView(stateWith({ method: 'totp', step: 'verify' }));
    expect(markup).toContain('<form');
    expect(markup).toContain('登录'); // FormStep 提交按钮（快照 totp 无 fields → 空表单）
  });

  test('success：跳转中文案（终点由 complete 副作用执行）', () => {
    const markup = renderView(
      stateWith({
        status: 'success',
        envelope: envelope({ status: 'success', redirectTo: 'https://app.test/home' }),
      }),
    );
    expect(markup).toContain('登录成功，正在跳转');
  });

  test('status=next + kind=form → StepDispatcher 分派 FormStep（§4.2 行 423-424）', () => {
    const markup = renderView(
      stateWith({
        method: 'totp',
        step: 'verify',
        status: 'next',
        envelope: envelope({
          status: 'next',
          nextStep: create(NextStepSchema, {
            kind: 'form',
            method: 'totp',
            fields: [create(FieldSchema, { name: 'code', label: '动态口令', type: 'totp', required: true, length: BigInt(6) })],
          }),
        }),
      }),
    );
    expect(markup).toContain('<form');
    expect(markup).toContain('动态口令');
  });

  test('status=next + 未实现 kind（poll 扩展位）/ external 宿主承载 → 兜底「请刷新重试」（redirect / challenge / qrcode 已实体化，断言归 steps.test.tsx）', () => {
    for (const kind of ['poll', 'external']) {
      const markup = renderView(
        stateWith({
          method: 'otp_sms',
          step: 'challenge',
          status: 'next',
          envelope: envelope({
            status: 'next',
            nextStep: create(NextStepSchema, { kind, method: 'otp_sms' }),
          }),
        }),
      );
      expect(markup).toContain('请刷新重试');
      expect(markup).not.toContain('<form');
    }
  });

  test('status=next + kind=form（otp_sms）→ OTPForm verify 段：CodeInput + 重发倒计时（§4.3 行 436）', () => {
    const markup = renderView(
      stateWith({
        method: 'otp_sms',
        step: 'verify',
        status: 'next',
        envelope: envelope({
          status: 'next',
          nextStep: create(NextStepSchema, {
            kind: 'form',
            method: 'otp_sms',
            fields: [create(FieldSchema, { name: 'code', label: '验证码', type: 'otp', required: true, length: BigInt(6) })],
            retryAfter: BigInt(60),
          }),
        }),
      }),
    );
    expect(markup).toContain('autoComplete="one-time-code"');
    expect(markup).toContain('60 秒后可重发');
  });

  test('status=next + kind=form（webauthn）→ WebAuthnButton 断言按钮 + challengeData 信封注入（§1.3 行 117 / §2.6 行 547-548）', () => {
    rs.stubGlobal('window', { PublicKeyCredential: {} });
    const markup = renderView(
      stateWith({
        method: 'webauthn',
        step: 'verify',
        status: 'next',
        envelope: envelope({
          status: 'next',
          nextStep: create(NextStepSchema, {
            kind: 'form',
            method: 'webauthn',
            challengeData: { challenge: 'k9v0x8', rpId: 'example.test' },
          }),
        }),
      }),
    );
    expect(markup).toContain('验证'); // challengeData 注入 → 断言按钮
    expect(markup).not.toContain('使用通行密钥登录'); // 非 challenge 步发起按钮
  });
});

// ---------------------------------------------------------------------------
// mfa 场景视图（选择器切换渲染；§4.1 行 407 原地、不跳页）
// ---------------------------------------------------------------------------

describe('LoginFlowView mfa 场景渲染（信封 mfa / 本地镜像 mfaMethods）', () => {
  const MFA_METHODS: MfaMethod[] = [
    create(MfaMethodSchema, {
      method: 'totp',
      steps: ['form'],
      fields: [create(FieldSchema, { name: 'code', label: '动态口令', type: 'totp', required: true, length: BigInt(6) })],
    }),
    create(MfaMethodSchema, { method: 'otp_sms', steps: ['challenge', 'form'], maskedTarget: '138****8000' }),
    create(MfaMethodSchema, {
      method: 'recovery_code',
      steps: ['form'],
      fields: [create(FieldSchema, { name: 'code', label: '恢复码', type: 'text', required: true })],
    }),
  ];

  function renderMfa(state: FlowState, otpCode?: string): string {
    return renderToStaticMarkup(
      createElement(container.LoginFlowView, {
        snapshot: SNAPSHOT,
        state,
        onSelect: () => {},
        onSelectMfa: () => {},
        onSubmit: () => {},
        onResend: () => {},
        otpCode,
        onOtpCodeChange: () => {},
        mfaMethods: MFA_METHODS,
      }),
    );
  }

  test('选择 totp 后（select_method 清信封 → 本地镜像驱动）：选择器高亮 + FormStep 渲染下发字段', () => {
    // 模拟 select_method('totp', firstStep='verify') 之后的 idle 态（§4.1 行 407 不跳页）。
    const markup = renderMfa(stateWith({ method: 'totp', step: 'verify' }));
    expect(markup).toContain('动态口令');
    expect(markup).toContain('aria-current="true"');
    expect(markup).toContain('<form');
    // mfa 场景不渲染主因子方式列表（MethodTabs 归主流程第一步）。
    expect(markup).not.toContain('请选择登录方式');
  });

  test('选择器切换：选中 otp_sms → OTPForm challenge 段展示掩码目标（§2.6 行 545 不传目标）', () => {
    const markup = renderMfa(stateWith({ method: 'otp_sms', step: 'challenge' }));
    expect(markup).toContain('138****8000');
    expect(markup).toContain('发送验证码');
    expect(markup).not.toContain('type="tel"');
  });

  test('选中 recovery_code → RecoveryCodeForm 渲染下发恢复码字段', () => {
    const markup = renderMfa(stateWith({ method: 'recovery_code', step: 'verify' }));
    expect(markup).toContain('恢复码');
    expect(markup).toContain('登录');
  });

  test('mfa 场景失败态（invalid_code）：选择器 + OTPForm verify 段保留原地重试（§1.6 可重试）', () => {
    const markup = renderMfa(
      stateWith({
        method: 'otp_sms',
        step: 'verify',
        status: 'invalid_code',
        envelope: envelope({
          status: 'invalid_code',
          error: { message: '验证码错误', attemptsLeft: '3' },
        }),
      }),
      // 容器持值注入——失败态（next 槽位↔直渲染位切换）实例重建
      // 后已输码仍在视图（§1.6 行 247 原地重试不清输入）。
      '123456',
    );
    expect(markup).toContain('aria-current="true"');
    expect(markup).toContain('还可尝试 3 次'); // error.attemptsLeft（§1.3 行 151）
    expect(markup).toContain('role="alert"'); // ErrorBanner（可重试失败态）
    expect(markup).toContain('value="1"'); // CodeInput 首格回填（容器持值）
  });
});

// ---------------------------------------------------------------------------
// LoginContainer 容器壳（静态 smoke：编排壳组合渲染不炸）
// ---------------------------------------------------------------------------

describe('LoginContainer 静态 smoke', () => {
  test('挂载渲染 = MethodTabs + 引导提示（effects 不执行，renderToStaticMarkup 语义）', () => {
    const markup = renderToStaticMarkup(
      createElement(container.LoginContainer, { snapshot: SNAPSHOT }),
    );
    expect(markup).toContain('密码登录');
    expect(markup).toContain('请选择登录方式');
  });

  // OAuth 回调 mfa_required 完整编排——初始信封直接进状态机。
  test('initialEnvelope（mfa_required）→ 挂载即渲染 MfaSelector + 未选方式引导（§1.6 行 233 不跳页；信封 mfa.methods 驱动，静态渲染读信封不依赖 effect 镜像）', () => {
    const markup = renderToStaticMarkup(
      createElement(container.LoginContainer, {
        snapshot: SNAPSHOT,
        initialEnvelope: envelope({
          status: 'mfa_required',
          loginToken: 'lt-mfa',
          mfa: {
            methods: [
              create(MfaMethodSchema, { method: 'totp', steps: ['form'] }),
              create(MfaMethodSchema, {
                method: 'otp_sms',
                steps: ['challenge', 'form'],
                maskedTarget: '138****8000',
              }),
            ],
          },
        }),
      }),
    );
    expect(markup).toContain('动态口令'); // factors.totp（MfaSelector 按钮）
    expect(markup).toContain('短信验证码'); // factors.otp_sms
    expect(markup).toContain('请选择二次验证方式'); // login.mfaSelectHint（未选方式）
    expect(markup).not.toContain('请选择登录方式'); // 不渲染主因子表单区
    expect(markup).not.toContain('正在处理'); // 非回调页处理中帧
  });
});

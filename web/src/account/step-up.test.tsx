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
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { create, toBinary, toJson } from '@bufbuild/protobuf';
import { UnbindTotpRequestSchema } from '../gen/proto/api/account/v1/mfa_pb';
import {
  StartVerificationRequestSchema,
  SubmitVerificationRequestSchema,
  VerificationMethodSchema,
} from '../gen/proto/api/common/v1/verification_pb';
import { CaptchaPayloadSchema } from '../gen/proto/api/sso/v1/login_pb';
import { CaptchaConfigSchema } from '../gen/proto/api/common/v1/captcha_pb';
import { ErrorInfoSchema } from '../gen/proto/api/common/v1/error_info_pb';
import { ApiError } from '../shared/api/errors';

const BASE = 'https://uc.test';
(globalThis as { __AUTHLOFT_INIT__?: unknown }).__AUTHLOFT_INIT__ = {
  al_root: `${BASE}/`,
  static_base: '/assets/',
};

const START_URL = `${BASE}/api.account.v1.AccountService/StartVerification`;
const SUBMIT_URL = `${BASE}/api.account.v1.AccountService/SubmitVerification`;
const UNBIND_TOTP_URL = `${BASE}/api.account.v1.AccountService/UnbindTotp`;

const server = setupServer();

let apiMod: typeof import('./api');
let componentsMod: typeof import('../shared/components/StepUpDialog');

beforeAll(async () => {
  server.listen({ onUnhandledRequest: 'error' });
  apiMod = await import('./api');
  componentsMod = await import('../shared/components/StepUpDialog');
});

beforeEach(() => {
  rs.stubGlobal('React', React);
});

afterEach(() => {
  server.resetHandlers();
  rs.unstubAllGlobals();
});

afterAll(() => {
  server.close();
  (globalThis as { __AUTHLOFT_INIT__?: unknown }).__AUTHLOFT_INIT__ = undefined;
});

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

async function captureRejection(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error('expected the promise to reject');
}

const { createElement } = React;

describe('二次验证请求构造（§3.8.2，纯函数）', () => {
  test('StartVerification：method 为空只取 methods[]；选定因子时 captcha 走请求顶层', () => {
    expect(
      toJson(
        StartVerificationRequestSchema,
        apiMod.buildStartVerificationRequest('unbind_totp', 'unbind_totp'),
      ),
    ).toEqual({ bizPurpose: 'unbind_totp', operation: 'unbind_totp' });

    const captcha = create(CaptchaPayloadSchema, {
      providerKey: 'builtin_image',
      id: 'cap-1',
      answer: '1234',
    });
    expect(
      toJson(
        StartVerificationRequestSchema,
        apiMod.buildStartVerificationRequest(
          'unbind_totp',
          'unbind_totp',
          'totp',
          captcha,
        ),
      ),
    ).toEqual({
      bizPurpose: 'unbind_totp',
      operation: 'unbind_totp',
      method: 'totp',
      captcha: { providerKey: 'builtin_image', id: 'cap-1', answer: '1234' },
    });
  });

  test('SubmitVerification：challengeToken / method / payload 原样承载（§2.6 {code}）', () => {
    expect(
      toJson(
        SubmitVerificationRequestSchema,
        apiMod.buildSubmitVerificationRequest('ct-1', 'totp', {
          code: '123456',
        }),
      ),
    ).toEqual({
      challengeToken: 'ct-1',
      method: 'totp',
      payload: { code: '123456' },
    });
  });

  test('UnbindTotp：verificationToken 是唯一载荷（缺失由服务端回 verification_required）', () => {
    expect(
      toJson(UnbindTotpRequestSchema, apiMod.buildUnbindTotpRequest('vt-1')),
    ).toEqual({ verificationToken: 'vt-1' });
  });
});

describe('StepUpDialog 因子字段（复用 mfa.methods[] + FieldRenderer）', () => {
  test('无 challengeFields 的验证码因子补 code 字段，位数取 codeLength', () => {
    const method = create(VerificationMethodSchema, {
      method: 'totp',
      steps: ['form'],
      codeLength: BigInt(6),
    });
    const fields = componentsMod.stepUpFields(method);
    expect(fields).toHaveLength(1);
    expect(fields[0]?.name).toBe('code');
    expect(fields[0]?.type).toBe('otp');
    expect(fields[0]?.length).toBe(BigInt(6));
    expect(componentsMod.stepUpPayload(fields, { code: '654321' })).toEqual({
      code: '654321',
    });
  });

  test('challengeFields（Struct 承载）映射为通用 Field；空值不进 payload', () => {
    const method = create(VerificationMethodSchema, {
      method: 'otp_sms',
      steps: ['challenge', 'form'],
      challengeFields: [{ name: 'phone', type: 'phone', required: true }],
    });
    const fields = componentsMod.stepUpFields(method);
    expect(fields[0]?.name).toBe('phone');
    expect(fields[0]?.type).toBe('phone');
    expect(fields[0]?.required).toBe(true);
    expect(componentsMod.stepUpPayload(fields, { phone: '' })).toEqual({});
  });

  test('webauthn 空 challengeFields 不合成 code 输入；静态帧不再有「暂不支持」降级（§2.6 verify 载荷是 credential）', () => {
    const webauthn = create(VerificationMethodSchema, {
      method: 'webauthn',
      steps: ['challenge', 'form'],
    });
    expect(componentsMod.stepUpFields(webauthn)).toEqual([]);

    const html = renderToStaticMarkup(
      createElement(componentsMod.StepUpDialogView, {
        phase: 'verify',
        methods: [webauthn],
        activeMethod: webauthn,
        values: {},
      }),
    );
    // webauthn 原生断言：正文无输入控件、无降级文案，提交由主按钮驱动。
    expect(html).not.toContain('<input');
    expect(html).not.toContain('暂不支持在此完成该验证方式');
  });

  test('主按钮禁用口径：未选方式 / 无字段 / 在途禁用；error 重试与 webauthn 断言恒可用', () => {
    const totp = create(VerificationMethodSchema, {
      method: 'totp',
      steps: ['form'],
      codeLength: BigInt(6),
    });
    const webauthn = create(VerificationMethodSchema, {
      method: 'webauthn',
      steps: ['challenge', 'form'],
    });
    const fields = componentsMod.stepUpFields(totp);
    // 取方式列表中 / 在途禁用。
    expect(
      componentsMod.stepUpOkDisabled('loading', undefined, [], false),
    ).toBe(true);
    expect(componentsMod.stepUpOkDisabled('verify', totp, fields, true)).toBe(
      true,
    );
    // verify 引导态（未选方式）与无可渲染字段禁用——不留「点了没反应」。
    expect(
      componentsMod.stepUpOkDisabled('verify', undefined, [], false),
    ).toBe(true);
    expect(componentsMod.stepUpOkDisabled('verify', totp, [], false)).toBe(
      true,
    );
    expect(
      componentsMod.stepUpOkDisabled('verify', totp, fields, false),
    ).toBe(false);
    // webauthn 断言由主按钮驱动（challengeData 由 Start 下发）→ 恒可用。
    expect(componentsMod.stepUpOkDisabled('verify', webauthn, [], false)).toBe(
      false,
    );
    // error 阶段主按钮即「重试」，恒可用。
    expect(
      componentsMod.stepUpOkDisabled('error', undefined, [], false),
    ).toBe(false);
  });

  test('因子失败文案：错误提示 + 剩余次数（§1.6 invalid_code）', () => {
    const failed = new ApiError({
      httpStatus: 400,
      code: 'invalid_code',
      message: 'code invalid',
      requestId: 'req-1',
      attemptsLeft: BigInt(3),
    });
    const text = componentsMod.stepUpErrorText(failed);
    expect(text).toContain('验证码错误');
    expect(text).toContain('还可尝试 3 次');
    // 无剩余次数时只留提示；未知异常走兜底、不透出内部信息。
    expect(
      componentsMod.stepUpErrorText(
        new ApiError({
          httpStatus: 400,
          code: 'invalid_code',
          message: '',
          requestId: '',
        }),
      ),
    ).toBe('验证码错误');
    expect(componentsMod.stepUpErrorText(new Error('boom'))).toBe(
      '操作失败，请稍后重试',
    );
  });
});

describe('StepUpDialog 分派与断言（纯函数）', () => {
  test('stepUpStartMode：OTP 下发恒拦截走 upfront；webauthn / totp / 恢复码走 reactive', () => {
    expect(componentsMod.stepUpStartMode('otp_sms')).toBe('upfront');
    expect(componentsMod.stepUpStartMode('otp_email')).toBe('upfront');
    expect(componentsMod.stepUpStartMode('webauthn')).toBe('reactive');
    expect(componentsMod.stepUpStartMode('totp')).toBe('reactive');
    expect(componentsMod.stepUpStartMode('recovery_code')).toBe('reactive');
  });

  test('stepUpAuthenticate：断言对象透传为 credential；NotAllowedError 区分取消与失败', async () => {
    const options = { challenge: 'k9v0x8' };
    const ok = await componentsMod.stepUpAuthenticate(options, {
      start: async (optionsJSON) => ({ id: 'cred-1', echo: optionsJSON }),
    });
    expect(ok).toEqual({
      ok: true,
      credential: { id: 'cred-1', echo: options },
    });
    const cancelled = await componentsMod.stepUpAuthenticate(options, {
      start: async () => {
        throw new DOMException('user denied', 'NotAllowedError');
      },
    });
    expect(cancelled).toEqual({ ok: false, cancelled: true });
    const failed = await componentsMod.stepUpAuthenticate(options, {
      start: async () => {
        throw new Error('boom');
      },
    });
    expect(failed).toEqual({ ok: false, cancelled: false });
  });
});

describe('StepUpDialogView 静态帧（tabs 一次提交，无 select / 「下一步」）', () => {
  const totp = create(VerificationMethodSchema, {
    method: 'totp',
    usage: ['secondary'],
    steps: ['form'],
    codeLength: BigInt(6),
  });
  const otpSms = create(VerificationMethodSchema, {
    method: 'otp_sms',
    usage: ['secondary'],
    steps: ['challenge', 'form'],
    codeLength: BigInt(6),
    resendAfter: BigInt(60),
  });
  const webauthn = create(VerificationMethodSchema, {
    method: 'webauthn',
    usage: ['secondary'],
    steps: ['challenge', 'form'],
    capability: 'window.PublicKeyCredential',
  });

  function renderView(
    props: Partial<Parameters<typeof componentsMod.StepUpDialogView>[0]> & {
      phase: 'loading' | 'verify' | 'error';
    },
  ): string {
    return renderToStaticMarkup(
      createElement(componentsMod.StepUpDialogView, props),
    );
  }

  test('tabs 常驻展示全部可用方式（factors.* 文案、当前项高亮），无 select / 下一步', () => {
    const html = renderView({
      phase: 'verify',
      methods: [totp, otpSms],
      activeMethod: totp,
      values: {},
    });
    expect(html).toContain('动态口令');
    expect(html).toContain('短信');
    expect(html).toContain('aria-current="true"');
    expect(html).not.toContain('<select');
    expect(html).not.toContain('下一步');
  });

  test('verify 引导态（未选方式）：tabs 区标题 + 引导，不出输入控件', () => {
    const html = renderView({
      phase: 'verify',
      methods: [totp],
      values: {},
    });
    expect(html).toContain('二次验证方式');
    expect(html).toContain('动态口令');
    expect(html).not.toContain('<input');
  });

  test('选中 otp_sms：FieldRenderer 输码 + 重发冷却倒计时（§2.6 challenge→form 两段由 Start 承担）', () => {
    const html = renderView({
      phase: 'verify',
      methods: [otpSms],
      activeMethod: otpSms,
      values: {},
      retryAfter: BigInt(60),
    });
    expect(html).toContain('autoComplete="one-time-code"');
    expect(html).toContain('60 秒后可重发');
    // 非 webauthn 且有字段：无降级文案。
    expect(html).not.toContain('暂不支持在此完成该验证方式');
  });

  test('loading / error / 无可用方式三态帧', () => {
    expect(
      renderView({ phase: 'loading', methods: [], values: {} }),
    ).toContain('加载中');
    const error = renderView({
      phase: 'error',
      methods: [],
      values: {},
      errorText: '动态口令错误',
    });
    expect(error).toContain('role="alert"');
    expect(error).toContain('动态口令错误');
    expect(
      renderView({ phase: 'verify', methods: [], values: {} }),
    ).toContain('当前没有可用的验证方式');
  });
});

describe('解绑 TOTP 全链（§3.5 行 1078、§3.8）', () => {
  test('Start → 选因子 Start → Submit → UnbindTotp 携带 verificationToken', async () => {
    const order: string[] = [];
    let unbindBody: unknown;
    server.use(
      http.post(START_URL, async ({ request }) => {
        const body = (await request.json()) as { method?: string };
        if (body.method === 'totp') {
          order.push('start-method');
          return HttpResponse.json({
            challengeToken: 'ct-1',
            methods: [
              {
                method: 'totp',
                usage: ['secondary'],
                steps: ['form'],
                codeLength: '6',
              },
            ],
            expiresIn: '300',
            nextStep: { kind: 'form' },
          });
        }
        order.push('start-methods');
        return HttpResponse.json({
          methods: [
            {
              method: 'totp',
              usage: ['secondary'],
              steps: ['form'],
              codeLength: '6',
            },
          ],
          expiresIn: '300',
        });
      }),
      http.post(SUBMIT_URL, async ({ request }) => {
        order.push('submit');
        expect(await request.json()).toEqual({
          challengeToken: 'ct-1',
          method: 'totp',
          payload: { code: '654321' },
        });
        return HttpResponse.json({
          verificationToken: 'vt-1',
          expiresIn: '120',
          amr: ['totp'],
        });
      }),
      http.post(UNBIND_TOTP_URL, async ({ request }) => {
        order.push('unbind');
        unbindBody = await request.json();
        return HttpResponse.json({});
      }),
    );

    // 与弹窗编排同构：先取 methods[]，选定因子后取挑战令牌，再提交因子。
    const methods = await apiMod.startVerification(
      apiMod.buildStartVerificationRequest('unbind_totp', 'unbind_totp'),
    );
    const selected = methods.methods[0]?.method ?? '';
    expect(selected).toBe('totp');

    const challenge = await apiMod.startVerification(
      apiMod.buildStartVerificationRequest(
        'unbind_totp',
        'unbind_totp',
        selected,
      ),
    );
    const fields = componentsMod.stepUpFields(challenge.methods[0]!);
    const submitted = await apiMod.submitVerification(
      apiMod.buildSubmitVerificationRequest(
        challenge.challengeToken,
        selected,
        componentsMod.stepUpPayload(fields, { code: '654321' }),
      ),
    );

    await apiMod.unbindTotp(
      apiMod.buildUnbindTotpRequest(submitted.verificationToken),
    );

    expect(order).toEqual([
      'start-methods',
      'start-method',
      'submit',
      'unbind',
    ]);
    expect(unbindBody).toEqual({ verificationToken: 'vt-1' });
  });

  test('Submit 失败不关窗：同一 challengeToken 可原地重试并成功', async () => {
    let attempts = 0;
    server.use(
      http.post(SUBMIT_URL, () => {
        attempts += 1;
        if (attempts === 1) {
          const info = create(ErrorInfoSchema, {
            domain: 'account',
            code: 'invalid_code',
            message: 'code invalid',
          });
          return HttpResponse.json(
            {
              code: 'failed_precondition',
              message: 'code invalid',
              details: [
                {
                  type: 'api.common.v1.ErrorInfo',
                  value: bytesToBase64(toBinary(ErrorInfoSchema, info)),
                },
              ],
            },
            { status: 400 },
          );
        }
        return HttpResponse.json({
          verificationToken: 'vt-2',
          expiresIn: '120',
          amr: ['totp'],
        });
      }),
    );

    const request = apiMod.buildSubmitVerificationRequest('ct-1', 'totp', {
      code: '111111',
    });
    const first = await captureRejection(apiMod.submitVerification(request));
    expect(first).toBeInstanceOf(ApiError);
    expect((first as ApiError).code).toBe('invalid_code');

    const second = await apiMod.submitVerification(request);
    expect(second.verificationToken).toBe('vt-2');
    expect(attempts).toBe(2);

    // 窗内错误帧：仍渲染因子输入与错误位，证明失败不关窗、可继续重试。
    const method = create(VerificationMethodSchema, {
      method: 'totp',
      steps: ['form'],
      codeLength: BigInt(6),
    });
    const html = renderToStaticMarkup(
      createElement(componentsMod.StepUpDialogView, {
        phase: 'verify',
        methods: [method],
        activeMethod: method,
        values: { code: '111111' },
        errorText: '动态口令错误',
      }),
    );
    expect(html).toContain('role="alert"');
    expect(html).toContain('动态口令错误');
    expect(html).toContain('<input');
  });
});

// ---------------------------------------------------------------------------
// StepUpDialog captcha gate 自闭环（§2.5 / §3.8.5）：弹窗持有 gate、按因子分派
// upfront / reactive，外部只注入基础配置。编排走导出的 runStepUpStart（组件
// beginMethod 同款接线），弹窗询问经脚本化 gate 作答（沿 login-container.test
// scriptedGate 边界惯例），StartVerification 用 msw 拦截。
// ---------------------------------------------------------------------------

/** 自绘图形码凭据（§2.5 三元组）。 */
function imageToken(id: string, answer: string) {
  return create(CaptchaPayloadSchema, {
    providerKey: 'builtin_image',
    id,
    answer,
  });
}

/**
 * gate 替身：跑真 runCaptchaGate 循环、把「弹窗询问」换成脚本化作答
 *（确认 → 凭据；用尽 / undefined → 取消），并记录每次询问的配置与次数。
 */
function scriptedGate(answers: ReturnType<typeof imageToken>[]) {
  const prompts: {
    config: unknown;
    invalid: boolean;
    attempt: number;
  }[] = [];
  const run: Parameters<typeof componentsMod.runStepUpStart>[3] = (options) =>
    // runCaptchaGate 的 prompt 由本替身提供；真实 hook 版见 useCaptchaGate。
    import('../shared/captcha/captchaGate').then(({ runCaptchaGate }) =>
      runCaptchaGate({
        ...options,
        prompt: async (next) => {
          prompts.push({
            config: next.config,
            invalid: next.invalid,
            attempt: next.attempt,
          });
          return answers[prompts.length - 1];
        },
      }),
    );
  return { run, prompts };
}

/** captcha 失败的非 200 Connect 错误体：ErrorInfo.code + details 并列 CaptchaConfig。 */
function captchaError(
  code: 'captcha_required' | 'captcha_invalid',
  config: { providerKey: string; type?: string },
) {
  const info = create(ErrorInfoSchema, { domain: 'account', code });
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

describe('StepUpDialog gate 自闭环（runStepUpStart：mode 分派 + 凭据注入）', () => {
  /** 组件同款 start 接线：凭据挂到 StartVerification 请求级 captcha（§3.8.2）。 */
  const startViaApi = (method: string, captcha?: unknown) =>
    apiMod.startVerification(
      apiMod.buildStartVerificationRequest(
        'unbind_totp',
        'unbind_totp',
        method,
        captcha as ReturnType<typeof imageToken> | undefined,
      ),
    );

  test('otp upfront：先问凭据再发（只发一次带凭据的请求），无配置退化为先探一次', async () => {
    const bodies: Record<string, unknown>[] = [];
    server.use(
      http.post(START_URL, async ({ request }) => {
        bodies.push((await request.json()) as Record<string, unknown>);
        return HttpResponse.json({
          challengeToken: 'ct-1',
          methods: [],
          expiresIn: '300',
        });
      }),
    );

    // 有配置 → upfront 先问再发，没有裸请求。
    const gate = scriptedGate([imageToken('up-1', '42')]);
    const response = await componentsMod.runStepUpStart(
      'otp_sms',
      create(CaptchaConfigSchema, { providerKey: 'builtin_image', type: 'image' }),
      startViaApi,
      gate.run,
    );
    expect(response?.challengeToken).toBe('ct-1');
    expect(gate.prompts).toHaveLength(1);
    expect(gate.prompts[0].attempt).toBe(0);
    expect(bodies).toHaveLength(1);
    expect(bodies[0]).toMatchObject({
      bizPurpose: 'unbind_totp',
      method: 'otp_sms',
      captcha: { providerKey: 'builtin_image', id: 'up-1', answer: '42' },
    });

    // 无配置 → 退化为先探一次（服务端未启用 captcha 的部署不该凭空弹窗）。
    const bareGate = scriptedGate([]);
    await componentsMod.runStepUpStart('otp_sms', undefined, startViaApi, bareGate.run);
    expect(bareGate.prompts).toHaveLength(0);
    expect(bodies).toHaveLength(2);
    expect(bodies[1]).not.toHaveProperty('captcha');
  });

  test('captcha_invalid：窗内换凭据循环（权威配置取错误体 details），不逃逸给调用方', async () => {
    const bodies: Record<string, unknown>[] = [];
    let calls = 0;
    server.use(
      http.post(START_URL, async ({ request }) => {
        bodies.push((await request.json()) as Record<string, unknown>);
        calls += 1;
        if (calls === 1) {
          return captchaError('captcha_required', {
            providerKey: 'cf_turnstile',
            type: 'turnstile',
          });
        }
        if (calls === 2) {
          // 厂商不可用 → 服务端降级为自绘图形码（§2.5），新配置随错误体下发。
          return captchaError('captcha_invalid', {
            providerKey: 'builtin_image',
            type: 'image',
          });
        }
        return HttpResponse.json({
          challengeToken: 'ct-2',
          methods: [],
          expiresIn: '300',
        });
      }),
    );

    const gate = scriptedGate([
      imageToken('id-1', 'aaa'),
      imageToken('id-2', 'bbb'),
    ]);
    const response = await componentsMod.runStepUpStart(
      'otp_email',
      undefined,
      startViaApi,
      gate.run,
    );
    expect(response?.challengeToken).toBe('ct-2');
    expect(gate.prompts).toHaveLength(2);
    expect(gate.prompts[0].config).toMatchObject({ type: 'turnstile' });
    expect(gate.prompts[0].invalid).toBe(false);
    // 降级后的权威配置 + invalid 文案位 + attempt 递增（widget 换新）。
    expect(gate.prompts[1].config).toMatchObject({
      providerKey: 'builtin_image',
      type: 'image',
    });
    expect(gate.prompts[1].invalid).toBe(true);
    expect(gate.prompts[1].attempt).toBe(1);
    expect(JSON.parse(JSON.stringify(bodies[2])).captcha).toEqual({
      providerKey: 'builtin_image',
      id: 'id-2',
      answer: 'bbb',
    });
  });

  test('totp reactive：裸发直通不弹窗（无下发场景，§2.5）', async () => {
    const bodies: Record<string, unknown>[] = [];
    server.use(
      http.post(START_URL, async ({ request }) => {
        bodies.push((await request.json()) as Record<string, unknown>);
        return HttpResponse.json({
          challengeToken: 'ct-1',
          methods: [],
          expiresIn: '300',
        });
      }),
    );

    const gate = scriptedGate([]);
    const response = await componentsMod.runStepUpStart(
      'totp',
      undefined,
      startViaApi,
      gate.run,
    );
    expect(response?.challengeToken).toBe('ct-1');
    expect(gate.prompts).toHaveLength(0);
    expect(bodies).toHaveLength(1);
    expect(bodies[0]).not.toHaveProperty('captcha');
  });

  test('用户取消 captcha 询问 → undefined（窗内原地保留，不抛错）', async () => {
    let calls = 0;
    server.use(
      http.post(START_URL, () => {
        calls += 1;
        return captchaError('captcha_required', {
          providerKey: 'builtin_image',
          type: 'image',
        });
      }),
    );

    const gate = scriptedGate([undefined]);
    const response = await componentsMod.runStepUpStart(
      'otp_sms',
      undefined,
      startViaApi,
      gate.run,
    );
    expect(response).toBeUndefined();
    expect(gate.prompts).toHaveLength(1);
    expect(calls).toBe(1); // 取消后不再重发
  });

  test('非 captcha 错误原样抛出交窗内错误位', async () => {
    server.use(
      http.post(START_URL, () => new HttpResponse(null, { status: 500 })),
    );
    const gate = scriptedGate([]);
    await expect(
      componentsMod.runStepUpStart('totp', undefined, startViaApi, gate.run),
    ).rejects.toBeInstanceOf(ApiError);
    expect(gate.prompts).toHaveLength(0);
  });
});

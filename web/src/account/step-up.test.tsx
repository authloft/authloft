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
import { MfaPolicyMethodSchema } from '../gen/proto/api/account/v1/profile_pb';
import { UnbindTotpRequestSchema } from '../gen/proto/api/account/v1/mfa_pb';
import {
  StartVerificationRequestSchema,
  SubmitVerificationRequestSchema,
  VerificationMethodSchema,
} from '../gen/proto/api/common/v1/verification_pb';
import { CaptchaPayloadSchema } from '../gen/proto/api/sso/v1/login_pb';
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
const SET_MFA_URL = `${BASE}/api.account.v1.AccountService/SetMfa`;

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
        selectedMethod: 'totp',
        fields: componentsMod.stepUpFields(method),
        values: { code: '111111' },
        errorText: '动态口令错误',
      }),
    );
    expect(html).toContain('role="alert"');
    expect(html).toContain('动态口令错误');
    expect(html).toContain('<input');
  });
});

describe('停用入口保持 SetMfa（§3.5 行 1075）', () => {
  test('停用 totp：SetMfa 全量集合替换移除该因子，payload 与改造前一致', async () => {
    let captured: unknown;
    server.use(
      http.post(SET_MFA_URL, async ({ request }) => {
        captured = await request.json();
        return HttpResponse.json({});
      }),
    );

    const methods = [
      create(MfaPolicyMethodSchema, {
        factor: 'totp',
        enabled: true,
        bound: true,
      }),
      create(MfaPolicyMethodSchema, {
        factor: 'otp_sms',
        enabled: true,
        bound: true,
      }),
    ];
    const built = apiMod.buildSetMfaRequest(methods, 'totp', false, false);
    expect(built.ok).toBe(true);
    if (!built.ok) {
      throw new Error('unreachable');
    }
    await apiMod.setMfa(built.request);

    expect(captured).toEqual({ methods: ['otp_sms'] });
  });
});

// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化后移除）。
// @ts-ignore
import { beforeEach, describe, expect, rs, test } from 'rstack/test';
import * as React from 'react';
// 本仓 rstest 为 node 环境（无 DOM）：静态渲染走 react-dom/server 的
// renderToStaticMarkup（沿 login-container.test.ts / components.test.ts 惯例）。
import { renderToStaticMarkup } from 'react-dom/server';
import { create } from '@bufbuild/protobuf';
import { CaptchaConfigSchema } from '../../gen/proto/api/common/v1/captcha_pb';
import {
  FieldSchema,
  LoginFlowResponseSchema,
  NextStepSchema,
  type LoginFlowResponse,
} from '../../gen/proto/api/sso/v1/envelope_pb';
import {
  CaptchaPayloadSchema,
  type CaptchaPayload,
} from '../../gen/proto/api/sso/v1/login_pb';
import {
  CreateQrcodeResponseSchema,
} from '../../gen/proto/api/sso/v1/ticket_pb';
import { ChallengeStep } from './ChallengeStep';
import { FormStep } from './FormStep';
import {
  QRCodeStep,
  completeLogin,
  dispatchQrResult,
  qrcodeRequester,
} from './QRCodeStep';
import { RedirectStep, runRedirect } from './RedirectStep';
import { StepDispatcher } from './StepDispatcher';

const { createElement } = React;

/** kind 兜底文案（StepDispatcher 经 common.refreshAndRetry 取用；测试断言保留字面量）。 */
const STEP_FALLBACK_TEXT = '请刷新重试';

/** kind=form 段的内容（FormStep 空字段 + 提交按钮，可辨识）。 */
function formNode(): React.ReactNode {
  return createElement(FormStep, {
    fields: [],
    loading: false,
    disabled: false,
    onSubmit: () => {},
  });
}

function renderDispatch(kind: string): string {
  return renderToStaticMarkup(
    createElement(StepDispatcher, {
      nextStep: create(NextStepSchema, { kind, method: 'totp' }),
      form: formNode(),
    }),
  );
}

beforeEach(() => {
  // rstest 对 .tsx 走 classic JSX runtime：渲染前 stub 全局 React（仅测试进程）。
  rs.stubGlobal('React', React);
});

describe('StepDispatcher kind 分派（§4.2 行 423；§1.4 行 169-176 六种）', () => {
  test('kind=form → 渲染注入的 form 段（容器构造：FormStep / 因子 verify 段）', () => {
    const markup = renderDispatch('form');
    expect(markup).toContain('<form');
    expect(markup).toContain('登录');
    expect(markup).not.toContain(STEP_FALLBACK_TEXT);
  });

  test('kind=challenge → ChallengeStep（触发下发按钮），不再兜底（§4.2 行 441）', () => {
    const markup = renderDispatch('challenge');
    expect(markup).toContain('发送验证码');
    expect(markup).not.toContain(STEP_FALLBACK_TEXT);
  });

  test('kind=redirect → RedirectStep（正在跳转…），不再兜底（§4.2 行 442）', () => {
    const markup = renderDispatch('redirect');
    expect(markup).toContain('正在跳转');
    expect(markup).not.toContain(STEP_FALLBACK_TEXT);
  });

  test('kind=qrcode → QRCodeStep 零值占位（NextStep 无 providerKey，§9 第 18 条），不再兜底（§4.2 行 443）', () => {
    const markup = renderDispatch('qrcode');
    // 占位是 role=alert（兜底为 role=status）——实体分派的结构证据。
    expect(markup).toContain('role="alert"');
    expect(markup).not.toContain('role="status"');
  });

  test('kind=poll：扩展位保留（§4.2 行 444 当前无实例）→ 兜底', () => {
    expect(renderDispatch('poll')).toContain(STEP_FALLBACK_TEXT);
  });

  test('kind=external：宿主承载（§9 第 10 条，login/ 不实现）→ 兜底', () => {
    expect(renderDispatch('external')).toContain(STEP_FALLBACK_TEXT);
  });

  test('未识别 kind → 兜底（§4.2 行 423「未识别 kind 走兜底」）', () => {
    expect(renderDispatch('teleport')).toContain(STEP_FALLBACK_TEXT);
    expect(renderDispatch('')).toContain(STEP_FALLBACK_TEXT);
  });
});

describe('FormStep（kind=form 通用渲染，§4.2 行 424；totp 渲染落点 §4.3 行 434）', () => {
  const totpFields = [
    create(FieldSchema, {
      name: 'code',
      label: '动态口令',
      type: 'totp',
      required: true,
      length: BigInt(6),
    }),
  ];

  function renderForm(props?: { loading?: boolean; disabled?: boolean }): string {
    return renderToStaticMarkup(
      createElement(FormStep, {
        fields: totpFields,
        loading: props?.loading ?? false,
        disabled: props?.disabled ?? false,
        onSubmit: () => {},
      }),
    );
  }

  test('fields[] → FieldRenderer：totp 字段分段输入（CodeInput，one-time-code 由 shared 承担）+ 提交按钮', () => {
    const markup = renderForm();
    expect(markup).toContain('<form');
    expect(markup).toContain('动态口令');
    // §1.11 行 331：totp 与 otp 同渲染逻辑（CodeInput 分段 + one-time-code）。
    // react-dom/server 静态输出保留 camelCase 属性名（autoComplete）。
    expect(markup).toContain('autoComplete="one-time-code"');
    expect(markup).toContain('登录');
  });

  test('loading / disabled 禁用提交（§3.2）', () => {
    expect(renderForm({ loading: true })).toContain('disabled=""');
    expect(renderForm({ disabled: true })).toContain('disabled=""');
    expect(renderForm()).not.toContain('disabled=""');
  });

  test('空 fields → 空表单（不产生字段控件，§1.11 零值兜底）', () => {
    const markup = renderToStaticMarkup(
      createElement(FormStep, {
        fields: [],
        loading: false,
        disabled: false,
        onSubmit: () => {},
      }),
    );
    expect(markup).toContain('<form');
    expect(markup).not.toContain('<label');
  });
});

// ---------------------------------------------------------------------------
// RedirectStep（kind=redirect 实体，§4.2 行 442）
// ---------------------------------------------------------------------------

describe('RedirectStep（§4.2 行 442）', () => {
  test('展示「正在跳转…」（effect 跳转在 node 静态渲染不执行，副作用经 runRedirect 覆盖）', () => {
    const markup = renderToStaticMarkup(
      createElement(RedirectStep, {
        authorizeUrl: 'https://auth.example/authorize',
      }),
    );
    expect(markup).toContain('正在跳转');
  });

  test('runRedirect：空 URL 不跳（零值兜底，§9 第 18 条）；非空跳一次', () => {
    const calls: string[] = [];
    runRedirect('', (url) => calls.push(url));
    expect(calls).toHaveLength(0);
    runRedirect('https://auth.example/authorize', (url) => calls.push(url));
    expect(calls).toEqual(['https://auth.example/authorize']);
  });
});

// ---------------------------------------------------------------------------
// ChallengeStep（kind=challenge 实体，§4.2 行 441）
// ---------------------------------------------------------------------------

describe('ChallengeStep（§4.2 行 441）', () => {
  const phoneField = create(FieldSchema, {
    name: 'phone',
    label: '手机号',
    type: 'phone',
    required: true,
  });

  test('challenge_fields → FieldRenderer + 触发下发按钮（phone → tel 控件，§1.11 行 326）', () => {
    const markup = renderToStaticMarkup(
      createElement(ChallengeStep, { fields: [phoneField] }),
    );
    expect(markup).toContain('<form');
    expect(markup).toContain('手机号');
    expect(markup).toContain('type="tel"');
    expect(markup).toContain('发送验证码');
  });

  test('captcha 配置存在 → 渲染 CaptchaWidget 容器（每次下发需新 captcha，§4.2 行 441）', () => {
    const withCaptcha = renderToStaticMarkup(
      createElement(ChallengeStep, {
        fields: [],
        captcha: create(CaptchaConfigSchema, {
          providerKey: 'builtin_image',
          type: 'image',
        }),
      }),
    );
    // CaptchaWidget 的 adapter effect 在 node 静态渲染不执行，仅容器 div。
    expect(withCaptcha).toContain('<div');
    const bare = renderToStaticMarkup(
      createElement(ChallengeStep, { fields: [] }),
    );
    expect(bare).not.toContain('<div');
  });

  test('loading / disabled 禁用触发（§3.2）', () => {
    expect(
      renderToStaticMarkup(
        createElement(ChallengeStep, { fields: [], loading: true }),
      ),
    ).toContain('disabled=""');
    expect(
      renderToStaticMarkup(
        createElement(ChallengeStep, { fields: [], disabled: true }),
      ),
    ).toContain('disabled=""');
  });
});

// ---------------------------------------------------------------------------
// QRCodeStep（kind=qrcode 实体，§4.2 行 443）
// ---------------------------------------------------------------------------

describe('QRCodeStep（§4.2 行 443；§2.8 行 688-708）', () => {
  test('无 captcha 配置 → QRCodePanel 直出（fetching 态；挂载即拉码归面板，§3.3 行 345）', () => {
    const markup = renderToStaticMarkup(
      createElement(QRCodeStep, { providerKey: 'scan' }),
    );
    expect(markup).toContain('正在获取二维码');
  });

  test('有 captcha 配置 → 门控：CaptchaWidget + 获取二维码按钮，面板不挂载（§2.8 行 690 必须携带 captcha）', () => {
    const markup = renderToStaticMarkup(
      createElement(QRCodeStep, {
        providerKey: 'scan',
        captcha: create(CaptchaConfigSchema, {
          providerKey: 'builtin_image',
          type: 'image',
        }),
      }),
    );
    expect(markup).toContain('获取二维码');
    expect(markup).not.toContain('正在获取二维码');
  });

  test('providerKey 空 → 零值兜底占位（§9 第 18 条；StepDispatcher 防御分派形态）', () => {
    const markup = renderToStaticMarkup(
      createElement(QRCodeStep, { providerKey: '' }),
    );
    expect(markup).toContain('role="alert"');
  });

  test('qrcodeRequester：凭据未就绪 → reject（§2.8 行 703 每次拉码都要新的 captcha）', async () => {
    await expect(
      qrcodeRequester('scan')(new AbortController().signal),
    ).rejects.toThrow('请先完成人机校验');
  });

  test('qrcodeRequester：就绪 → {providerKey, captcha} 调拉码（scene 缺省 login 省略，§2.8 行 702）', async () => {
    const payload: CaptchaPayload = create(CaptchaPayloadSchema, {
      providerKey: 'builtin_image',
      id: 'b7f3',
      answer: '123',
    });
    const requests: Array<{ providerKey: string; captcha: CaptchaPayload }> = [];
    const qr = await qrcodeRequester('scan', {
      getToken: () => payload,
      request: async (req) => {
        requests.push(req);
        return create(CreateQrcodeResponseSchema, {
          ticket: 't',
          qrcodeUrl: 'https://cdn.test/q.jpg',
        });
      },
    })(new AbortController().signal);
    expect(qr.qrcodeUrl).toBe('https://cdn.test/q.jpg');
    expect(requests).toHaveLength(1);
    expect(requests[0]?.providerKey).toBe('scan');
    expect(requests[0]?.captcha).toBe(payload);
  });

  test('completeLogin：syncCookieUrl 优先 / redirectTo 回退 / 皆空 → 默认落点（§1.3 行 158-162）', () => {
    const calls: string[] = [];
    const nav = (url: string) => calls.push(url);
    completeLogin(
      create(LoginFlowResponseSchema, {
        syncCookieUrl: 'https://sync.test/first',
        redirectTo: 'https://app.test/done',
      }),
      nav,
    );
    completeLogin(
      create(LoginFlowResponseSchema, { redirectTo: 'https://app.test/done' }),
      nav,
    );
    completeLogin(create(LoginFlowResponseSchema, {}), nav);
    expect(calls).toEqual([
      'https://sync.test/first',
      'https://app.test/done',
      '/account#/profile',
    ]);
  });

  // onResult 完整状态机（§2.8 行 739-743——登录结论在内层 login 信封）。
  test('dispatchQrResult：内层 success → completeLogin 收内层信封（终点字段在内层）+ 上抛外层（§2.8 行 739）', () => {
    const login = create(LoginFlowResponseSchema, {
      status: 'success',
      syncCookieUrl: 'https://sync.test/first',
      redirectTo: 'https://app.test/done',
    });
    const outer = create(LoginFlowResponseSchema, {
      status: 'success',
      login,
    });
    const completed: LoginFlowResponse[] = [];
    const raised: LoginFlowResponse[] = [];
    dispatchQrResult(outer, {
      completeLogin: (env) => completed.push(env),
      onResult: (env) => raised.push(env),
    });
    expect(completed).toHaveLength(1);
    expect(completed[0]?.syncCookieUrl).toBe('https://sync.test/first'); // 内层终点
    expect(raised).toEqual([outer]); // 上抛外层（观测）
  });

  test('dispatchQrResult：内层 binding_required / 失败态 → 不跳转，上抛外层交容器分派（§1.6 行 234/240）', () => {
    for (const innerStatus of ['binding_required', 'target_taken', 'failed']) {
      const outer = create(LoginFlowResponseSchema, {
        status: 'success',
        login: create(LoginFlowResponseSchema, {
          status: innerStatus,
          loginToken: 'lt-bind',
        }),
      });
      let completed = 0;
      const raised: LoginFlowResponse[] = [];
      dispatchQrResult(outer, {
        completeLogin: () => {
          completed += 1;
        },
        onResult: (env) => raised.push(env),
      });
      expect(completed).toBe(0); // 不跳转
      expect(raised).toEqual([outer]);
    }
  });

  test('dispatchQrResult：内层缺失（防御，外层 success 必附 login）→ 不跳转仍上抛；无 onResult 不炸', () => {
    const outer = create(LoginFlowResponseSchema, { status: 'success' });
    let completed = 0;
    const raised: LoginFlowResponse[] = [];
    dispatchQrResult(outer, {
      completeLogin: () => {
        completed += 1;
      },
      onResult: (env) => raised.push(env),
    });
    dispatchQrResult(outer, { completeLogin: () => {} }); // onResult 缺省
    expect(completed).toBe(0);
    expect(raised).toEqual([outer]);
  });
});

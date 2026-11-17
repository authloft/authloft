// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化后移除）。
// @ts-ignore
import { beforeEach, describe, expect, rs, test } from 'rstack/test';
import * as React from 'react';
// 本仓 rstest 为 node 环境（无 DOM）：静态渲染走 react-dom/server 的
// renderToStaticMarkup（沿 login-container.test.ts / components.test.ts 惯例）。
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from '@modern-js/runtime/router';
import { create } from '@bufbuild/protobuf';
import { CaptchaConfigSchema } from '../../gen/proto/api/common/v1/captcha_pb';
import { SubmitVerificationResponseSchema } from '../../gen/proto/api/common/v1/verification_pb';
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
import { CreateQrcodeResponseSchema } from '../../gen/proto/api/sso/v1/ticket_pb';
import { ApiError } from '../../shared/api/errors';
import { stepUpErrorText } from '../../shared/components/StepUpDialog';
import { ChallengeStep } from './ChallengeStep';
import { FormStep } from './FormStep';
import {
  QRCodeStep,
  completeLogin,
  completeStepUpSubmit,
  dispatchQrResult,
  qrcodeRequester,
  stepUpDismissState,
  stepUpPollAction,
  stepUpSubmitError,
  stepUpTicketOf,
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
  // kind=qrcode 分派的 QRCodeStep 消费 useSearchParams，统一 MemoryRouter 包裹。
  return renderToStaticMarkup(
    createElement(
      MemoryRouter,
      { initialEntries: ['/sso/login'] },
      createElement(StepDispatcher, {
        nextStep: create(NextStepSchema, { kind, method: 'totp' }),
        form: formNode(),
      }),
    ),
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
      label: 'login.field.totpCode',
      type: 'totp',
      required: true,
      length: BigInt(6),
    }),
  ];

  function renderForm(props?: {
    loading?: boolean;
    disabled?: boolean;
  }): string {
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

  test('加载视觉：loading → spinner + 「登录中…」替换按钮文案', () => {
    const markup = renderForm({ loading: true });
    expect(markup).toContain('aria-label="加载中…"');
    expect(markup).toContain('登录中…');
    expect(renderForm()).not.toContain('登录中…');
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
  test('展示「正在跳转…」+ Spinner（加载视觉；effect 跳转在 node 静态渲染不执行，副作用经 runRedirect 覆盖）', () => {
    const markup = renderToStaticMarkup(
      createElement(RedirectStep, {
        authorizeUrl: 'https://auth.example/authorize',
      }),
    );
    expect(markup).toContain('正在跳转');
    expect(markup).toContain('aria-label="加载中…"'); // Spinner md
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
    label: 'login.field.phone',
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

  test('captcha 配置存在也不内联渲染 widget（弹窗承接，点击触发才问）', () => {
    const withCaptcha = renderToStaticMarkup(
      createElement(ChallengeStep, {
        fields: [],
        captcha: create(CaptchaConfigSchema, {
          providerKey: 'builtin_image',
          type: 'image',
        }),
      }),
    );
    expect(withCaptcha).toContain('发送验证码');
    expect(withCaptcha).not.toContain('<div'); // 无内联 CaptchaWidget 容器
    expect(withCaptcha).not.toContain('安全验证'); // 弹窗未开（CaptchaDialog 无 session 返回 null）
    expect(withCaptcha).not.toContain('role="alert"'); // 初始无失败提示
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
  // QRCodeStep 消费 useSearchParams（returnTo 终点），直接渲染需 MemoryRouter。
  function renderQr(props: React.ComponentProps<typeof QRCodeStep>): string {
    return renderToStaticMarkup(
      createElement(
        MemoryRouter,
        { initialEntries: ['/sso/login'] },
        createElement(QRCodeStep, props),
      ),
    );
  }

  test('无 captcha 配置 → QRCodePanel 直出（fetching 态；挂载即拉码归面板，§3.3 行 345）', () => {
    const markup = renderQr({ providerKey: 'scan' });
    expect(markup).toContain('正在获取二维码');
  });

  test('有 captcha 配置也不内联渲染 widget：面板直出，弹窗关闭（点击拉码才问，§2.8 行 690）', () => {
    const markup = renderQr({
      providerKey: 'scan',
      captcha: create(CaptchaConfigSchema, {
        providerKey: 'builtin_image',
        type: 'image',
      }),
    });
    expect(markup).toContain('正在获取二维码');
    expect(markup).not.toContain('安全验证');
    expect(markup).not.toContain('获取二维码<button');
  });

  test('providerKey 空 → 零值兜底占位（§9 第 18 条；StepDispatcher 防御分派形态）', () => {
    const markup = renderQr({ providerKey: '' });
    expect(markup).toContain('role="alert"');
  });

  test('qrcodeRequester：gate 注入的凭据 → {providerKey, captcha} 调拉码（scene 缺省 login 省略，§2.8 行 702-703）', async () => {
    const payload: CaptchaPayload = create(CaptchaPayloadSchema, {
      providerKey: 'builtin_image',
      id: 'b7f3',
      answer: '123',
    });
    const requests: Array<{ providerKey: string; captcha: CaptchaPayload }> =
      [];
    const qr = await qrcodeRequester('scan', {
      request: async (req) => {
        requests.push(req);
        return create(CreateQrcodeResponseSchema, {
          ticket: 't',
          qrcodeUrl: 'https://cdn.test/q.jpg',
        });
      },
    })(payload);
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
      '/account#/',
    ]);
  });

  test('completeLogin returnTo 消费（非 OIDC 流）：皆空时合法值放行 / 站外值拒绝回落；合法值优先于 redirectTo（§1.3）', () => {
    const calls: string[] = [];
    const nav = (url: string) => calls.push(url);
    // 本文件测试环境无 oidc 注入（window 未 stub）→ 非 OIDC 分支。
    // 合法 returnTo（/account# 前缀白名单）→ 放行。
    completeLogin(
      create(LoginFlowResponseSchema, {}),
      nav,
      '/account#/security',
    );
    // 站外值 → 回落默认落点（防开放重定向）。
    completeLogin(
      create(LoginFlowResponseSchema, {}),
      nav,
      'https://evil.example.com/x',
    );
    // 非 OIDC 流：合法 returnTo 优先于 redirectTo——显式落点不做应用默认回跳。
    completeLogin(
      create(LoginFlowResponseSchema, { redirectTo: 'https://app.test/done' }),
      nav,
      '/account#/security',
    );
    expect(calls).toEqual([
      '/account#/security',
      '/account#/',
      '/account#/security',
    ]);
  });

  test('completeLogin：OIDC 流 redirectTo 优先于 returnTo（oidc 上下文在场，fail-closed，§1.3）', () => {
    const calls: string[] = [];
    const nav = (url: string) => calls.push(url);
    rs.stubGlobal('window', {
      __AUTHLOFT_INIT__: {
        al_root: 'https://uc.test/',
        oidc: { client_id: 'cid', redirect_uri: 'https://app/cb' },
      },
    });
    completeLogin(
      create(LoginFlowResponseSchema, { redirectTo: 'https://app.test/done' }),
      nav,
      '/account#/security',
    );
    expect(calls).toEqual(['https://app.test/done']);
    // 本文件无 afterEach：显式还原，防 window 桩泄漏进后续用例。
    rs.unstubAllGlobals();
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

  test('取消不自动重弹：已处理标记保留 + 改由显式重开入口承接；验证通过不提供入口', () => {
    const needsStepUp = create(LoginFlowResponseSchema, {
      status: 'needs_step_up',
      loginToken: 'lt-qr',
      ticket: { status: 'scanned', ticketId: 'tid-1' },
    });
    const opened = stepUpTicketOf(needsStepUp, undefined);
    expect(opened).toBe('tid-1');
    // 验证通过：标记保留、无重开入口，同一票据不重复弹。
    const verified = stepUpDismissState(opened, 'verified');
    expect(verified.handledTicketId).toBe('tid-1');
    expect(verified.reopenTicketId).toBeUndefined();
    expect(
      stepUpTicketOf(needsStepUp, verified.handledTicketId),
    ).toBeUndefined();
    // 用户取消：标记同样保留 → 下一轮轮询同一票据绝不自动重弹（可证伪：
    // 若清空标记，这里会再次返回 tid-1）。
    const cancelled = stepUpDismissState(opened, 'cancelled');
    expect(cancelled.handledTicketId).toBe('tid-1');
    expect(
      stepUpTicketOf(needsStepUp, cancelled.handledTicketId),
    ).toBeUndefined();
    // 取消只提供用户可见的显式重开入口（同一票据），由点击触发重开。
    expect(cancelled.reopenTicketId).toBe('tid-1');
    // 显式重开不改写标记：此后轮询仍不自动重弹。
    expect(
      stepUpTicketOf(needsStepUp, cancelled.handledTicketId),
    ).toBeUndefined();
  });

  test('stepUpPollAction：needs_step_up 每轮刷新 loginToken；已处理票据不自动弹；终态关闭重开入口', () => {
    const fresh = create(LoginFlowResponseSchema, {
      status: 'needs_step_up',
      loginToken: 'lt-new',
      ticket: { status: 'scanned', ticketId: 'tid-1' },
    });
    // 首次：弹窗 + 写入主体凭证。
    expect(stepUpPollAction(fresh, undefined)).toEqual({
      loginToken: 'lt-new',
      openTicketId: 'tid-1',
      terminal: false,
    });
    // 已处理（取消后）：不自动弹窗，但仍刷新为最新 loginToken —— 显式重开
    // 拿到的不是丢弃前的旧凭证。
    expect(stepUpPollAction(fresh, 'tid-1')).toEqual({
      loginToken: 'lt-new',
      openTicketId: undefined,
      terminal: false,
    });
    // 终态：重开入口失效（expired 兜底重拉新码）。
    expect(
      stepUpPollAction(
        create(LoginFlowResponseSchema, {
          status: 'expired',
          ticket: { status: 'expired', ticketId: 'tid-1' },
        }),
        'tid-1',
      ),
    ).toEqual({ loginToken: '', openTicketId: undefined, terminal: true });
    // 非 needs_step_up 不写凭证。
    expect(
      stepUpPollAction(
        create(LoginFlowResponseSchema, {
          status: 'scanned',
          ticket: { status: 'scanned', ticketId: 'tid-1' },
        }),
        undefined,
      ),
    ).toEqual({ loginToken: '', openTicketId: undefined, terminal: false });
  });

  test('Submit 成功响应即登录结论：直接交终点跳转（不等轮询 success）；失败不跳转', () => {
    const calls: string[] = [];
    const nav = (url: string) => calls.push(url);
    // 成功：响应里的 syncCookieUrl / redirectTo 直接按 completeLogin 优先级落点。
    const placeholder = completeStepUpSubmit(
      create(SubmitVerificationResponseSchema, {
        status: 'success',
        syncCookieUrl: 'https://sync.test/step-up',
        redirectTo: 'https://app.test/step-up',
      }),
      (terminal) => completeLogin(terminal, nav),
    );
    expect(placeholder).toBe('ok');
    expect(calls).toEqual(['https://sync.test/step-up']);
    // 仅 redirectTo：回退到 redirectTo（可证伪：不再依赖下一次轮询的 login 信封）。
    completeStepUpSubmit(
      create(SubmitVerificationResponseSchema, {
        status: 'success',
        redirectTo: 'https://app.test/step-up',
      }),
      (terminal) => completeLogin(terminal, nav),
    );
    expect(calls).toEqual([
      'https://sync.test/step-up',
      'https://app.test/step-up',
    ]);
    // 失败：抛窗内错误、不跳转（含剩余次数）。
    expect(() =>
      completeStepUpSubmit(
        create(SubmitVerificationResponseSchema, {
          status: 'invalid_code',
          attemptsLeft: BigInt(2),
        }),
        (terminal) => completeLogin(terminal, nav),
      ),
    ).toThrow();
    expect(calls).toHaveLength(2);
  });

  test('needs_step_up 带 loginToken 才弹窗；token 缺省不展示（可反向证伪）', () => {
    const withToken = create(LoginFlowResponseSchema, {
      status: 'needs_step_up',
      loginToken: 'lt-qr',
      ticket: { status: 'scanned', ticketId: 'tid-1' },
    });
    expect(stepUpTicketOf(withToken, undefined)).toBe('tid-1');
    // 反向：信封未下发 loginToken → 不弹窗（主体凭证缺省不展示）。
    const withoutToken = create(LoginFlowResponseSchema, {
      status: 'needs_step_up',
      ticket: { status: 'scanned', ticketId: 'tid-1' },
    });
    expect(stepUpTicketOf(withoutToken, undefined)).toBeUndefined();
    // 反向：非 needs_step_up 即使带 token 也不弹窗。
    expect(
      stepUpTicketOf(
        create(LoginFlowResponseSchema, {
          status: 'scanned',
          loginToken: 'lt-qr',
          ticket: { status: 'scanned', ticketId: 'tid-1' },
        }),
        undefined,
      ),
    ).toBeUndefined();
  });

  test('stepUpSubmitError 携带 attemptsLeft → 文案拼接剩余次数；缺省不展示（可反向证伪）', () => {
    const withAttempts = stepUpSubmitError('invalid_code', BigInt(3));
    expect(withAttempts).toBeInstanceOf(ApiError);
    expect(withAttempts.code).toBe('invalid_code');
    expect(stepUpErrorText(withAttempts)).toContain('还可尝试 3 次');
    // 反向：缺省 / 零值不展示剩余次数（§1.6「零值或缺失即不展示」）。
    expect(stepUpErrorText(stepUpSubmitError('invalid_code'))).toBe(
      '验证码错误',
    );
    expect(stepUpErrorText(stepUpSubmitError('invalid_code', BigInt(0)))).toBe(
      '验证码错误',
    );
  });

  test('因子失败不再吞成空串：非 success status 抛错误码交弹窗展示（§1.6）', () => {
    const failed = stepUpSubmitError('invalid_code');
    expect(failed).toBeInstanceOf(ApiError);
    expect(failed.code).toBe('invalid_code');
    // 零值 status 兜底 failed，不抛空错误码。
    expect(stepUpSubmitError('').code).toBe('failed');
  });
});

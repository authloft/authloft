// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化后移除）。
// @ts-ignore
import { describe, expect, test } from 'rstack/test';
import { create } from '@bufbuild/protobuf';
import {
  CaptchaConfigSchema,
  type CaptchaConfig,
} from '../../gen/proto/api/common/v1/captcha_pb';
import {
  LoginFlowResponseSchema,
  type LoginFlowResponse,
} from '../../gen/proto/api/sso/v1/envelope_pb';
import {
  CaptchaPayloadSchema,
  type CaptchaPayload,
} from '../../gen/proto/api/sso/v1/login_pb';
import { ApiError } from '../api/errors';
import {
  errorCaptchaOutcome,
  flowCaptchaOutcome,
  runCaptchaGate,
  type CaptchaPrompt,
} from './captchaGate';

function makeCaptcha(init: {
  providerKey?: string;
  type?: string;
  siteKey?: string;
}): CaptchaConfig {
  return create(CaptchaConfigSchema, init);
}

function envelope(status: string, captcha?: CaptchaConfig): LoginFlowResponse {
  return create(LoginFlowResponseSchema, { status, captcha });
}

const IMAGE = makeCaptcha({ providerKey: 'builtin_image', type: 'image' });
const TURNSTILE = makeCaptcha({
  providerKey: 'cf_turnstile',
  type: 'turnstile',
  siteKey: '0x4AAA',
});

function token(answer: string): CaptchaPayload {
  return create(CaptchaPayloadSchema, {
    providerKey: 'builtin_image',
    id: `id-${answer}`,
    answer,
  });
}

/** 记录弹窗询问序列的 prompt 替身；answers 逐项消费，耗尽后一律取消。 */
function scriptedPrompt(answers: (CaptchaPayload | undefined)[]) {
  const prompts: CaptchaPrompt[] = [];
  let index = 0;
  return {
    prompts,
    prompt: (p: CaptchaPrompt) => {
      prompts.push(p);
      const answer = index < answers.length ? answers[index] : undefined;
      index += 1;
      return Promise.resolve(answer);
    },
  };
}

describe('runCaptchaGate upfront（challenge 必经：先问再发，省一次被拦往返）', () => {
  test('有配置 → 先弹窗，确认后带凭据发一次请求即终局', async () => {
    const script = scriptedPrompt([token('a')]);
    const sent: (CaptchaPayload | undefined)[] = [];
    const result = await runCaptchaGate({
      mode: 'upfront',
      config: IMAGE,
      request: (captcha) => {
        sent.push(captcha);
        return Promise.resolve(envelope('next'));
      },
      readOutcome: flowCaptchaOutcome,
      prompt: script.prompt,
    });

    expect(result).toEqual({ kind: 'result', result: envelope('next') });
    expect(script.prompts).toHaveLength(1);
    expect(script.prompts[0]).toEqual({
      config: IMAGE,
      invalid: false,
      attempt: 0,
    });
    // 只发一次，且带凭据——没有注定被拦的裸请求。
    expect(sent).toEqual([token('a')]);
  });

  test('无配置 → 退化为先探一次（服务端未启用 captcha 时不凭空弹窗）', async () => {
    const script = scriptedPrompt([]);
    const sent: (CaptchaPayload | undefined)[] = [];
    const result = await runCaptchaGate({
      mode: 'upfront',
      request: (captcha) => {
        sent.push(captcha);
        return Promise.resolve(envelope('next'));
      },
      readOutcome: flowCaptchaOutcome,
      prompt: script.prompt,
    });

    expect(result.kind).toBe('result');
    expect(sent).toEqual([undefined]);
    expect(script.prompts).toHaveLength(0);
  });

  test('确认后收到非 captcha 失败态 → 原样逃逸给调用方状态机', async () => {
    const script = scriptedPrompt([token('a')]);
    const result = await runCaptchaGate({
      mode: 'upfront',
      config: IMAGE,
      request: () => Promise.resolve(envelope('invalid_credentials')),
      readOutcome: flowCaptchaOutcome,
      prompt: script.prompt,
    });

    expect(result).toEqual({
      kind: 'result',
      result: envelope('invalid_credentials'),
    });
    expect(script.prompts).toHaveLength(1);
  });
});

describe('runCaptchaGate reactive（密码 verify：阈值前端不可预知，先探再问）', () => {
  test('裸请求命中 captcha_required → 弹窗 → 带凭据重提 → 终局', async () => {
    const script = scriptedPrompt([token('a')]);
    const sent: (CaptchaPayload | undefined)[] = [];
    const result = await runCaptchaGate({
      mode: 'reactive',
      config: IMAGE,
      request: (captcha) => {
        sent.push(captcha);
        return Promise.resolve(
          captcha === undefined
            ? envelope('captcha_required', IMAGE)
            : envelope('success'),
        );
      },
      readOutcome: flowCaptchaOutcome,
      prompt: script.prompt,
    });

    expect(result).toEqual({ kind: 'result', result: envelope('success') });
    expect(sent).toEqual([undefined, token('a')]);
    expect(script.prompts).toHaveLength(1);
  });

  test('裸请求直接终局（未达阈值）→ 不弹窗', async () => {
    const script = scriptedPrompt([]);
    const result = await runCaptchaGate({
      mode: 'reactive',
      config: IMAGE,
      request: () => Promise.resolve(envelope('success')),
      readOutcome: flowCaptchaOutcome,
      prompt: script.prompt,
    });

    expect(result.kind).toBe('result');
    expect(script.prompts).toHaveLength(0);
  });
});

describe('captcha_invalid 弹窗内循环（§1.6 reset_captcha）', () => {
  test('invalid → 保持弹窗、attempt 递增、invalid 置位，换新凭据后成功', async () => {
    const script = scriptedPrompt([token('a'), token('b')]);
    const sent: (CaptchaPayload | undefined)[] = [];
    const result = await runCaptchaGate({
      mode: 'upfront',
      config: IMAGE,
      request: (captcha) => {
        sent.push(captcha);
        return Promise.resolve(
          captcha?.answer === 'b'
            ? envelope('next')
            : envelope('captcha_invalid', IMAGE),
        );
      },
      readOutcome: flowCaptchaOutcome,
      prompt: script.prompt,
    });

    expect(result.kind).toBe('result');
    expect(sent).toEqual([token('a'), token('b')]);
    expect(script.prompts).toHaveLength(2);
    expect(script.prompts[0].invalid).toBe(false);
    expect(script.prompts[0].attempt).toBe(0);
    expect(script.prompts[1].invalid).toBe(true);
    expect(script.prompts[1].attempt).toBe(1);
  });

  test('响应顶层 captcha 覆盖注入配置（服务端降级为 image）', async () => {
    const script = scriptedPrompt([token('a'), token('b')]);
    const seen: CaptchaConfig[] = [];
    const result = await runCaptchaGate({
      mode: 'upfront',
      config: TURNSTILE,
      request: () => {
        seen.push(script.prompts[script.prompts.length - 1].config);
        return Promise.resolve(
          seen.length === 1
            ? envelope('captcha_invalid', IMAGE)
            : envelope('next'),
        );
      },
      readOutcome: flowCaptchaOutcome,
      prompt: script.prompt,
    });

    expect(result.kind).toBe('result');
    expect(script.prompts[0].config).toEqual(TURNSTILE);
    expect(script.prompts[1].config).toEqual(IMAGE);
  });

  test('响应未附 captcha → 沿用上一轮配置（ErrorInfo 形态无该字段）', async () => {
    const script = scriptedPrompt([token('a'), token('b')]);
    let calls = 0;
    await runCaptchaGate({
      mode: 'upfront',
      config: IMAGE,
      request: () => {
        calls += 1;
        return Promise.resolve(
          calls === 1 ? envelope('captcha_invalid') : envelope('next'),
        );
      },
      readOutcome: flowCaptchaOutcome,
      prompt: script.prompt,
    });

    expect(script.prompts[1].config).toEqual(IMAGE);
  });
});

describe('取消（不清流程态，不再发请求）', () => {
  test('upfront 取消 → 一次请求都不发', async () => {
    const script = scriptedPrompt([undefined]);
    let calls = 0;
    const result = await runCaptchaGate({
      mode: 'upfront',
      config: IMAGE,
      request: () => {
        calls += 1;
        return Promise.resolve(envelope('next'));
      },
      readOutcome: flowCaptchaOutcome,
      prompt: script.prompt,
    });

    expect(result).toEqual({ kind: 'cancelled' });
    expect(calls).toBe(0);
  });

  test('reactive 命中后取消 → 停在已发的那一次，不重提', async () => {
    const script = scriptedPrompt([undefined]);
    let calls = 0;
    const result = await runCaptchaGate({
      mode: 'reactive',
      config: IMAGE,
      request: () => {
        calls += 1;
        return Promise.resolve(envelope('captcha_required', IMAGE));
      },
      readOutcome: flowCaptchaOutcome,
      prompt: script.prompt,
    });

    expect(result).toEqual({ kind: 'cancelled' });
    expect(calls).toBe(1);
  });

  test('invalid 循环中取消 → 立即终止', async () => {
    const script = scriptedPrompt([token('a'), undefined]);
    let calls = 0;
    const result = await runCaptchaGate({
      mode: 'upfront',
      config: IMAGE,
      request: () => {
        calls += 1;
        return Promise.resolve(envelope('captcha_invalid', IMAGE));
      },
      readOutcome: flowCaptchaOutcome,
      prompt: script.prompt,
    });

    expect(result).toEqual({ kind: 'cancelled' });
    expect(calls).toBe(1);
    expect(script.prompts).toHaveLength(2);
  });
});

describe('抛出形态（扫码 / 绑定域：非 200 ErrorInfo.code）', () => {
  test('ApiError code=captcha_required → 弹窗后带凭据重提', async () => {
    const script = scriptedPrompt([token('a')]);
    const sent: (CaptchaPayload | undefined)[] = [];
    const result = await runCaptchaGate<string>({
      mode: 'reactive',
      config: IMAGE,
      request: (captcha) => {
        sent.push(captcha);
        if (captcha === undefined) {
          return Promise.reject(
            new ApiError({
              httpStatus: 400,
              code: 'captcha_required',
              message: '',
              requestId: '',
            }),
          );
        }
        return Promise.resolve('ticket-1');
      },
      readOutcome: () => ({ action: 'message' }),
      readError: errorCaptchaOutcome,
      prompt: script.prompt,
    });

    expect(result).toEqual({ kind: 'result', result: 'ticket-1' });
    expect(sent).toEqual([undefined, token('a')]);
    // ErrorInfo 不携带配置 → 沿用注入的快照配置。
    expect(script.prompts[0].config).toEqual(IMAGE);
  });

  test('upfront 确认后仍被判 captcha_required → 再问一次而非逃逸', async () => {
    const script = scriptedPrompt([token('a'), token('b')]);
    let calls = 0;
    const result = await runCaptchaGate<string>({
      mode: 'upfront',
      config: IMAGE,
      request: () => {
        calls += 1;
        if (calls === 1) {
          return Promise.reject(
            new ApiError({
              httpStatus: 400,
              code: 'captcha_required',
              message: '',
              requestId: '',
            }),
          );
        }
        return Promise.resolve('ticket-1');
      },
      readOutcome: () => ({ action: 'message' }),
      readError: errorCaptchaOutcome,
      prompt: script.prompt,
    });

    expect(result).toEqual({ kind: 'result', result: 'ticket-1' });
    expect(script.prompts).toHaveLength(2);
    expect(script.prompts[1].attempt).toBe(1);
    // required 不是 invalid：不出「校验未通过」文案。
    expect(script.prompts[1].invalid).toBe(false);
  });

  test('captcha_invalid 抛出 → 弹窗内循环', async () => {
    const script = scriptedPrompt([token('a'), token('b')]);
    let calls = 0;
    const result = await runCaptchaGate<string>({
      mode: 'upfront',
      config: IMAGE,
      request: () => {
        calls += 1;
        if (calls < 2) {
          return Promise.reject(
            new ApiError({
              httpStatus: 400,
              code: 'captcha_invalid',
              message: '',
              requestId: '',
            }),
          );
        }
        return Promise.resolve('ticket-1');
      },
      readOutcome: () => ({ action: 'message' }),
      readError: errorCaptchaOutcome,
      prompt: script.prompt,
    });

    expect(result).toEqual({ kind: 'result', result: 'ticket-1' });
    expect(script.prompts[1].invalid).toBe(true);
  });

  test('非 captcha 的 ApiError → 原样交回，不弹窗', async () => {
    const script = scriptedPrompt([]);
    const error = new ApiError({
      httpStatus: 429,
      code: 'too_many_requests',
      message: '',
      requestId: '',
    });
    const result = await runCaptchaGate<string>({
      mode: 'reactive',
      config: IMAGE,
      request: () => Promise.reject(error),
      readOutcome: () => ({ action: 'message' }),
      readError: errorCaptchaOutcome,
      prompt: script.prompt,
    });

    expect(result).toEqual({ kind: 'error', error });
    expect(script.prompts).toHaveLength(0);
  });

  test('传输层异常（非 ApiError）→ 原样交回', async () => {
    const error = new Error('network down');
    const result = await runCaptchaGate<string>({
      mode: 'reactive',
      config: IMAGE,
      request: () => Promise.reject(error),
      readOutcome: () => ({ action: 'message' }),
      readError: errorCaptchaOutcome,
      prompt: scriptedPrompt([]).prompt,
    });

    expect(result).toEqual({ kind: 'error', error });
  });

  test('未注入 readError → 抛出即终局', async () => {
    const error = new Error('boom');
    const result = await runCaptchaGate<string>({
      mode: 'reactive',
      config: IMAGE,
      request: () => Promise.reject(error),
      readOutcome: () => ({ action: 'message' }),
      prompt: scriptedPrompt([]).prompt,
    });

    expect(result).toEqual({ kind: 'error', error });
  });
});

describe('配置缺失防御（§2.5 服务端必附）', () => {
  test('判需要 captcha 却始终无配置 → 交回错误，不无限弹窗', async () => {
    const script = scriptedPrompt([token('a')]);
    const result = await runCaptchaGate({
      mode: 'reactive',
      request: () => Promise.resolve(envelope('captcha_required')),
      readOutcome: flowCaptchaOutcome,
      prompt: script.prompt,
    });

    expect(result.kind).toBe('error');
    expect(script.prompts).toHaveLength(0);
  });
});

describe('判读helper（§1.6 一套词汇两个位置）', () => {
  test('flowCaptchaOutcome 取信封顶层 status 动作与 captcha', () => {
    expect(flowCaptchaOutcome(envelope('captcha_required', IMAGE))).toEqual({
      action: 'require_captcha',
      captcha: IMAGE,
    });
    expect(flowCaptchaOutcome(envelope('captcha_invalid')).action).toBe(
      'reset_captcha',
    );
    expect(flowCaptchaOutcome(envelope('success')).action).toBe('complete');
  });

  test('errorCaptchaOutcome 只认 ApiError，取位置二动作', () => {
    expect(
      errorCaptchaOutcome(
        new ApiError({
          httpStatus: 400,
          code: 'captcha_required',
          message: '',
          requestId: '',
        }),
      ),
    ).toEqual({ action: 'require_captcha' });
    expect(errorCaptchaOutcome(new Error('x'))).toBeUndefined();
    expect(errorCaptchaOutcome(undefined)).toBeUndefined();
  });
});

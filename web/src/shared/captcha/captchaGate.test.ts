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

function envelope(status: string): LoginFlowResponse {
  return create(LoginFlowResponseSchema, { status });
}

/** captcha 失败统一为 ErrorInfo.code，配置来自同一错误体 details（§1.5 行 228 / §2.5）。 */
function apiError(code: string, captcha?: CaptchaConfig): ApiError {
  return new ApiError({
    httpStatus: 400,
    code,
    message: '',
    requestId: '',
    captcha,
  });
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
  test('裸请求命中 captcha_required → 弹窗（配置取错误体 details）→ 带凭据重提 → 终局', async () => {
    const script = scriptedPrompt([token('a')]);
    const sent: (CaptchaPayload | undefined)[] = [];
    const result = await runCaptchaGate({
      mode: 'reactive',
      config: TURNSTILE,
      request: (captcha) => {
        sent.push(captcha);
        return captcha === undefined
          ? Promise.reject(apiError('captcha_required', IMAGE))
          : Promise.resolve(envelope('success'));
      },
      readOutcome: flowCaptchaOutcome,
      prompt: script.prompt,
    });

    expect(result).toEqual({ kind: 'result', result: envelope('success') });
    expect(sent).toEqual([undefined, token('a')]);
    expect(script.prompts).toHaveLength(1);
    // 服务端降级为 image：以错误体配置覆盖注入的首屏配置。
    expect(script.prompts[0].config).toEqual(IMAGE);
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
      config: TURNSTILE,
      request: (captcha) => {
        sent.push(captcha);
        return captcha?.answer === 'b'
          ? Promise.resolve(envelope('next'))
          : Promise.reject(apiError('captcha_invalid', IMAGE));
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
    // 错误体 details 的配置覆盖注入配置（服务端降级为 image）。
    expect(script.prompts[0].config).toEqual(TURNSTILE);
    expect(script.prompts[1].config).toEqual(IMAGE);
  });

  test('错误体未附 captcha → 沿用上一轮配置', async () => {
    const script = scriptedPrompt([token('a'), token('b')]);
    let calls = 0;
    await runCaptchaGate({
      mode: 'upfront',
      config: IMAGE,
      request: () => {
        calls += 1;
        return calls === 1
          ? Promise.reject(apiError('captcha_invalid'))
          : Promise.resolve(envelope('next'));
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
        return Promise.reject(apiError('captcha_required', IMAGE));
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
        return Promise.reject(apiError('captcha_invalid', IMAGE));
      },
      readOutcome: flowCaptchaOutcome,
      prompt: script.prompt,
    });

    expect(result).toEqual({ kind: 'cancelled' });
    expect(calls).toBe(1);
    expect(script.prompts).toHaveLength(2);
  });
});

describe('抛出形态（ErrorInfo.code，默认判读吸收）', () => {
  test('未注入 readError：captcha_required 仍被默认判读吸收，配置取错误体 details', async () => {
    const script = scriptedPrompt([token('a')]);
    const sent: (CaptchaPayload | undefined)[] = [];
    const result = await runCaptchaGate<string>({
      mode: 'reactive',
      config: TURNSTILE,
      request: (captcha) => {
        sent.push(captcha);
        return captcha === undefined
          ? Promise.reject(apiError('captcha_required', IMAGE))
          : Promise.resolve('ticket-1');
      },
      readOutcome: () => ({ action: 'message' }),
      prompt: script.prompt,
    });

    expect(result).toEqual({ kind: 'result', result: 'ticket-1' });
    expect(sent).toEqual([undefined, token('a')]);
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
        return calls === 1
          ? Promise.reject(apiError('captcha_required', IMAGE))
          : Promise.resolve('ticket-1');
      },
      readOutcome: () => ({ action: 'message' }),
      prompt: script.prompt,
    });

    expect(result).toEqual({ kind: 'result', result: 'ticket-1' });
    expect(script.prompts).toHaveLength(2);
    expect(script.prompts[1].attempt).toBe(1);
    // required 不是 invalid：不出「校验未通过」文案。
    expect(script.prompts[1].invalid).toBe(false);
  });

  test('非 captcha 的 ApiError → 原样交回，不弹窗', async () => {
    const script = scriptedPrompt([]);
    const error = apiError('too_many_requests');
    const result = await runCaptchaGate<string>({
      mode: 'reactive',
      config: IMAGE,
      request: () => Promise.reject(error),
      readOutcome: () => ({ action: 'message' }),
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
      request: () => Promise.reject(apiError('captcha_required')),
      readOutcome: flowCaptchaOutcome,
      prompt: script.prompt,
    });

    expect(result.kind).toBe('error');
    expect(script.prompts).toHaveLength(0);
  });
});

describe('判读 helper（§1.6 一套词汇两个位置）', () => {
  test('flowCaptchaOutcome 只取信封 status 动作，不读信封上的 captcha 字段', () => {
    expect(flowCaptchaOutcome(envelope('success')).action).toBe('complete');
    // captcha_* 已不是流程态：作 status 到达时按未知兜底，不走开窗动作。
    expect(flowCaptchaOutcome(envelope('captcha_required')).action).toBe(
      'message',
    );
  });

  test('errorCaptchaOutcome 只认 ApiError，取位置二动作与错误体配置', () => {
    expect(
      errorCaptchaOutcome(apiError('captcha_required', TURNSTILE)),
    ).toEqual({ action: 'require_captcha', captcha: TURNSTILE });
    expect(errorCaptchaOutcome(apiError('captcha_invalid')).action).toBe(
      'reset_captcha',
    );
    expect(errorCaptchaOutcome(new Error('x'))).toBeUndefined();
    expect(errorCaptchaOutcome(undefined)).toBeUndefined();
  });
});

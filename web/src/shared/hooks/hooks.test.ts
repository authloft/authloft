// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径；
// 本次不改 tsconfig，故仅在测试文件放宽该 import 的类型解析（既定口径）。
// @ts-ignore
import { afterAll, afterEach, describe, expect, rs, test } from 'rstack/test';
import {
  createRaceGuard,
  INITIAL_REQUEST_STATE,
  requestReducer,
  type RequestState,
} from './useRequest';
import {
  COUNTDOWN_TICK_MS,
  countdownSeconds,
  secondsUntil,
} from './useCountdown';
import { resolveCapability } from './useCapability';
import { COPY_FEEDBACK_MS, createCopyController } from './useCopy';

/**
 * 本仓 rstest 默认 node 环境（无 DOM、未装 happy-dom，且禁改 rstack.config），
 * hook 壳不做渲染测试；各 hook 的核心逻辑抽为纯函数 / 纯闭包在此覆盖
 * （沿 setup/RestartingPage 的依赖注入测试模式）。
 */
afterAll(() => {
  rs.unstubAllGlobals();
});

describe('hooks/useRequest 状态机（§3.2：idle/loading/success/error）', () => {
  type S = RequestState<string>;
  const initial: S = INITIAL_REQUEST_STATE as S;

  test('初始态 idle；start → loading（清空 data / error）', () => {
    expect(initial).toEqual({ status: 'idle', data: undefined, error: undefined });
    const loading = requestReducer(initial, { type: 'start' });
    expect(loading).toEqual({ status: 'loading', data: undefined, error: undefined });
    // 上一轮结果被新一轮 start 覆盖。
    const again = requestReducer(
      { status: 'success', data: 'x', error: undefined },
      { type: 'start' },
    );
    expect(again.status).toBe('loading');
    expect(again.data).toBeUndefined();
  });

  test('success → 存 data 清 error；failure → 存 error 清 data（互斥）', () => {
    const loading = requestReducer(initial, { type: 'start' });
    expect(requestReducer(loading, { type: 'success', data: 'x' })).toEqual({
      status: 'success',
      data: 'x',
      error: undefined,
    });
    expect(requestReducer(loading, { type: 'failure', error: new Error('e') })).toEqual({
      status: 'error',
      data: undefined,
      error: new Error('e'),
    });
  });

  test('reset → 回 idle 并清空（手动 reset 口径）', () => {
    expect(
      requestReducer({ status: 'error', data: undefined, error: 'boom' }, {
        type: 'reset',
      }),
    ).toEqual(initial);
  });
});

describe('hooks/useRequest 竞态令牌（§3.2：旧响应到达时丢弃）', () => {
  test('begin 递增；isCurrent 仅对最新一次为真', () => {
    const guard = createRaceGuard();
    const first = guard.begin();
    const second = guard.begin();
    expect(first).toBe(1);
    expect(second).toBe(2);
    expect(guard.isCurrent(first)).toBe(false);
    expect(guard.isCurrent(second)).toBe(true);
  });

  test('reset 语义复用 begin：使在途请求失效', () => {
    const guard = createRaceGuard();
    const inFlight = guard.begin();
    expect(guard.isCurrent(inFlight)).toBe(true);
    const afterReset = guard.begin();
    expect(guard.isCurrent(inFlight)).toBe(false);
    expect(guard.isCurrent(afterReset)).toBe(true);
  });
});

describe('hooks/useCountdown 秒级换算（§3.2：retryAfter/expiresIn 的 bigint 归一）', () => {
  test('countdownSeconds：undefined / 0 / 负值 / 超界异常时长 → 0', () => {
    expect(countdownSeconds(undefined)).toBe(0);
    expect(countdownSeconds(BigInt(0))).toBe(0);
    expect(countdownSeconds(BigInt(-3))).toBe(0);
    expect(
      countdownSeconds(BigInt(Number.MAX_SAFE_INTEGER) + BigInt(1)),
    ).toBe(0);
  });

  test('countdownSeconds：正常时长经 toCount 归一为 number', () => {
    expect(countdownSeconds(BigInt(60))).toBe(60);
    expect(countdownSeconds(BigInt(300))).toBe(300);
  });

  test('secondsUntil：不足 1 秒按 1 计（ceil）；到期 / 过期 → 0', () => {
    const now = 1_000_000;
    expect(secondsUntil(now + 1500, now)).toBe(2);
    expect(secondsUntil(now + 1000, now)).toBe(1);
    expect(secondsUntil(now + 1, now)).toBe(1);
    expect(secondsUntil(now, now)).toBe(0);
    expect(secondsUntil(now - 500, now)).toBe(0);
  });

  test('常量口径：tick 250ms（秒跳变及时且平滑对齐 deadline）', () => {
    expect(COUNTDOWN_TICK_MS).toBe(250);
  });
});

describe('hooks/useCapability 能力表达式（§3.2：属性链逐段取值，禁 eval）', () => {
  test('undefined / 空串（零值）= 无能力要求 → true', () => {
    expect(resolveCapability(undefined)).toBe(true);
    expect(resolveCapability('')).toBe(true);
  });

  test('整链解析成功且末段真值 → true（从 window 起逐段取值）', () => {
    rs.stubGlobal('window', {
      PublicKeyCredential: function PublicKeyCredential() {},
      enabledFlag: 'on',
      zero: 0,
    });
    expect(resolveCapability('window.PublicKeyCredential')).toBe(true);
    expect(resolveCapability('window.enabledFlag')).toBe(true);
  });

  test('末段非真值 / 任一段缺失 → false', () => {
    rs.stubGlobal('window', { zero: 0 });
    expect(resolveCapability('window.zero')).toBe(false); // 末段 falsy
    expect(resolveCapability('window.Missing')).toBe(false); // 缺失
    expect(resolveCapability('window.Missing.deeper')).toBe(false);
  });

  test('中间段非对象 / 函数（无法继续取属性）→ false', () => {
    rs.stubGlobal('window', { text: 'abc' });
    expect(resolveCapability('window.text')).toBe(true); // 末段真值字符串可用
    expect(resolveCapability('window.text.length')).toBe(false); // 中间段 primitive
  });

  test('不带 window 前缀：从 globalThis 起取值', () => {
    rs.stubGlobal('PublicKeyCredential', {});
    expect(resolveCapability('PublicKeyCredential')).toBe(true);
    expect(resolveCapability('PublicKeyCredential.isUVPAA')).toBe(false); // 缺失
  });

  test('表达式非法一律 false、不抛错（空段 / 非标识符段）', () => {
    expect(resolveCapability('.')).toBe(false);
    expect(resolveCapability('window.')).toBe(false);
    expect(resolveCapability('.window')).toBe(false);
    expect(resolveCapability('window..x')).toBe(false);
    expect(resolveCapability('window.a-b')).toBe(false);
    expect(resolveCapability('window.1abc')).toBe(false);
    expect(resolveCapability('return process.exit')).toBe(false);
  });
});

describe('hooks/useCopy 复制控制器（§3.2：剪贴板复制 + 短暂成功态）', () => {
  afterEach(() => {
    rs.useRealTimers();
  });

  test('常量口径：成功态 2000ms', () => {
    expect(COPY_FEEDBACK_MS).toBe(2000);
  });

  test('复制成功 → copied=true，duration 后回落 false', async () => {
    rs.useFakeTimers();
    const states: boolean[] = [];
    const controller = createCopyController((copied) => states.push(copied), {
      writeText: async () => {},
    });

    expect(controller.isCopied()).toBe(false);
    expect(await controller.copy('provider-key-1')).toBe(true);
    expect(states).toEqual([true]);
    expect(controller.isCopied()).toBe(true);

    rs.advanceTimersByTime(COPY_FEEDBACK_MS);
    expect(states).toEqual([true, false]);
    expect(controller.isCopied()).toBe(false);
  });

  test('writeText 收到原文；返回 true', async () => {
    rs.useFakeTimers();
    const written: string[] = [];
    const controller = createCopyController(() => {}, {
      writeText: async (text) => {
        written.push(text);
      },
    });
    expect(await controller.copy('https://callback.example/cb')).toBe(true);
    expect(written).toEqual(['https://callback.example/cb']);
  });

  test('剪贴板不可用 / 写入失败 → false，不抛错、不触发成功态', async () => {
    rs.useFakeTimers();
    const states: boolean[] = [];
    const controller = createCopyController((copied) => states.push(copied), {
      writeText: async () => {
        throw new Error('clipboard denied');
      },
    });
    expect(await controller.copy('x')).toBe(false);
    expect(states).toEqual([]);
    expect(controller.isCopied()).toBe(false);
  });

  test('成功窗口内再次复制成功 → 重新计时（短暂成功态不叠加）', async () => {
    rs.useFakeTimers();
    const states: boolean[] = [];
    const controller = createCopyController((copied) => states.push(copied), {
      writeText: async () => {},
    });

    await controller.copy('a');
    rs.advanceTimersByTime(1_500); // 窗口内过半
    await controller.copy('b'); // 重新计时
    rs.advanceTimersByTime(1_500); // 距上次成功 1500ms < 2000ms
    expect(states).toEqual([true, true]);
    expect(controller.isCopied()).toBe(true);
    rs.advanceTimersByTime(500); // 累计 2000ms 到点
    expect(states).toEqual([true, true, false]);
  });

  test('dispose：清掉计时器，成功态不再回落', async () => {
    rs.useFakeTimers();
    const states: boolean[] = [];
    const controller = createCopyController((copied) => states.push(copied), {
      writeText: async () => {},
    });

    await controller.copy('x');
    controller.dispose();
    rs.advanceTimersByTime(COPY_FEEDBACK_MS * 2);
    expect(states).toEqual([true]); // 回落回调不再触发
  });
});

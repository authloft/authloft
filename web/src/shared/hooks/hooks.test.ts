// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径；
// 本次不改 tsconfig，故仅在测试文件放宽该 import 的类型解析（既定口径）。
// @ts-ignore
import { afterAll, afterEach, describe, expect, rs, test } from 'rstack/test';
import {
  COUNTDOWN_TICK_MS,
  countdownSeconds,
  secondsUntil,
} from './useCountdown';
import { resolveCapability } from './useCapability';
import { COPY_FEEDBACK_MS, createCopyController } from './useCopy';
import {
  createLongPollController,
  DEFAULT_MAX_POLL_ERRORS,
  DEFAULT_POLL_BACKOFF_BASE_MS,
  DEFAULT_POLL_BACKOFF_MAX_MS,
} from './useLongPoll';

/**
 * 本仓 rstest 默认 node 环境（无 DOM、未装 happy-dom，且禁改 rstack.config），
 * hook 壳不做渲染测试；各 hook 的核心逻辑抽为纯函数 / 纯闭包在此覆盖
 * （沿 setup/RestartingPage 的依赖注入测试模式）。
 */
afterAll(() => {
  rs.unstubAllGlobals();
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

describe('hooks/useLongPoll 轮询控制器（§3.2 行 318 / §8.2 行 591）', () => {
  interface PollResult {
    readonly state: string;
  }

  afterEach(() => {
    rs.useRealTimers();
  });

  test('常量口径：错误上限 5、退避基数 500ms、封顶 8000ms', () => {
    expect(DEFAULT_MAX_POLL_ERRORS).toBe(5);
    expect(DEFAULT_POLL_BACKOFF_BASE_MS).toBe(500);
    expect(DEFAULT_POLL_BACKOFF_MAX_MS).toBe(8000);
  });

  test('未就绪结果 → onPoll 通知 + 立即重连（无退避介入）', async () => {
    rs.useFakeTimers();
    let calls = 0;
    const polled: string[] = [];
    const controller = createLongPollController<PollResult>(() => ({
      poll: () => {
        calls += 1;
        if (calls <= 2) {
          return Promise.resolve({ state: 'pending' });
        }
        if (calls === 3) {
          return Promise.resolve({ state: 'scanned' });
        }
        return new Promise(() => {}); // 第 4 次起在途挂起
      },
      isSettled: (r) => r.state === 'success',
      onPoll: (r) => polled.push(r.state),
      onSettled: () => {},
      pollTimeoutMs: 1000,
    }));
    controller.start();
    await rs.advanceTimersByTimeAsync(0);
    // 3 次结果全部 0ms 内消化（pending / scanned 都立即重连）+ 第 4 次在途。
    expect(calls).toBe(4);
    expect(polled).toEqual(['pending', 'pending', 'scanned']);
    expect(controller.isRunning()).toBe(true);
    controller.stop();
  });

  test('终态 → onSettled 通知后停止（不再发起）', async () => {
    rs.useFakeTimers();
    let calls = 0;
    let settled: PollResult | undefined;
    const controller = createLongPollController<PollResult>(() => ({
      poll: () => {
        calls += 1;
        return Promise.resolve(
          calls < 2 ? { state: 'pending' } : { state: 'success' },
        );
      },
      isSettled: (r) => r.state === 'success',
      onPoll: () => {},
      onSettled: (r) => {
        settled = r;
      },
      pollTimeoutMs: 1000,
    }));
    controller.start();
    await rs.advanceTimersByTimeAsync(0);
    expect(calls).toBe(2);
    expect(settled).toEqual({ state: 'success' });
    expect(controller.isRunning()).toBe(false);
    await rs.advanceTimersByTimeAsync(5000);
    expect(calls).toBe(2); // 停止后不再发起
  });

  test('单次最长等待到点 → abort 在途并立即重连（超时不是错误，不触发错误上限）', async () => {
    rs.useFakeTimers();
    let calls = 0;
    let maxErrorCalls = 0;
    const controller = createLongPollController<PollResult>(() => ({
      poll: (signal) => {
        calls += 1;
        if (calls <= 2 || calls >= 4) {
          // 前两次挂起模拟服务端不回（等超时 abort）；第 3 次返回 pending
          // 后第 4 次在途挂起，终止微任务链。
          return new Promise((_resolve, reject) => {
            signal.addEventListener('abort', () =>
              reject(new Error('timeout-abort')),
            );
          });
        }
        return Promise.resolve({ state: 'pending' });
      },
      isSettled: (r) => r.state === 'success',
      onPoll: () => {},
      onSettled: () => {},
      onMaxErrors: () => {
        maxErrorCalls += 1;
      },
      pollTimeoutMs: 1000,
      maxErrors: 1, // 若超时计入错误，第一次超时即停止
    }));
    controller.start();
    await rs.advanceTimersByTimeAsync(0);
    expect(calls).toBe(1);
    await rs.advanceTimersByTimeAsync(1000); // 第 1 次超时
    expect(calls).toBe(2); // 立即重连
    expect(maxErrorCalls).toBe(0);
    await rs.advanceTimersByTimeAsync(1000); // 第 2 次超时
    // 第 3 次（pending）后立即第 4 次在途：2 次超时均未计入错误。
    expect(calls).toBe(4);
    expect(maxErrorCalls).toBe(0);
    controller.stop();
  });

  test('poll 抛错 → 指数退避（base、2x、封顶）；连续错误达上限 → onMaxErrors 停止', async () => {
    rs.useFakeTimers();
    let calls = 0;
    let maxError: unknown;
    const controller = createLongPollController<PollResult>(() => ({
      poll: () => {
        calls += 1;
        return Promise.reject(new Error(`net-${calls}`));
      },
      isSettled: () => false,
      onPoll: () => {},
      onSettled: () => {},
      onMaxErrors: (e) => {
        maxError = e;
      },
      pollTimeoutMs: 1000,
      maxErrors: 4,
      baseDelayMs: 100,
      maxDelayMs: 250,
    }));
    controller.start();
    await rs.advanceTimersByTimeAsync(0);
    expect(calls).toBe(1); // 第 1 次失败 → 退避 100ms
    await rs.advanceTimersByTimeAsync(100);
    expect(calls).toBe(2); // 退避 100 到点 → 第 2 次 → 退避 200
    await rs.advanceTimersByTimeAsync(100);
    expect(calls).toBe(2); // 200 只过了一半，未重连
    await rs.advanceTimersByTimeAsync(100);
    expect(calls).toBe(3); // 200 到点 → 第 3 次 → 退避 min(400, 250)
    await rs.advanceTimersByTimeAsync(250);
    expect(calls).toBe(4); // 250 到点 → 第 4 次 = 上限
    expect(maxError).toBeInstanceOf(Error);
    expect((maxError as Error).message).toBe('net-4');
    expect(controller.isRunning()).toBe(false);
    await rs.advanceTimersByTimeAsync(10000);
    expect(calls).toBe(4); // 停止后不再发起
  });

  test('错误后成功 → 连续错误计数回血（非累计）', async () => {
    rs.useFakeTimers();
    let calls = 0;
    let maxErrorCalls = 0;
    const controller = createLongPollController<PollResult>(() => ({
      poll: () => {
        calls += 1;
        return calls % 2 === 1
          ? Promise.reject(new Error('net'))
          : Promise.resolve({ state: 'pending' });
      },
      isSettled: () => false,
      onPoll: () => {},
      onSettled: () => {},
      onMaxErrors: () => {
        maxErrorCalls += 1;
      },
      pollTimeoutMs: 1000,
      maxErrors: 2,
      baseDelayMs: 100,
    }));
    controller.start();
    await rs.advanceTimersByTimeAsync(0); // 失败 1 → 退避
    await rs.advanceTimersByTimeAsync(100); // 成功（回血）→ 失败 1 → 退避
    await rs.advanceTimersByTimeAsync(100); // 成功 → 失败 1 → 退避
    // 交替失败从未连续达到 2：仍在轮询。
    expect(controller.isRunning()).toBe(true);
    expect(maxErrorCalls).toBe(0);
    controller.stop();
  });

  test('stop：在途请求 abort 且不再发起（unmount 语义）；stop 后可重新 start', async () => {
    rs.useFakeTimers();
    let calls = 0;
    let lastSignal: AbortSignal | undefined;
    let abortEvent = false;
    const controller = createLongPollController<PollResult>(() => ({
      poll: (signal) => {
        calls += 1;
        lastSignal = signal;
        return new Promise(() => {}); // 永不 settle
      },
      isSettled: () => false,
      onPoll: () => {},
      onSettled: () => {},
      pollTimeoutMs: 1000,
    }));
    controller.start();
    await rs.advanceTimersByTimeAsync(0);
    expect(calls).toBe(1);
    lastSignal!.addEventListener('abort', () => {
      abortEvent = true;
    });
    controller.stop();
    expect(abortEvent).toBe(true); // 在途 abort
    expect(controller.isRunning()).toBe(false);
    await rs.advanceTimersByTimeAsync(10000); // 含单次超时到点
    expect(calls).toBe(1); // 不再发起（超时计时器已清理）
    controller.start(); // expired 重拉新码场景：可重新开始
    await rs.advanceTimersByTimeAsync(0);
    expect(calls).toBe(2);
    controller.stop();
  });

  test('退避等待中 stop → 立即中断，退避到点不再发起', async () => {
    rs.useFakeTimers();
    let calls = 0;
    const controller = createLongPollController<PollResult>(() => ({
      poll: () => {
        calls += 1;
        return Promise.reject(new Error('net'));
      },
      isSettled: () => false,
      onPoll: () => {},
      onSettled: () => {},
      pollTimeoutMs: 1000,
      baseDelayMs: 10000,
    }));
    controller.start();
    await rs.advanceTimersByTimeAsync(0); // 第 1 次失败 → 退避 10s
    expect(calls).toBe(1);
    controller.stop();
    await rs.advanceTimersByTimeAsync(20000);
    expect(calls).toBe(1); // 退避计时被清，不再发起
  });
});

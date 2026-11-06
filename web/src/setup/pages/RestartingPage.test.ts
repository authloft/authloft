// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化后移除）。
// @ts-ignore
import { describe, expect, test } from 'rstack/test';
// pollRestart 移至 ../wizard（零 Semi 依赖，rstest 可加载；
// RestartingPage.tsx Semi 化后模块图含 Semi import，测试不可直接引用）。
import {
  pollRestart,
  RESTART_POLL_INTERVAL_MS,
  RESTART_POLL_TIMEOUT_MS,
} from '../wizard';
import type { SetupStatusResult } from '../api';

/** 探测桩：按序回放结果，用尽后重复最后一项；记录调用次数。 */
function probe(results: SetupStatusResult[]) {
  const state = { calls: 0 };
  const check = async (): Promise<SetupStatusResult> => {
    state.calls += 1;
    return results[Math.min(state.calls - 1, results.length - 1)];
  };
  return { check, state };
}

/** 时钟桩：记录每次 sleep 的间隔，并按其推进时间。 */
function fakeClock(startAt = 0) {
  const state = { now: startAt, sleeps: [] as number[] };
  const sleep = async (ms: number): Promise<void> => {
    state.sleeps.push(ms);
    state.now += ms;
  };
  return { sleep, now: () => state.now, state };
}

describe('setup/RestartingPage pollRestart（§13.4 重启轮询）', () => {
  test('常量口径：2s 间隔 / 120s 超时', () => {
    expect(RESTART_POLL_INTERVAL_MS).toBe(2_000);
    expect(RESTART_POLL_TIMEOUT_MS).toBe(120_000);
  });

  test('2s 间隔轮询，status 404 视为完成', async () => {
    const probeStub = probe([
      { kind: 'setup' },
      { kind: 'unreachable' },
      { kind: 'gone' },
    ]);
    const clock = fakeClock();
    const handle = pollRestart({
      check: probeStub.check,
      sleep: clock.sleep,
      now: clock.now,
    });

    expect(await handle.done).toBe('restarted');
    // 起点立即探测一次，之后每 2s 一次，共 3 次探测、2 次 sleep。
    expect(probeStub.state.calls).toBe(3);
    expect(clock.state.sleeps).toEqual([
      RESTART_POLL_INTERVAL_MS,
      RESTART_POLL_INTERVAL_MS,
    ]);
  });

  test('首个探测即 404 → 立即完成，不进入定时等待', async () => {
    const probeStub = probe([{ kind: 'gone' }]);
    const clock = fakeClock();
    const handle = pollRestart({
      check: probeStub.check,
      sleep: clock.sleep,
      now: clock.now,
    });

    expect(await handle.done).toBe('restarted');
    expect(probeStub.state.calls).toBe(1);
    expect(clock.state.sleeps).toEqual([]);
  });

  test('连接被拒 / 超时 → 视为未恢复，继续轮询', async () => {
    const probeStub = probe([
      { kind: 'unreachable' },
      { kind: 'unreachable' },
      { kind: 'gone' },
    ]);
    const clock = fakeClock();
    const handle = pollRestart({
      check: probeStub.check,
      sleep: clock.sleep,
      now: clock.now,
    });

    expect(await handle.done).toBe('restarted');
    expect(probeStub.state.calls).toBe(3);
    expect(clock.state.sleeps).toEqual([
      RESTART_POLL_INTERVAL_MS,
      RESTART_POLL_INTERVAL_MS,
    ]);
  });

  test('120 秒仍未恢复 → 超时（不自动重试），之后不再探测', async () => {
    const probeStub = probe([{ kind: 'setup' }]);
    const clock = fakeClock();
    const handle = pollRestart({
      check: probeStub.check,
      sleep: clock.sleep,
      now: clock.now,
    });

    expect(await handle.done).toBe('timeout');
    // 起点立即探测，之后每 2s 一次；第 120s 的探测仍未恢复 → 超时。
    expect(probeStub.state.calls).toBe(61);
    expect(clock.state.sleeps.length).toBe(60);
    expect(clock.state.now).toBe(RESTART_POLL_TIMEOUT_MS);
  });

  test('恰好在 120s 时刻恢复 → 未超过超时线，按完成处理', async () => {
    const probeStub = probe([
      ...Array.from({ length: 60 }, () => ({ kind: 'setup' }) as SetupStatusResult),
      { kind: 'gone' },
    ]);
    const clock = fakeClock();
    const handle = pollRestart({
      check: probeStub.check,
      sleep: clock.sleep,
      now: clock.now,
    });

    expect(await handle.done).toBe('restarted');
    expect(probeStub.state.calls).toBe(61);
    expect(clock.state.now).toBe(RESTART_POLL_TIMEOUT_MS);
  });

  test('cancel：探测挂起期间取消 → done 以 cancelled 结束，不再探测', async () => {
    const state = { checks: 0, sleeps: 0 };
    let release!: (result: SetupStatusResult) => void;
    const check = (): Promise<SetupStatusResult> => {
      state.checks += 1;
      return new Promise((resolve) => {
        release = resolve;
      });
    };
    const sleep = (): Promise<void> => {
      state.sleeps += 1;
      return Promise.resolve();
    };
    const handle = pollRestart({ check, sleep, now: () => 0 });

    // pollRestart 同步发起首轮探测。
    expect(state.checks).toBe(1);
    handle.cancel();
    release({ kind: 'setup' });

    expect(await handle.done).toBe('cancelled');
    expect(state.checks).toBe(1);
    expect(state.sleeps).toBe(0);
  });

  test('cancel：sleep 挂起期间取消 → 醒来后终止，不再探测', async () => {
    const state = { checks: 0, sleeps: 0 };
    const check = async (): Promise<SetupStatusResult> => {
      state.checks += 1;
      return { kind: 'setup' };
    };
    let releaseSleep!: () => void;
    const sleep = (): Promise<void> => {
      state.sleeps += 1;
      return new Promise((resolve) => {
        releaseSleep = resolve;
      });
    };
    const handle = pollRestart({ check, sleep, now: () => 0 });

    // 让首轮探测（微任务）完成并进入首个 sleep。
    await new Promise((resolve) => {
      setTimeout(resolve, 0);
    });
    expect(state.sleeps).toBe(1);
    handle.cancel();
    releaseSleep();

    expect(await handle.done).toBe('cancelled');
    expect(state.checks).toBe(1);
    expect(state.sleeps).toBe(1);
  });
});

/**
 * 秒级倒计时（docs/前端架构.md §3.2 useCountdown 行 303）：基于 retryAfter /
 * expiresIn（生成消息里的 bigint，§1.12），暴露 seconds 与 expired；用时间戳
 * 而非递减计数——后台标签页 interval 被节流后回到前台按 deadline 重算，不漂移。
 *
 * 无 DOM 测试环境下测纯逻辑（countdownSeconds / secondsUntil），hook 壳只做
 * interval 绑定。
 */
import { useEffect, useState } from 'react';
import { toCount } from '../utils/int';

/** 秒级对齐的检查间隔（250ms：秒跳变及时，且平滑对齐 deadline）。 */
export const COUNTDOWN_TICK_MS = 250;

export interface CountdownState {
  seconds: number;
  expired: boolean;
}

/**
 * bigint（生成消息 int64）→ 倒计时秒数：undefined / 负值 → 0（无倒计时）；
 * 超 Number.MAX_SAFE_INTEGER 的异常时长按 0 兜底（倒计时是体验功能，
 * 不让 toCount 的断言炸组件树；§1.12 精度约束仍由 toCount 自身保证）。
 */
export function countdownSeconds(retryAfter: bigint | undefined): number {
  if (retryAfter === undefined || retryAfter < BigInt(0)) {
    return 0;
  }
  try {
    return toCount(retryAfter);
  } catch {
    return 0;
  }
}

/** 距 deadline 的剩余整秒（向上取整，剩余不足 1 秒按 1 计；已过期 → 0）。 */
export function secondsUntil(deadline: number, now: number): number {
  return Math.max(0, Math.ceil((deadline - now) / 1000));
}

/**
 * @param retryAfter 剩余秒数（生成消息 int64 bigint，如 ApiError.retryAfter、
 *        nextStep.retryAfter）；undefined = 无倒计时。
 * @returns seconds 剩余整秒；expired 是否到期（无倒计时恒为 true）。
 * 入参变化（新值）时重启倒计时。
 */
export function useCountdown(retryAfter: bigint | undefined): CountdownState {
  const total = countdownSeconds(retryAfter);
  const [state, setState] = useState<CountdownState>(() =>
    total <= 0
      ? { seconds: 0, expired: true }
      : { seconds: total, expired: false },
  );

  useEffect(() => {
    if (total <= 0) {
      setState({ seconds: 0, expired: true });
      return;
    }
    // 时间戳口径：deadline 固定，tick 每次用 Date.now() 重算剩余。
    const deadline = Date.now() + total * 1000;
    setState({ seconds: total, expired: false });
    const tick = () => {
      const seconds = secondsUntil(deadline, Date.now());
      setState({ seconds, expired: seconds <= 0 });
    };
    const timer = setInterval(tick, COUNTDOWN_TICK_MS);
    return () => clearInterval(timer);
  }, [total]);

  return state;
}

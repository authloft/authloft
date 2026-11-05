/**
 * 错误横幅（docs/前端架构.md §3.3 行 325）：错误文案（i18n 优先，其次信封 /
 * 错体兜底 message，§1.5 行 202）+ 冷却倒计时（retry_after，复用 shared/hooks 的
 * useCountdown，bigint 入参）+ locked 状态展示剩余时长（需求 §4.1.7）+
 * 可重试动作（§1.6「可重试」列；倒计时进行中禁用）。
 *
 * 文案解析（errorText）与剩余次数归一（attemptsCount）为纯函数，
 * node 环境测试覆盖。
 */
import { useCountdown } from '../hooks/useCountdown';
import { toCount } from '../utils/int';
import { hasKey, t } from '../i18n';
import styles from './ErrorBanner.module.less';

/**
 * 文案解析：i18nKey 可译 → 字典文案；否则用服务端兜底 message；两者皆无 →
 * unknown 兜底文案（§1.6 行 272：不暴露内部信息）。
 */
export function errorText(i18nKey: string, fallbackMessage?: string): string {
  if (hasKey(i18nKey)) {
    return t(i18nKey);
  }
  return fallbackMessage || t('errors.status.unknown');
}

/**
 * 剩余尝试次数：bigint（生成消息 int64）经 toCount 归一（§1.12 禁止
 * Number 直转）；缺失 / 非正值 / 超界 → 0（不展示）。
 */
export function attemptsCount(attemptsLeft: bigint | undefined): number {
  if (attemptsLeft === undefined || attemptsLeft <= BigInt(0)) {
    return 0;
  }
  try {
    return toCount(attemptsLeft);
  } catch {
    return 0;
  }
}

export interface ErrorBannerProps {
  /** shared/api/errors.ts 解析出的 i18n 键（errors.status.* / errors.code.*）。 */
  i18nKey: string;
  /** 服务端兜底文案（信封 error.message / ErrorInfo.message）。 */
  fallbackMessage?: string;
  /** 冷却 / 解封剩余秒数（too_many_requests / locked；bigint 直入）。 */
  retryAfter?: bigint;
  /** 剩余尝试次数（invalid_code；bigint 直入）。 */
  attemptsLeft?: bigint;
  /** §1.6「可重试」列。 */
  retryable?: boolean;
  /** 可重试动作；提供且 retryable 才渲染按钮，倒计时进行中禁用。 */
  onRetry?: () => void;
}

export function ErrorBanner({
  i18nKey,
  fallbackMessage,
  retryAfter,
  attemptsLeft,
  retryable,
  onRetry,
}: ErrorBannerProps) {
  const { seconds, expired } = useCountdown(retryAfter);
  const counting = !expired && seconds > 0;
  const attempts = attemptsCount(attemptsLeft);

  return (
    <div role="alert" className={styles.banner}>
      <p className={styles.text}>{errorText(i18nKey, fallbackMessage)}</p>
      {attempts > 0 && (
        <p className={styles.text}>
          {t('common.remainingAttempts', { count: attempts })}
        </p>
      )}
      {counting && (
        <p className={styles.text}>
          {t('common.remainingSeconds', { seconds })}
        </p>
      )}
      {retryable && onRetry && (
        <button
          type="button"
          className={styles.button}
          onClick={onRetry}
          disabled={counting}
        >
          {t('common.retry')}
        </button>
      )}
    </div>
  );
}

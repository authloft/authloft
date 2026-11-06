/**
 * 轻量加载指示（评审 P1-1）：10 行级 CSS 圆环，零第三方依赖；
 * 提交中按钮内嵌（size="sm"）与跳转 / 处理中帧（size="md"）共用。
 * 零文案硬编码：播报文案默认走 common.loading（§9 第 3 条）。
 */
import { t } from '../i18n';
import styles from './Spinner.module.less';

export interface SpinnerProps {
  /** 无障碍播报文案（默认 common.loading）。 */
  label?: string;
  /** 尺寸档：sm = 按钮内嵌；md = 独立帧（默认）。 */
  size?: 'sm' | 'md';
}

export function Spinner({ label, size = 'md' }: SpinnerProps) {
  return (
    <span
      role="status"
      aria-label={label ?? t('common.loading')}
      className={size === 'sm' ? styles.spinnerSm : styles.spinner}
    />
  );
}

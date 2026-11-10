/**
 * captcha 弹窗纯视图（无 DOM API、无 portal，renderToStaticMarkup 可测；
 * 脱体与焦点管理归 CaptchaDialog 薄壳，沿 QRCodePanel 的「纯视图 + 组件壳」
 * 分工惯例，docs/前端架构.md §3.3）。
 *
 * widget 以 attempt 为 key：每次询问重挂 → 天然换新凭据（服务端校验即失效，
 * §2.5），不依赖调用方记得 reset；配置变化另由 CaptchaWidget 的 adapterKey
 * 重建兜住（含服务端降级为 image）。
 *
 * 零 Semi 依赖：login 端不引 UI 库（《CODE_GUIDE》§4.1 第 13 条），本弹窗
 * login 与 account 共用。
 */
import { useId, type KeyboardEvent, type Ref } from 'react';
import type { CaptchaConfig } from '../../gen/proto/api/common/v1/captcha_pb';
import { t } from '../i18n';
import { CaptchaWidget, type CaptchaWidgetHandle } from './CaptchaWidget';
import styles from './CaptchaDialogView.module.less';

export interface CaptchaDialogViewProps {
  config: CaptchaConfig;
  /** 本轮 gate 内第几次询问（0 起）；作 widget key 保证每次换新凭据。 */
  attempt: number;
  /** 原请求在途：确认 / 取消禁用，防重复消费凭据。 */
  submitting: boolean;
  /** 弹窗内错误位（i18n 键）：未作答即确认 / 上一轮凭据被判无效。 */
  errorKey?: string;
  widgetRef?: Ref<CaptchaWidgetHandle>;
  dialogRef?: Ref<HTMLDivElement>;
  onKeyDown?: (event: KeyboardEvent<HTMLDivElement>) => void;
  onConfirm: () => void;
  onCancel: () => void;
}

export function CaptchaDialogView({
  config,
  attempt,
  submitting,
  errorKey,
  widgetRef,
  dialogRef,
  onKeyDown,
  onConfirm,
  onCancel,
}: CaptchaDialogViewProps) {
  const titleId = useId();
  return (
    <div className={styles.overlay}>
      <div
        className={styles.dialog}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        ref={dialogRef}
        onKeyDown={onKeyDown}
      >
        <h2 className={styles.title} id={titleId}>
          {t('common.captchaTitle')}
        </h2>
        <p className={styles.hint}>{t('common.captchaHint')}</p>
        <div className={styles.widget}>
          <CaptchaWidget key={attempt} captcha={config} ref={widgetRef} />
        </div>
        {errorKey !== undefined && (
          <p className={styles.error} role="alert">
            {t(errorKey)}
          </p>
        )}
        <div className={styles.actions}>
          <button
            type="button"
            className={styles.cancel}
            onClick={onCancel}
            disabled={submitting}
          >
            {t('common.cancel')}
          </button>
          <button
            type="button"
            className={styles.confirm}
            onClick={onConfirm}
            disabled={submitting}
          >
            {t('common.captchaConfirm')}
          </button>
        </div>
      </div>
    </div>
  );
}

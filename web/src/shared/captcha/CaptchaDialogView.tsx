/**
 * captcha 弹窗内容（纯视图，无 DOM API、无 portal，renderToStaticMarkup 可测）：
 * 只出提示语 + widget + 错误位。窗体（遮罩 / 标题 / 确认取消 / 焦点 / Esc）归
 * 调用方注入的 ModalRenderer——login 自绘、account / admin 走 Semi，通用层因此
 * 不沾染任何 UI 库（《CODE_GUIDE》§4.1 第 11、13 条）。
 *
 * widget 以 attempt 为 key：每次询问重挂 → 天然换新凭据（服务端校验即失效，
 * §2.5），不依赖调用方记得 reset；配置变化另由 CaptchaWidget 的 adapterKey
 * 重建兜住（含服务端降级为 image）。
 */
import type { Ref } from 'react';
import type { CaptchaConfig } from '../../gen/proto/api/common/v1/captcha_pb';
import { t } from '../i18n';
import { CaptchaWidget, type CaptchaWidgetHandle } from './CaptchaWidget';
import styles from './CaptchaDialogView.module.less';

export interface CaptchaDialogViewProps {
  config: CaptchaConfig;
  /** 本轮 gate 内第几次询问（0 起）；作 widget key 保证每次换新凭据。 */
  attempt: number;
  /** 弹窗内错误位（i18n 键）：未作答即确认 / 上一轮凭据被判无效。 */
  errorKey?: string;
  widgetRef?: Ref<CaptchaWidgetHandle>;
}

export function CaptchaDialogView({
  config,
  attempt,
  errorKey,
  widgetRef,
}: CaptchaDialogViewProps) {
  return (
    <div className={styles.content}>
      <p className={styles.hint}>{t('common.captchaHint')}</p>
      <div className={styles.widget}>
        <CaptchaWidget key={attempt} captcha={config} ref={widgetRef} />
      </div>
      {errorKey !== undefined && (
        <p className={styles.error} role="alert">
          {t(errorKey)}
        </p>
      )}
    </div>
  );
}

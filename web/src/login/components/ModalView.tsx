/**
 * login 域弹窗纯视图（无 DOM API、无 portal，renderToStaticMarkup 可测）：
 * 遮罩 + 窗体 + 标题 + 关闭图标 + children + 确认/取消两按钮（或自定义 footer）。
 * 脱体与焦点管理归 Modal 薄壳，沿 QRCodePanel「纯视图 + 组件壳」的分工惯例
 * （docs/前端架构.md §3.3）。
 *
 * 零 Semi 依赖：login 端不引 UI 库（《CODE_GUIDE》§4.1 第 13 条）。props 命名
 * 沿用 Semi Modal 的 ModalRenderer 契约，窗体视觉是 login 域所有弹窗的统一基线。
 */
import { useId, type KeyboardEvent, type MouseEvent, type Ref } from 'react';
import type { ModalProps } from '../../shared/components/modal';
import { t } from '../../shared/i18n';
import styles from './Modal.module.less';

/** 壳自行消费的 prop 不进纯视图。 */
type ViewProps = Omit<
  ModalProps,
  'visible' | 'closeOnEsc' | 'maskClosable' | 'afterClose'
>;

export interface ModalViewProps extends ViewProps {
  dialogRef?: Ref<HTMLDivElement>;
  onKeyDown?: (event: KeyboardEvent<HTMLDivElement>) => void;
  onMaskClick?: (event: MouseEvent<HTMLDivElement>) => void;
}

export function ModalView({
  title,
  children,
  okText,
  cancelText,
  confirmLoading = false,
  cancelLoading = false,
  okButtonProps,
  cancelButtonProps,
  hasCancel = true,
  footer,
  closable = true,
  onOk,
  onCancel,
  dialogRef,
  onKeyDown,
  onMaskClick,
}: ModalViewProps) {
  const titleId = useId();
  const okDisabled = confirmLoading || okButtonProps?.disabled === true;
  const cancelDisabled = cancelLoading || cancelButtonProps?.disabled === true;

  return (
    <div className={styles.overlay} onClick={onMaskClick}>
      <div
        className={styles.dialog}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        ref={dialogRef}
        onKeyDown={onKeyDown}
      >
        <div className={styles.header}>
          <h2 className={styles.title} id={titleId}>
            {title}
          </h2>
          {closable && (
            <button
              type="button"
              className={styles.close}
              aria-label={t('common.close')}
              onClick={onCancel}
            >
              <span aria-hidden="true">×</span>
            </button>
          )}
        </div>
        <div className={styles.body}>{children}</div>
        {footer !== undefined ? (
          <div className={styles.actions}>{footer}</div>
        ) : (
          <div className={styles.actions}>
            {hasCancel && (
              <button
                type="button"
                className={styles.cancel}
                onClick={onCancel}
                disabled={cancelDisabled}
              >
                {cancelText}
              </button>
            )}
            <button
              type="button"
              className={styles.confirm}
              onClick={onOk}
              disabled={okDisabled}
            >
              {okText}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

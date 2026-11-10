/**
 * captcha 弹窗组件壳：脱体（createPortal 到 body）+ 焦点管理 + ESC + 滚动锁。
 *  markup 全在 CaptchaDialogView（纯视图可测），本壳只承担必须在 DOM 上做的
 *  四件事，沿 QRCodePanel「控制器 / 纯视图 / 组件壳」的分工惯例。
 *
 * 脱体是必需的而非可选：account 侧 ContactBindForm 渲染在 Semi Modal 内部，
 * 不脱体会被 Modal 的滚动容器裁剪。portal 只出现在本壳——纯视图不含 portal，
 * 故 renderToStaticMarkup 测试链不受影响（服务端渲染不支持 portal）。
 *
 * 遮罩点击不关窗：本弹窗是流程中的必经安全步骤，误触遮罩丢失作答的代价高于
 * 便利；关窗只经取消按钮与 ESC 两条显式路径。
 */
import { useEffect, useRef, type KeyboardEvent } from 'react';
import { createPortal } from 'react-dom';
import type { CaptchaConfig } from '../../gen/proto/api/common/v1/captcha_pb';
import type { CaptchaPayload } from '../../gen/proto/api/sso/v1/login_pb';
import { CaptchaDialogView } from './CaptchaDialogView';
import type { CaptchaWidgetHandle } from './CaptchaWidget';

/** 一次开窗的渲染态；undefined = 关窗。 */
export interface CaptchaDialogSession {
  config: CaptchaConfig;
  attempt: number;
  submitting: boolean;
  errorKey?: string;
}

export interface CaptchaDialogProps {
  session?: CaptchaDialogSession;
  /** 用户确认且凭据就绪（壳内取 widget getToken 后上抛）。 */
  onConfirm: (token: CaptchaPayload) => void;
  /** 用户确认但挑战未作答 / 厂商 token 未就绪。 */
  onNotReady: () => void;
  onCancel: () => void;
}

/** 焦点陷阱的停靠点；iframe 计入——厂商挑战内容跨域不可遍历，停在 iframe 本身。 */
const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), iframe, [tabindex]:not([tabindex="-1"])';

export function CaptchaDialog({
  session,
  onConfirm,
  onNotReady,
  onCancel,
}: CaptchaDialogProps) {
  const dialogRef = useRef<HTMLDivElement | null>(null);
  const widgetRef = useRef<CaptchaWidgetHandle | null>(null);
  const open = session !== undefined;
  const submitting = session?.submitting ?? false;

  useEffect(() => {
    if (!open) {
      return;
    }
    const restoreTo =
      document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null;
    // 滚动锁是 body 级副作用，非组件布局内联样式（《CODE_GUIDE》§4.1 第 20 条
    // 禁的是后者）；卸载必须还原，否则关窗后整页不可滚。
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    dialogRef.current?.focus();
    return () => {
      document.body.style.overflow = previousOverflow;
      restoreTo?.focus();
    };
  }, [open]);

  const handleKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === 'Escape') {
      if (!submitting) {
        event.stopPropagation();
        onCancel();
      }
      return;
    }
    if (event.key !== 'Tab') {
      return;
    }
    const root = dialogRef.current;
    if (root === null) {
      return;
    }
    const nodes = Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE));
    if (nodes.length === 0) {
      event.preventDefault();
      return;
    }
    const first = nodes[0];
    const last = nodes[nodes.length - 1];
    const active = document.activeElement;
    if (event.shiftKey && (active === first || active === root)) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && active === last) {
      event.preventDefault();
      first.focus();
    }
  };

  const handleConfirm = () => {
    const token = widgetRef.current?.getToken();
    if (token === undefined) {
      onNotReady();
      return;
    }
    onConfirm(token);
  };

  // 服务端渲染无 document：portal 不可用，直接不渲染（纯视图另有测试覆盖）。
  if (!open || typeof document === 'undefined') {
    return null;
  }

  return createPortal(
    <CaptchaDialogView
      config={session.config}
      attempt={session.attempt}
      submitting={session.submitting}
      errorKey={session.errorKey}
      widgetRef={widgetRef}
      dialogRef={dialogRef}
      onKeyDown={handleKeyDown}
      onConfirm={handleConfirm}
      onCancel={onCancel}
    />,
    document.body,
  );
}

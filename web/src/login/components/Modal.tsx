/**
 * login 域弹窗组件壳：脱体（createPortal 到 body）+ 焦点管理 + Esc + 滚动锁。
 * markup 全在 ModalView（纯视图可测），本壳只承担必须在 DOM 上做的四件事。
 *
 * 实现 shared/components/modal 的 ModalRenderer 契约；props 命名与语义沿用
 * @douyinfe/semi-ui Modal（account / admin 侧由 shared/app-ui/Modal 用 Semi 实现），
 * 两端可互换注入，通用弹窗内容（captcha 等）不认识具体 UI 库。
 */
import { useEffect, useRef, type KeyboardEvent, type MouseEvent } from 'react';
import { createPortal } from 'react-dom';
import type { ModalProps } from '../../shared/components/modal';
import { ModalView } from './ModalView';

/** 焦点陷阱的停靠点；iframe 计入——厂商挑战内容跨域不可遍历，停在 iframe 本身。 */
const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), iframe, [tabindex]:not([tabindex="-1"])';

export function Modal({
  visible,
  closeOnEsc = true,
  maskClosable = false,
  afterClose,
  ...view
}: ModalProps) {
  const dialogRef = useRef<HTMLDivElement | null>(null);
  // afterClose 只作卸载时回调，不进 effect 依赖：调用方多传一个 inline 箭头，
  // 不该反复触发滚动锁还原与焦点归还。
  const afterCloseRef = useRef(afterClose);
  afterCloseRef.current = afterClose;

  useEffect(() => {
    if (!visible) {
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
      afterCloseRef.current?.();
    };
  }, [visible]);

  const handleKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === 'Escape') {
      if (closeOnEsc) {
        event.stopPropagation();
        view.onCancel?.(event);
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

  const handleMaskClick = (event: MouseEvent<HTMLDivElement>) => {
    // 只在点到遮罩本身时关窗；窗体内冒泡上来的一律忽略。
    if (!maskClosable || event.target !== event.currentTarget) {
      return;
    }
    view.onCancel?.(event);
  };

  // 服务端渲染无 document：portal 不可用，直接不渲染（纯视图另有测试覆盖）。
  if (!visible || typeof document === 'undefined') {
    return null;
  }

  return createPortal(
    <ModalView
      {...view}
      dialogRef={dialogRef}
      onKeyDown={handleKeyDown}
      onMaskClick={handleMaskClick}
    />,
    document.body,
  );
}

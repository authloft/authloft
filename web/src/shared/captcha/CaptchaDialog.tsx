/**
 * captcha 弹窗组件壳：把 gate 的开窗态映射到调用方注入的 ModalRenderer，
 * 并在确认时取 widget 凭据。窗体（脱体 / 遮罩 / 标题 / 两按钮 / 焦点 / Esc /
 * 滚动锁）全归注入实现——login 传 login/components/Modal，account / admin 传
 * shared/app-ui/Modal，本壳与纯内容因此零 UI 库依赖、零 DOM API。
 *
 * 凭据读取留在本壳而非 Modal：Modal 是 domain 通用窗体，不该认识 captcha。
 *
 * 传给 Modal 的 props 全部沿用 Semi Modal 的同名字段（契约见
 * shared/components/modal）。在途策略也按 Semi 词汇显式表达：两个 loading 字段
 * 由两端窗体归一为按钮硬禁用，关窗三条路径（关闭图标 / Esc / 遮罩）分别由
 * closable / closeOnEsc / maskClosable 控制，契约不再自造 `busy` 这种把四件事
 * 捆一起的字段。
 */
import { useRef } from 'react';
import type { CaptchaConfig } from '../../gen/proto/api/common/v1/captcha_pb';
import type { CaptchaPayload } from '../../gen/proto/api/sso/v1/login_pb';
import type { ModalRenderer } from '../components/modal';
import { t } from '../i18n';
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
  /** domain 窗体实现（契约见 shared/components/modal）。 */
  modal: ModalRenderer;
  session?: CaptchaDialogSession;
  /** 用户确认且凭据就绪（壳内取 widget getToken 后上抛）。 */
  onConfirm: (token: CaptchaPayload) => void;
  /** 用户确认但挑战未作答 / 厂商 token 未就绪。 */
  onNotReady: () => void;
  onCancel: () => void;
}

export function CaptchaDialog({
  modal,
  session,
  onConfirm,
  onNotReady,
  onCancel,
}: CaptchaDialogProps) {
  const widgetRef = useRef<CaptchaWidgetHandle | null>(null);

  const handleOk = () => {
    const token = widgetRef.current?.getToken();
    if (token === undefined) {
      onNotReady();
      return;
    }
    onConfirm(token);
  };

  if (session === undefined) {
    return null;
  }

  const Modal = modal;
  const submitting = session.submitting;
  return (
    <Modal
      visible
      title={t('common.captchaTitle')}
      okText={t('common.captchaConfirm')}
      cancelText={t('common.cancel')}
      confirmLoading={submitting}
      cancelLoading={submitting}
      closable={!submitting}
      closeOnEsc={!submitting}
      maskClosable={false}
      onOk={handleOk}
      onCancel={onCancel}
    >
      <CaptchaDialogView
        config={session.config}
        attempt={session.attempt}
        errorKey={session.errorKey}
        widgetRef={widgetRef}
      />
    </Modal>
  );
}

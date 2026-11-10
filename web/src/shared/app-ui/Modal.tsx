/**
 * account / admin 域弹窗：用 Semi Modal 实现 shared/components/modal 的
 * ModalRenderer 契约（login 侧同一契约由 login/components/Modal 自绘实现）。
 * 窗体归 domain，通用弹窗内容（captcha 等）经注入消费，两端各自保证域内视觉一致。
 *
 * 落 shared/app-ui 而非 shared/components：本文件依赖 Semi，而 login 禁止
 * import app-ui 与 @douyinfe/semi-ui（《CODE_GUIDE》§4.1 第 13 条）。
 *
 * 契约只承载内容与行为，尺寸 / 层级 / 居中在此处按 account 域基线补齐；
 * 无自绘样式故无同名 module.less。
 */
import type { ComponentProps, ReactNode } from 'react';
import { Modal as SemiModal } from '@douyinfe/semi-ui';
import type { ModalProps } from '../components/modal';

type SemiModalProps = ComponentProps<typeof SemiModal>;

type Assert<T extends true> = T;
/**
 * 编译期钉死「契约 ⊆ Semi Modal API」：契约里的每个键都必须是 Semi 认识的同名
 * prop，且值类型可赋给 Semi 对应字段。契约改名 / 放宽类型 / 多加自造字段时这里
 * 直接报 tsc 错误，防止两端实现与 Semi 词汇悄悄漂移。
 */
export type ModalContractSemiConformance = Assert<
  keyof ModalProps extends keyof SemiModalProps
    ? ModalProps extends SemiModalProps
      ? true
      : false
    : false
>;

/** 与 tokens.less 的 @z-modal 同值（Less 变量进不了 TS）：须盖住触发它的 Semi 浮层。 */
const Z_INDEX = 1100;

/** 与 login 域窗体同宽（login/components/Modal.module.less 的 min(420px, 100%)）。 */
const WIDTH = 420;

export function Modal({
  confirmLoading,
  cancelLoading,
  okButtonProps,
  cancelButtonProps,
  ...rest
}: ModalProps): ReactNode {
  return (
    <SemiModal
      centered
      width={WIDTH}
      zIndex={Z_INDEX}
      maskClosable={false}
      {...rest}
      confirmLoading={confirmLoading}
      cancelLoading={cancelLoading}
      // Semi 的 loading 只给按钮加 pointer-events: none，键盘 Enter 仍能触发
      // onOk / onCancel（重复提交凭据）。契约规定 loading 即硬禁用，在此补齐。
      okButtonProps={{
        ...okButtonProps,
        disabled: okButtonProps?.disabled === true || confirmLoading === true,
      }}
      cancelButtonProps={{
        ...cancelButtonProps,
        disabled:
          cancelButtonProps?.disabled === true || cancelLoading === true,
      }}
    />
  );
}

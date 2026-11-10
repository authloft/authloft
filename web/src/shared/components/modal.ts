/**
 * 弹窗渲染契约（零第三方 UI 依赖，login 可安全引用，《CODE_GUIDE》§4.1 第 13 条）。
 *
 * 通用弹窗内容（如 shared/captcha 的人机校验）不自带窗体，由调用方注入本契约的
 * 实现：login 传 `login/components/Modal`（自绘），account / admin 传
 * `shared/app-ui/Modal`（Semi）。窗体归属 domain 才能保证同一 entry 内所有弹窗
 * 视觉一致，通用层则不沾染任何 UI 库。
 *
 * 【API 口径】props 一律沿用 @douyinfe/semi-ui Modal 的同名同义字段，只取本工程
 * 两端实现都真正支持的那部分（不铺满 Semi 全量属性表）：`visible` / `title` /
 * `okText` / `onOk` / `confirmLoading` …，熟悉 Semi 文档的人无需另学一套词汇。
 * 契约与 Semi 的对齐由 `shared/app-ui/Modal.tsx` 的编译期断言钉死——改名、类型
 * 放宽或多出 Semi 不认识的字段都会在那里报 tsc 错误。
 *
 * 【职责边界】实现方拥有遮罩 / 窗体 / 标题 / 确认取消两按钮 / 焦点管理 / Esc /
 * 滚动锁；调用方只给正文与文案、动作回调。尺寸、层级、居中等视觉基线归各 domain
 * 实现自定（login 在同名 module.less，account / admin 在 app-ui 适配层），不进契约。
 *
 * 【与 Semi 的两处差异】① `visible=false` 时两端都直接卸载窗体（不做 keepDOM /
 * 退场动画）；② `confirmLoading` / `cancelLoading` 除 loading 表现外还禁用对应按钮
 * （含键盘触发），Semi 仅靠 `pointer-events: none` 挡鼠标。差异只在实现层，props
 * 名称与语义不变。
 */
import type { ComponentType, ReactNode, SyntheticEvent } from 'react';

/** 按钮透传属性：只取两端都用得上的 `disabled`（Semi 的 ButtonProps 子集）。 */
export interface ModalButtonProps {
  disabled?: boolean;
}

export interface ModalProps {
  /** 同 Semi Modal.visible：开窗态；关窗时窗体卸载。 */
  visible: boolean;
  /** 同 Semi Modal.title。 */
  title?: ReactNode;
  /** 同 Semi Modal.children：窗体正文。 */
  children?: ReactNode;

  /** 同 Semi Modal.okText / cancelText：两按钮文案。 */
  okText?: string;
  cancelText?: string;
  /** 同 Semi Modal.confirmLoading / cancelLoading：在途表现并禁用对应按钮。 */
  confirmLoading?: boolean;
  cancelLoading?: boolean;
  /** 同 Semi Modal.okButtonProps / cancelButtonProps：按钮透传（当前只支持 disabled）。 */
  okButtonProps?: ModalButtonProps;
  cancelButtonProps?: ModalButtonProps;
  /** 同 Semi Modal.hasCancel：默认 true，false 时只留确认按钮。 */
  hasCancel?: boolean;
  /** 同 Semi Modal.footer：给出后整块替换默认按钮区。 */
  footer?: ReactNode;

  /** 同 Semi Modal.closable：默认 true，显示右上关闭图标并走 onCancel。 */
  closable?: boolean;
  /** 同 Semi Modal.closeOnEsc：默认 true；Esc 走 onCancel。 */
  closeOnEsc?: boolean;
  /** 同 Semi Modal.maskClosable：本契约默认 false（域弹窗统一不误触关窗）。 */
  maskClosable?: boolean;
  /** 同 Semi Modal.afterClose：窗体关闭（卸载）后回调。 */
  afterClose?: () => void;

  /** 同 Semi Modal.onOk / onCancel；回传触发它的事件（按钮点击 / 关闭图标 / Esc / 遮罩）。 */
  onOk?: (event: SyntheticEvent) => void;
  onCancel?: (event: SyntheticEvent) => void;
}

/** 弹窗渲染器：按 domain 注入的窗体组件（Semi Modal 本身也满足该类型）。 */
export type ModalRenderer = ComponentType<ModalProps>;

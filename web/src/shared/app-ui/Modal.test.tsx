// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化后移除）。
// @ts-ignore
import { afterAll, describe, expect, test, rs } from 'rstack/test';
import * as React from 'react';
import { Modal } from './Modal';
import type { ModalProps } from '../components/modal';

rs.stubGlobal('React', React);

afterAll(() => {
  rs.unstubAllGlobals();
});

/** 本测试关心的 SemiModal 入参切片。 */
interface SemiModalPassedProps {
  visible: boolean;
  title?: React.ReactNode;
  okText?: string;
  cancelText?: string;
  centered?: boolean;
  width?: number;
  zIndex?: number;
  maskClosable?: boolean;
  closable?: boolean;
  closeOnEsc?: boolean;
  confirmLoading?: boolean;
  cancelLoading?: boolean;
  okButtonProps?: { disabled?: boolean };
  cancelButtonProps?: { disabled?: boolean };
}

/**
 * 适配层是无 hook 的纯函数：直接调用取回它交给 SemiModal 的 element props，
 * 绕开 Semi Modal 的 portal（SSR 环境不可渲染），只断言接线与归一化。
 */
function semiProps(props: ModalProps): SemiModalPassedProps {
  const element = Modal(props) as React.ReactElement<SemiModalPassedProps>;
  return element.props;
}

const BASE: ModalProps = {
  visible: true,
  title: '安全验证',
  okText: '验证并继续',
  cancelText: '取消',
};

describe('app-ui/Modal 域基线', () => {
  test('Semi 同名字段与 account 域视觉基线一并透传', () => {
    expect(semiProps(BASE)).toMatchObject({
      visible: true,
      title: '安全验证',
      okText: '验证并继续',
      cancelText: '取消',
      centered: true,
      width: 420,
      zIndex: 1100,
      maskClosable: false,
    });
  });

  test('调用方可显式覆盖 maskClosable / closable / closeOnEsc', () => {
    expect(
      semiProps({
        ...BASE,
        maskClosable: true,
        closable: false,
        closeOnEsc: false,
      }),
    ).toMatchObject({
      maskClosable: true,
      closable: false,
      closeOnEsc: false,
    });
  });
});

describe('app-ui/Modal 的 loading → 硬禁用归一', () => {
  test('confirmLoading / cancelLoading → 两按钮 disabled（挡住键盘 Enter）', () => {
    const props = semiProps({
      ...BASE,
      confirmLoading: true,
      cancelLoading: true,
    });
    expect(props.confirmLoading).toBe(true);
    expect(props.cancelLoading).toBe(true);
    expect(props.okButtonProps.disabled).toBe(true);
    expect(props.cancelButtonProps.disabled).toBe(true);
  });

  test('调用方自带的按钮透传属性不被吞掉', () => {
    const props = semiProps({
      ...BASE,
      okButtonProps: { disabled: true },
      cancelButtonProps: { disabled: false },
    });
    expect(props.okButtonProps.disabled).toBe(true);
    expect(props.cancelButtonProps.disabled).toBe(false);
  });

  test('无 loading 时不误禁用', () => {
    const props = semiProps(BASE);
    expect(props.okButtonProps.disabled).toBe(false);
    expect(props.cancelButtonProps.disabled).toBe(false);
  });
});

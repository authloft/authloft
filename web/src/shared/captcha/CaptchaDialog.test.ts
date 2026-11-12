// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化后移除）。
// @ts-ignore
import { afterAll, describe, expect, test, rs } from 'rstack/test';
import * as React from 'react';
// 本仓 rstest 为 node 环境（无 DOM）：渲染断言走 renderToStaticMarkup。
// 窗体（portal / 焦点陷阱 / 滚动锁）归注入的 domain Modal，本链用 stub
// ModalRenderer 断言 CaptchaDialog 透传的 Semi 风格 props；纯内容独立断言。
import { renderToStaticMarkup } from 'react-dom/server';
import { create } from '@bufbuild/protobuf';
import { CaptchaConfigSchema } from '../../gen/proto/api/common/v1/captcha_pb';
import type { ModalProps } from '../components/modal';
import { CaptchaDialog, type CaptchaDialogProps } from './CaptchaDialog';
import { CaptchaDialogView } from './CaptchaDialogView';

const { createElement } = React;
rs.stubGlobal('React', React);

afterAll(() => {
  rs.unstubAllGlobals();
});

const IMAGE = create(CaptchaConfigSchema, {
  providerKey: 'builtin_image',
  type: 'image',
});

const noop = () => {};

/** 记录本轮注入 Modal 实际收到的 props，并把内容渲染进静态 markup。 */
let lastProps: ModalProps | undefined;
function ProbeModal(props: ModalProps) {
  lastProps = props;
  return createElement(
    'section',
    {
      'data-visible': String(props.visible),
      'data-mask-closable': String(props.maskClosable),
    },
    props.title,
    props.children,
  );
}

function renderContent(
  props: Partial<React.ComponentProps<typeof CaptchaDialogView>> = {},
) {
  return renderToStaticMarkup(
    createElement(CaptchaDialogView, {
      config: IMAGE,
      attempt: 0,
      ...props,
    }),
  );
}

function renderDialog(props: Partial<CaptchaDialogProps> = {}) {
  lastProps = undefined;
  return renderToStaticMarkup(
    createElement(CaptchaDialog, {
      modal: ProbeModal,
      session: { config: IMAGE, attempt: 0, submitting: false },
      onConfirm: noop,
      onNotReady: noop,
      onCancel: noop,
      ...props,
    }),
  );
}

describe('CaptchaDialogView 纯内容', () => {
  test('提示语 + widget，不含窗体骨架', () => {
    const markup = renderContent();
    expect(markup).toContain('请完成下方人机校验后继续');
    expect(markup).not.toContain('role="dialog"');
    expect(markup).not.toContain('验证并继续');
  });

  test('errorKey 缺省 → 无错误位', () => {
    expect(renderContent()).not.toContain('role="alert"');
  });

  test('凭据被判无效 → 内容内出「验证未通过」', () => {
    const markup = renderContent({ errorKey: 'errors.code.captcha_invalid' });
    expect(markup).toContain('role="alert"');
    expect(markup).toContain('验证未通过，请重试');
  });

  test('未作答即确认 → 内容内出「请完成验证」', () => {
    expect(
      renderContent({ errorKey: 'errors.code.captcha_required' }),
    ).toContain('请完成验证');
  });

  test('未知 type → widget 兜底错误态在窗内可见', () => {
    const markup = renderContent({
      config: create(CaptchaConfigSchema, {
        providerKey: 'x',
        type: 'future_v2',
      }),
    });
    expect(markup).toContain('请刷新重试');
  });

  test('厂商 type → 渲染 adapter 挂载点，不走兜底', () => {
    const markup = renderContent({
      config: create(CaptchaConfigSchema, {
        providerKey: 'cf_turnstile',
        type: 'turnstile',
        siteKey: '0x4AAA',
      }),
    });
    expect(markup).not.toContain('请刷新重试');
  });
});

describe('CaptchaDialog 壳 → 注入窗体的 Semi 风格 props', () => {
  test('session 缺省（关窗）→ 返回 null，不渲染窗体', () => {
    expect(renderDialog({ session: undefined })).toBe('');
    expect(lastProps).toBeUndefined();
  });

  test('开窗 → visible / 文案 / 关窗策略按 Semi 同名字段透传', () => {
    const markup = renderDialog();
    expect(markup).toContain('data-visible="true"');
    expect(markup).toContain('data-mask-closable="false"');
    expect(markup).toContain('安全验证');
    expect(markup).toContain('请完成下方人机校验后继续');
    expect(lastProps).toMatchObject({
      visible: true,
      title: '安全验证',
      okText: '验证并继续',
      cancelText: '取消',
      closable: true,
      closeOnEsc: true,
      maskClosable: false,
      confirmLoading: false,
      cancelLoading: false,
    });
  });

  test('在途 → 两按钮 loading 且封死图标 / Esc / 遮罩', () => {
    renderDialog({
      session: { config: IMAGE, attempt: 1, submitting: true },
    });
    expect(lastProps).toMatchObject({
      confirmLoading: true,
      cancelLoading: true,
      closable: false,
      closeOnEsc: false,
      maskClosable: false,
    });
  });

  test('onCancel 原样转交窗体（取消仍由 gate 兑现 undefined）', () => {
    const onCancel = () => {};
    renderDialog({ onCancel });
    expect(lastProps?.onCancel).toBe(onCancel);
  });

  test('onOk 未取得凭据 → 走 onNotReady，不上抛 onConfirm', () => {
    let notReady = 0;
    let confirmed = 0;
    renderDialog({
      onNotReady: () => {
        notReady += 1;
      },
      onConfirm: () => {
        confirmed += 1;
      },
    });
    // 服务端静态渲染不挂 ref，widgetRef.current 为 null：即「未作答」路径。
    lastProps?.onOk?.({} as React.SyntheticEvent);
    expect(notReady).toBe(1);
    expect(confirmed).toBe(0);
  });
});

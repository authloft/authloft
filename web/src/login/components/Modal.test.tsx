// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化后移除）。
// @ts-ignore
import { afterAll, describe, expect, test, rs } from 'rstack/test';
import * as React from 'react';
// 本仓 rstest 为 node 环境（无 DOM）：组件壳的 portal / 焦点陷阱 / 滚动锁
// 不在本链覆盖，只断言纯视图产出的可访问性骨架与 Semi 风格 props 语义。
import { renderToStaticMarkup } from 'react-dom/server';
import { ModalView } from './ModalView';

const { createElement } = React;
rs.stubGlobal('React', React);

afterAll(() => {
  rs.unstubAllGlobals();
});

function render(props: Partial<React.ComponentProps<typeof ModalView>> = {}) {
  return renderToStaticMarkup(
    createElement(ModalView, {
      title: '安全验证',
      okText: '验证并继续',
      cancelText: '取消',
      ...props,
    }),
  );
}

describe('login 域 ModalView 骨架', () => {
  test('dialog 角色 + aria-modal + 标题关联', () => {
    const markup = render();
    expect(markup).toContain('role="dialog"');
    expect(markup).toContain('aria-modal="true"');
    expect(markup).toContain('aria-labelledby=');
    expect(markup).toContain('安全验证');
  });

  test('默认两显式动作 + 关闭图标（Semi closable 同义）', () => {
    const markup = render();
    expect(markup).toContain('验证并继续');
    expect(markup).toContain('取消');
    expect(markup).toContain('aria-label="关闭"');
  });

  test('children 落在正文区', () => {
    const markup = render({ children: '请完成人机校验' });
    expect(markup).toContain('请完成人机校验');
  });
});

describe('login 域 ModalView 的 Semi 同名 props', () => {
  test('confirmLoading / cancelLoading → 两按钮禁用', () => {
    const markup = render({ confirmLoading: true, cancelLoading: true });
    expect(markup.match(/disabled=""/g)).toHaveLength(2);
  });

  test('okButtonProps / cancelButtonProps.disabled → 两按钮禁用', () => {
    const markup = render({
      okButtonProps: { disabled: true },
      cancelButtonProps: { disabled: true },
    });
    expect(markup.match(/disabled=""/g)).toHaveLength(2);
  });

  test('不在途 → 按钮可点', () => {
    expect(render()).not.toContain('disabled=""');
  });

  test('hasCancel=false → 只留确认按钮', () => {
    const markup = render({ hasCancel: false });
    expect(markup).toContain('验证并继续');
    expect(markup).not.toContain('>取消<');
  });

  test('footer 给出后整块替换默认按钮区', () => {
    const markup = render({
      footer: createElement('button', null, '自定义动作'),
    });
    expect(markup).toContain('自定义动作');
    expect(markup).not.toContain('验证并继续');
  });

  test('closable=false → 无关闭图标，取消按钮仍在', () => {
    const markup = render({ closable: false });
    expect(markup).not.toContain('aria-label="关闭"');
    expect(markup).toContain('取消');
  });
});

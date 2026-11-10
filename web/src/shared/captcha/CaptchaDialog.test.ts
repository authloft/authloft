// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化后移除）。
// @ts-ignore
import { afterAll, describe, expect, test, rs } from 'rstack/test';
import * as React from 'react';
// 本仓 rstest 为 node 环境（无 DOM）：渲染断言走 renderToStaticMarkup。
// 壳 CaptchaDialog 的 portal / 焦点陷阱 / 滚动锁属 DOM 副作用，不在本链覆盖
// （壳无 document 时返回 null，纯视图在此独立断言）。
import { renderToStaticMarkup } from 'react-dom/server';
import { create } from '@bufbuild/protobuf';
import { CaptchaConfigSchema } from '../../gen/proto/api/common/v1/captcha_pb';
import { CaptchaDialog } from './CaptchaDialog';
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

function render(
  props: Partial<React.ComponentProps<typeof CaptchaDialogView>> = {},
) {
  return renderToStaticMarkup(
    createElement(CaptchaDialogView, {
      config: IMAGE,
      attempt: 0,
      submitting: false,
      onConfirm: noop,
      onCancel: noop,
      ...props,
    }),
  );
}

describe('CaptchaDialogView 无障碍骨架', () => {
  test('dialog 角色 + aria-modal + 标题关联', () => {
    const markup = render();
    expect(markup).toContain('role="dialog"');
    expect(markup).toContain('aria-modal="true"');
    expect(markup).toContain('aria-labelledby=');
    expect(markup).toContain('安全验证');
    expect(markup).toContain('请完成下方人机校验后继续');
  });

  test('确认与取消两个显式动作', () => {
    const markup = render();
    expect(markup).toContain('验证并继续');
    expect(markup).toContain('取消');
  });
});

describe('CaptchaDialogView 状态帧', () => {
  test('在途 → 两个按钮均禁用（防重复消费凭据）', () => {
    const markup = render({ submitting: true });
    expect(markup).toContain('disabled=""');
    expect(markup.match(/disabled=""/g)).toHaveLength(2);
  });

  test('不在途 → 按钮可点', () => {
    expect(render()).not.toContain('disabled=""');
  });

  test('errorKey 缺省 → 无错误位', () => {
    expect(render()).not.toContain('role="alert"');
  });

  test('凭据被判无效 → 弹窗内出「验证未通过」', () => {
    const markup = render({ errorKey: 'errors.status.captcha_invalid' });
    expect(markup).toContain('role="alert"');
    expect(markup).toContain('验证未通过，请重试');
  });

  test('未作答即确认 → 弹窗内出「请完成验证」', () => {
    const markup = render({ errorKey: 'errors.status.captcha_required' });
    expect(markup).toContain('请完成验证');
  });
});

describe('CaptchaDialogView 配置分派透传', () => {
  test('未知 type → CaptchaWidget 兜底错误态在窗内可见', () => {
    const markup = render({
      config: create(CaptchaConfigSchema, {
        providerKey: 'x',
        type: 'future_v2',
      }),
    });
    expect(markup).toContain('请刷新重试');
  });

  test('厂商 type → 渲染 adapter 挂载点，不走兜底', () => {
    const markup = render({
      config: create(CaptchaConfigSchema, {
        providerKey: 'cf_turnstile',
        type: 'turnstile',
        siteKey: '0x4AAA',
      }),
    });
    expect(markup).not.toContain('请刷新重试');
  });
});

describe('CaptchaDialog 壳的服务端边界', () => {
  test('无 document（node 环境）→ 返回 null，不触发 portal', () => {
    const markup = renderToStaticMarkup(
      createElement(CaptchaDialog, {
        session: { config: IMAGE, attempt: 0, submitting: false },
        onConfirm: noop,
        onNotReady: noop,
        onCancel: noop,
      }),
    );
    expect(markup).toBe('');
  });

  test('session 缺省（关窗）→ 返回 null', () => {
    const markup = renderToStaticMarkup(
      createElement(CaptchaDialog, {
        onConfirm: noop,
        onNotReady: noop,
        onCancel: noop,
      }),
    );
    expect(markup).toBe('');
  });
});

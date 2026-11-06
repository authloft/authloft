// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化后移除）。
// @ts-ignore
import { afterAll, describe, expect, test, rs } from 'rstack/test';
import * as React from 'react';
// 本仓 rstest 为 node 环境（无 DOM），渲染断言走 react-dom/server 的
// renderToStaticMarkup（沿 components.test.ts 的测试边界惯例）；rstest 对
// .tsx 采用 classic JSX runtime，渲染前 stub 全局 React，仅测试进程内生效。
// 交互 / effect 生命周期在 Image.test.ts 的纯逻辑层覆盖（adapter 类无 DOM
// 依赖路径）；本文件覆盖分派逻辑与静态渲染两端。
import { renderToStaticMarkup } from 'react-dom/server';
import { create } from '@bufbuild/protobuf';
import {
  CaptchaConfigSchema,
  type CaptchaConfig,
} from '../../gen/proto/api/common/v1/captcha_pb';
import {
  CaptchaWidget,
  adapterFactoryFor,
  adapterKey,
} from './CaptchaWidget';
import { createHCaptchaAdapter } from './adapters/HCaptcha';
import { createImageAdapter } from './adapters/Image';
import { createRecaptchaAdapter } from './adapters/Recaptcha';
import { createTurnstileAdapter } from './adapters/Turnstile';

const { createElement } = React;
rs.stubGlobal('React', React);

afterAll(() => {
  rs.unstubAllGlobals();
});

interface CaptchaInit {
  providerKey?: string;
  type?: string;
  siteKey?: string;
}

/** 生成物消息构造（报文类型只从 gen 引用，沿 components.test.ts 惯例）。 */
function makeCaptcha(init: CaptchaInit): CaptchaConfig {
  return create(CaptchaConfigSchema, init);
}

describe('adapterFactoryFor 分派（§3.5 行 350；§2.5 行 500 四种 type + 未知兜底）', () => {
  test('image → Image 工厂（含降级态）', () => {
    expect(adapterFactoryFor('image')).toBe(createImageAdapter);
  });

  test('turnstile / recaptcha / hcaptcha → 各自厂商 wrapper 工厂', () => {
    expect(adapterFactoryFor('turnstile')).toBe(createTurnstileAdapter);
    expect(adapterFactoryFor('recaptcha')).toBe(createRecaptchaAdapter);
    expect(adapterFactoryFor('hcaptcha')).toBe(createHCaptchaAdapter);
  });

  test('未知 type（协议外取值）→ undefined（兜底错误态）', () => {
    expect(adapterFactoryFor('future_vendor_v2')).toBeUndefined();
    expect(adapterFactoryFor('')).toBeUndefined();
  });
});

describe('adapterKey 重建判据（§3.5 行 361：权威来源变化按新 type 重渲染）', () => {
  test('同值不重建（对象换引用、值不变 → key 相同）', () => {
    const a = makeCaptcha({ providerKey: 'cf_turnstile', type: 'turnstile', siteKey: '0x4AAA' });
    const b = makeCaptcha({ providerKey: 'cf_turnstile', type: 'turnstile', siteKey: '0x4AAA' });
    expect(adapterKey(a)).toBe(adapterKey(b));
  });

  test('type 变（含服务端降级 image）→ key 变', () => {
    const before = makeCaptcha({ providerKey: 'cf_turnstile', type: 'turnstile' });
    const degraded = makeCaptcha({ providerKey: 'builtin_image', type: 'image' });
    expect(adapterKey(before)).not.toBe(adapterKey(degraded));
    // 同 providerKey 仅 type 变也重建
    const x = makeCaptcha({ providerKey: 'p', type: 'turnstile' });
    const y = makeCaptcha({ providerKey: 'p', type: 'image' });
    expect(adapterKey(x)).not.toBe(adapterKey(y));
  });

  test('providerKey / siteKey 变 → key 变', () => {
    const base = makeCaptcha({ providerKey: 'a', type: 'image', siteKey: '' });
    expect(
      adapterKey(makeCaptcha({ providerKey: 'b', type: 'image', siteKey: '' })),
    ).not.toBe(adapterKey(base));
    expect(
      adapterKey(makeCaptcha({ providerKey: 'a', type: 'image', siteKey: 's' })),
    ).not.toBe(adapterKey(base));
  });
});

describe('CaptchaWidget 静态渲染（四态容器 / 未知 type 兜底）', () => {
  test('type=image → 渲染 wrapper 容器（adapter 挂载点）', () => {
    const markup = renderToStaticMarkup(
      createElement(CaptchaWidget, {
        captcha: makeCaptcha({ providerKey: 'builtin_image', type: 'image' }),
      }),
    );
    expect(markup).toContain('<div');
  });

  test('type=turnstile / recaptcha / hcaptcha → 渲染 wrapper 容器（不兜底；挂载细节由各 adapter 测试覆盖）', () => {
    for (const type of ['turnstile', 'recaptcha', 'hcaptcha']) {
      const markup = renderToStaticMarkup(
        createElement(CaptchaWidget, {
          captcha: makeCaptcha({
            providerKey: 'cf_turnstile',
            type,
            siteKey: '0x4AAA',
          }),
        }),
      );
      expect(markup).toContain('<div');
      expect(markup).not.toContain('role="alert"');
    }
  });

  test('未知 type（协议外取值）→ 兜底错误态「请刷新重试」', () => {
    const markup = renderToStaticMarkup(
      createElement(CaptchaWidget, {
        captcha: makeCaptcha({ providerKey: 'x', type: 'future_vendor_v2' }),
      }),
    );
    expect(markup).toContain('请刷新重试');
    expect(markup).toContain('role="alert"');
  });
});

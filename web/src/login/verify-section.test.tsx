// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化后移除）。
// @ts-ignore
import { afterEach, beforeEach, describe, expect, rs, test } from 'rstack/test';
import * as React from 'react';
// 本仓 rstest 为 node 环境（无 DOM）：静态渲染走 react-dom/server 的
// renderToStaticMarkup（沿 register-reset.test.tsx / factors.test.tsx 惯例）。
import { renderToStaticMarkup } from 'react-dom/server';
import {
  VerifyCodeSection,
  type VerifyCodeSectionProps,
} from './VerifyCodeSection';

const { createElement } = React;

// 评审 P2-10：OTPForm / RegisterPage / ResetPage 三处 verify 段收敛的
// 共享实现——可配提交文案、id 关联、attemptsLeft / retryAfter 展示口径、
// resendDisabled 禁用口径差异（OTPForm 含 disabled、页族不含）的静态帧覆盖。
// 消费方回归（OTPForm「登录」/ 页族「下一步」按钮文案、倒计时、剩余次数）由
// factors.test.tsx 与 register-reset.test.tsx 既有用例承担。

beforeEach(() => {
  // rstest 对 .tsx 走 classic JSX runtime：渲染前 stub 全局 React（仅测试进程）。
  rs.stubGlobal('React', React);
});

afterEach(() => {
  rs.unstubAllGlobals();
});

function renderSection(props: Partial<VerifyCodeSectionProps> = {}): string {
  return renderToStaticMarkup(
    createElement(VerifyCodeSection, {
      id: 'vs-code',
      length: 6,
      code: '',
      onCodeChange: () => {},
      onSubmit: () => {},
      submitLabelKey: 'login.nextStep',
      classes: {},
      ...props,
    }),
  );
}

describe('VerifyCodeSection 可配文案与结构（P2-10）', () => {
  test('提交按钮文案键可配：login.nextStep / login.submit；label 关联注入 id', () => {
    expect(renderSection()).toContain('下一步');
    expect(renderSection({ submitLabelKey: 'login.submit' })).toContain(
      '>登录</button>',
    );
    const markup = renderSection();
    expect(markup).toContain('for="vs-code"');
    expect(markup).toContain('id="vs-code"');
  });

  test('attemptsLeft 展示 / 缺省不展示（§1.3 行 151）', () => {
    expect(renderSection({ attemptsLeft: BigInt(3) })).toContain(
      '还可尝试 3 次',
    );
    expect(renderSection()).not.toContain('还可尝试');
  });

  test('retryAfter 重发倒计时（§1.3 行 115/150）；缺省重发立即可用', () => {
    expect(renderSection({ retryAfter: BigInt(60) })).toContain(
      '60 秒后可重发',
    );
    expect(renderSection()).toContain('重新发送');
  });

  test('resendDisabled 口径保留：true → 重发禁用；缺省（页族口径）不禁用', () => {
    // 静态输出属性按 prop 序渲染（type → disabled）。
    expect(renderSection({ resendDisabled: true })).toContain(
      'type="button" disabled=""',
    );
    expect(renderSection()).not.toContain('type="button" disabled=""');
  });

  test('disabled → 提交禁用（§3.2）；loading 同口径', () => {
    expect(renderSection({ disabled: true })).toContain(
      'type="submit" disabled=""',
    );
    expect(renderSection({ loading: true })).toContain(
      'type="submit" disabled=""',
    );
  });
});

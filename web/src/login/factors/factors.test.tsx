// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化后移除）。
// @ts-ignore
import { beforeEach, describe, expect, rs, test } from 'rstack/test';
import * as React from 'react';
// 本仓 rstest 为 node 环境（无 DOM）：静态渲染走 react-dom/server 的
// renderToStaticMarkup（沿 login-container.test.ts / components.test.ts 惯例）；
// useCountdown 在静态渲染下只执行初始 state（effects 不跑），倒计时文案可断言。
import { renderToStaticMarkup } from 'react-dom/server';
import { create } from '@bufbuild/protobuf';
import { FieldSchema } from '../../gen/proto/api/sso/v1/envelope_pb';
import { OTPForm, isOtpForm } from './OTPForm';
import { PasswordForm } from './PasswordForm';
import { RecoveryCodeForm } from './RecoveryCodeForm';
import { lookupFactor } from './registry';

const { createElement } = React;

/** 主因子 challenge 步目标字段（§2.1 行 390：otp_sms challengeFields）。 */
const phoneField = create(FieldSchema, {
  name: 'phone',
  label: '手机号',
  type: 'phone',
  required: true,
});

function renderOtp(
  props: Record<string, unknown>,
  fields = [phoneField],
): string {
  return renderToStaticMarkup(
    createElement(OTPForm, {
      fields,
      loading: false,
      disabled: false,
      onSubmit: () => {},
      ...props,
    }),
  );
}

beforeEach(() => {
  // rstest 对 .tsx 走 classic JSX runtime：渲染前 stub 全局 React（仅测试进程）。
  rs.stubGlobal('React', React);
});

// ---------------------------------------------------------------------------
// registry 映射（§4.3 行 434；新增 otp_sms / otp_email / recovery_code）
// ---------------------------------------------------------------------------

describe('lookupFactor / isOtpForm（§4.3 映射表三态）', () => {
  test('otp_sms / otp_email → OTPForm；recovery_code → RecoveryCodeForm；totp → null；password → PasswordForm', () => {
    expect(lookupFactor('otp_sms')).toBe(OTPForm);
    expect(lookupFactor('otp_email')).toBe(OTPForm);
    expect(lookupFactor('recovery_code')).toBe(RecoveryCodeForm);
    expect(lookupFactor('totp')).toBeNull();
    expect(lookupFactor('password')).toBe(PasswordForm);
  });

  test('isOtpForm：OTP 系组件判定（容器 verify 段扩展 props 的渲染开关）', () => {
    expect(isOtpForm(lookupFactor('otp_sms'))).toBe(true);
    expect(isOtpForm(lookupFactor('otp_email'))).toBe(true);
    expect(isOtpForm(lookupFactor('password'))).toBe(false);
    expect(isOtpForm(lookupFactor('totp'))).toBe(false);
    expect(isOtpForm(undefined)).toBe(false);
  });

  test('缺映射 → undefined（webauthn / thirdparty 归后续实现，不静默回退）', () => {
    expect(lookupFactor('webauthn')).toBeUndefined();
    expect(lookupFactor('thirdparty')).toBeUndefined();
    expect(lookupFactor('')).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// OTPForm 双段（§4.3 行 436；§1.10 行 306-307 challenge→form）
// ---------------------------------------------------------------------------

describe('OTPForm challenge 段（§2.6 行 544-545）', () => {
  test('主因子：目标输入（快照 challengeFields → FieldRenderer）+ 发送按钮', () => {
    const markup = renderOtp({ step: 'challenge' });
    expect(markup).toContain('<form');
    expect(markup).toContain('手机号');
    // FieldRenderer 的 phone type → tel 控件（§1.11 行 326）。
    expect(markup).toContain('type="tel"');
    expect(markup).toContain('发送验证码');
  });

  test('MFA：maskedTarget 掩码展示、不渲染目标输入（§2.6 行 545 不传目标）', () => {
    const markup = renderOtp({ step: 'challenge', maskedTarget: '138****8000' });
    expect(markup).toContain('138****8000');
    expect(markup).not.toContain('type="tel"');
    expect(markup).toContain('发送验证码');
  });

  test('step 缺省按 challenge 段渲染（§9 第 18 条零值兜底）', () => {
    expect(renderOtp({})).toContain('发送验证码');
  });

  test('loading / disabled 禁用发送（§3.2）', () => {
    expect(renderOtp({ step: 'challenge', loading: true })).toContain('disabled=""');
    expect(renderOtp({ step: 'challenge', disabled: true })).toContain('disabled=""');
  });
});

describe('OTPForm verify 段（§2.6 行 546 payload {code}）', () => {
  test('CodeInput 输码（one-time-code / 粘贴拆分由 CodeInput 承担）+ 倒计时 + 提交', () => {
    const markup = renderOtp({ step: 'verify', retryAfter: BigInt(60) });
    // react-dom/server 静态输出保留 camelCase 属性名（autoComplete）。
    expect(markup).toContain('autoComplete="one-time-code"');
    expect(markup).toContain('60 秒后可重发');
    expect(markup).toContain('登录');
    // 倒计时未到期 → 重发禁用（§1.3 行 115 重发冷却）。
    expect(markup).toContain('disabled=""');
  });

  test('无倒计时（retryAfter 缺省）→ 重发立即可用（「重新发送」）', () => {
    const markup = renderOtp({ step: 'verify' });
    expect(markup).toContain('重新发送');
  });

  test('错误计数提示 attemptsLeft（§1.3 行 151；§1.6 行 247 invalid_code 带剩余次数）', () => {
    expect(renderOtp({ step: 'verify', attemptsLeft: BigInt(3) })).toContain('还可尝试 3 次');
    expect(renderOtp({ step: 'verify' })).not.toContain('还可尝试');
  });

  test('受控模式：code 注入 → CodeInput 渲染容器持有的值，实例重建不丢已输码', () => {
    const markup = renderOtp({
      step: 'verify',
      code: '123',
      onCodeChange: () => {},
    });
    // CodeInput 分段回填：前 3 格 value 为 1/2/3（§1.6 行 247 可重试原地语义，
    // 容器持值经 props 注入，不再依赖组件本地 state）。
    expect(markup).toContain('value="1"');
    expect(markup).toContain('value="2"');
    expect(markup).toContain('value="3"');
  });
});

// ---------------------------------------------------------------------------
// RecoveryCodeForm（§4.3 行 441；§2.6 行 550）
// ---------------------------------------------------------------------------

describe('RecoveryCodeForm（仅二次因子，§1.10 行 310）', () => {
  const codeField = create(FieldSchema, {
    name: 'code',
    label: '恢复码',
    type: 'text',
    required: true,
  });

  test('fields 下发渲染（普通文本输入，xxxx-xxxx 最简输入）+ 提交按钮', () => {
    const markup = renderToStaticMarkup(
      createElement(RecoveryCodeForm, {
        fields: [codeField],
        loading: false,
        disabled: false,
        onSubmit: () => {},
      }),
    );
    expect(markup).toContain('<form');
    expect(markup).toContain('恢复码');
    // 普通文本输入（§4.3 行 441：不做自动格式化）。
    expect(markup).toContain('type="text"');
    expect(markup).toContain('登录');
  });

  test('loading / disabled 禁用提交（§3.2）', () => {
    const base = { fields: [codeField], onSubmit: () => {} };
    expect(
      renderToStaticMarkup(
        createElement(RecoveryCodeForm, { ...base, loading: true, disabled: false }),
      ),
    ).toContain('disabled=""');
    expect(
      renderToStaticMarkup(
        createElement(RecoveryCodeForm, { ...base, loading: false, disabled: true }),
      ),
    ).toContain('disabled=""');
  });
});

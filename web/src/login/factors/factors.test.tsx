// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化后移除）。
// @ts-ignore
import { beforeEach, describe, expect, rs, test } from 'rstack/test';
import * as React from 'react';
// 本仓 rstest 为 node 环境（无 DOM）：静态渲染走 react-dom/server 的
// renderToStaticMarkup（沿 login-container.test.ts / components.test.ts 惯例）；
// useCountdown 在静态渲染下只执行初始 state（effects 不跑），倒计时文案可断言。
import { renderToStaticMarkup } from 'react-dom/server';
import { create, type JsonObject } from '@bufbuild/protobuf';
import { FieldSchema } from '../../gen/proto/api/sso/v1/envelope_pb';
import type {
  OidcContext,
  SnapshotProvider,
} from '../../shared/types/init';
import { OTPForm, isOtpForm } from './OTPForm';
import { PasswordForm } from './PasswordForm';
import {
  ProviderButtons,
  providerDisplayName,
  startRedirect,
} from './ProviderButtons';
import { RecoveryCodeForm, recoverySubmitGuard } from './RecoveryCodeForm';
import {
  WebAuthnButton,
  authenticate,
  isWebAuthnForm,
} from './WebAuthnButton';
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
  test('otp_sms / otp_email → OTPForm；recovery_code → RecoveryCodeForm；totp → null；password → PasswordForm；webauthn → WebAuthnButton', () => {
    expect(lookupFactor('otp_sms')).toBe(OTPForm);
    expect(lookupFactor('otp_email')).toBe(OTPForm);
    expect(lookupFactor('recovery_code')).toBe(RecoveryCodeForm);
    expect(lookupFactor('totp')).toBeNull();
    expect(lookupFactor('password')).toBe(PasswordForm);
    expect(lookupFactor('webauthn')).toBe(WebAuthnButton);
  });

  test('isOtpForm：OTP 系组件判定（容器 verify 段扩展 props 的渲染开关）', () => {
    expect(isOtpForm(lookupFactor('otp_sms'))).toBe(true);
    expect(isOtpForm(lookupFactor('otp_email'))).toBe(true);
    expect(isOtpForm(lookupFactor('password'))).toBe(false);
    expect(isOtpForm(lookupFactor('totp'))).toBe(false);
    expect(isOtpForm(undefined)).toBe(false);
  });

  test('缺映射 → undefined（thirdparty 由 MethodTabs 链路接入，不进 registry，不静默回退）', () => {
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

  test('加载视觉：challenge 段 loading → spinner + 「发送中…」（非 loading 原样）', () => {
    const markup = renderOtp({ step: 'challenge', loading: true });
    expect(markup).toContain('aria-label="加载中…"'); // Spinner 内嵌
    expect(markup).toContain('发送中…');
    expect(markup).not.toContain('发送验证码</button>');
    expect(renderOtp({ step: 'challenge' })).toContain('发送验证码');
  });

  test('加载视觉：verify 段 loading → spinner 前置 + 原文案保留（VerifyCodeSection 共享口径）', () => {
    const markup = renderOtp({ step: 'verify', loading: true });
    expect(markup).toContain('aria-label="加载中…"');
    expect(markup).toContain('登录</button>');
  });

  test('initialValues 回填（评审 P1-5：传输失败 reset 后已输入目标不丢）', () => {
    const markup = renderOtp({
      step: 'challenge',
      initialValues: { phone: '13800000000' },
    });
    expect(markup).toContain('value="13800000000"');
    // 缺省 → 空值初态（既有行为不变）。
    expect(renderOtp({ step: 'challenge' })).toContain('value=""');
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

  test('加载视觉：loading → spinner + 「登录中…」替换按钮文案', () => {
    const markup = renderToStaticMarkup(
      createElement(RecoveryCodeForm, {
        fields: [codeField],
        loading: true,
        disabled: false,
        onSubmit: () => {},
      }),
    );
    expect(markup).toContain('aria-label="加载中…"');
    expect(markup).toContain('登录中…');
  });

  test('recoverySubmitGuard（评审 P0-2）：空值拦截（错误槽文案 + 焦点锚 fr-code）；满值放行', () => {
    // 空恢复码不直提：拦截 + 聚焦首错字段（FieldRenderer 缺省 idPrefix 'fr'）。
    const block = recoverySubmitGuard([codeField], {});
    expect(block?.errors).toEqual({ code: '请填写此项' });
    expect(block?.focusId).toBe('fr-code');
    // 纯空白同空值（isFilled 去首尾空白）。
    expect(recoverySubmitGuard([codeField], { code: '  ' })?.focusId).toBe('fr-code');
    // 满值放行（xxxx-xxxx 原样，不做格式化校验，§4.3 行 441）。
    expect(recoverySubmitGuard([codeField], { code: 'abcd-1234' })).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// ProviderButtons 图标墙 + redirect 渠道分派（§4.3 行 454）
// ---------------------------------------------------------------------------

describe('ProviderButtons 图标墙（§4.3 行 454；§2.7.1 行 560-574）', () => {
  const providers: SnapshotProvider[] = [
    { providerKey: 'qq', displayName: 'QQ', type: 'qq', channel: 'redirect', icon: 'https://ex.test/qq.png', uiGroup: 'social', sortOrder: '10' },
    { providerKey: 'scan', displayName: '微信扫码', type: 'wechat_mp_scan', channel: 'qrcode', uiGroup: 'social', sortOrder: '20' },
    { providerKey: 'wxmp', displayName: '微信', type: 'wechat_mp', channel: 'api', uiGroup: 'social', sortOrder: '30' },
    { providerKey: 'ent', displayName: '企业SSO', type: 'cas', channel: 'redirect', uiGroup: 'enterprise', sortOrder: '5' },
  ];

  function renderWall(list: readonly SnapshotProvider[] = providers): string {
    return renderToStaticMarkup(
      createElement(ProviderButtons, { providers: list }),
    );
  }

  test('channel=api 不渲染（§4.3 行 456 宿主承载）；未知 channel 不渲染（不硬编码渠道，§4.3 行 454）', () => {
    const withUnknown = [
      ...providers,
      { providerKey: 'x', displayName: '未知渠道', type: 'x', channel: 'teleport' },
    ];
    const markup = renderWall(withUnknown);
    expect(markup).not.toContain('微信</span>'); // wechat_mp（channel=api）不渲染
    expect(markup).not.toContain('未知渠道');
  });

  test('uiGroup 分组 + 组内 sortOrder 排序（§2.7.1 行 566-572）', () => {
    const markup = renderWall();
    expect(markup.indexOf('data-group="enterprise"')).toBeLessThan(
      markup.indexOf('data-group="social"'),
    );
    // 组内 10 < 20。
    expect(markup.indexOf('QQ')).toBeLessThan(markup.indexOf('微信扫码'));
  });

  test('图标经 ProviderIcon（§4.3 行 454）：icon 非空 <img>；空则内联 SVG 占位（§2.7.1 行 578 不做本地回落）', () => {
    expect(renderWall()).toContain('src="https://ex.test/qq.png"');
    const markup = renderWall([
      { providerKey: 'scan', displayName: '微信扫码', type: 'wechat_mp_scan', channel: 'qrcode' },
    ]);
    expect(markup).toContain('<svg');
  });
});

describe('startRedirect（redirect 渠道分派，§4.3 行 454 → §2.7.2 行 580）', () => {
  const OIDC: OidcContext = { client_id: 'cid', redirect_uri: 'https://app/cb' };

  test('Authorize 成功 → 跳转前落盘 oidc（§2.7.2 行 599-600）→ 返回 authorizeUrl', async () => {
    const saved: OidcContext[] = [];
    const url = await startRedirect('qq', {
      request: async () => 'https://auth.example/authorize?state=l…',
      readOidc: () => OIDC,
      save: (ctx) => saved.push(ctx),
    });
    expect(url).toBe('https://auth.example/authorize?state=l…');
    expect(saved).toEqual([OIDC]);
  });

  test('Authorize 失败 → undefined、不落盘', async () => {
    const saved: OidcContext[] = [];
    const url = await startRedirect('qq', {
      request: async () => {
        throw new Error('network');
      },
      readOidc: () => OIDC,
      save: (ctx) => saved.push(ctx),
    });
    expect(url).toBeUndefined();
    expect(saved).toHaveLength(0);
  });

  test('空 authorizeUrl → 不落盘不跳（零值兜底，§9 第 18 条）', async () => {
    const saved: OidcContext[] = [];
    const url = await startRedirect('qq', {
      request: async () => '',
      readOidc: () => OIDC,
      save: (ctx) => saved.push(ctx),
    });
    expect(url).toBeUndefined();
    expect(saved).toHaveLength(0);
  });

  test('非 OIDC 场景（快照无 oidc）→ 不落盘、仍返回 URL（§2.7.2 行 600：仅存在时落盘）', async () => {
    const saved: OidcContext[] = [];
    const url = await startRedirect('qq', {
      request: async () => 'https://auth.example/authorize',
      readOidc: () => undefined,
      save: (ctx) => saved.push(ctx),
    });
    expect(url).toBe('https://auth.example/authorize');
    expect(saved).toHaveLength(0);
  });
});

describe('providerDisplayName（评审 P2-9 失败帧展示名）', () => {
  const providers: SnapshotProvider[] = [
    { providerKey: 'qq', displayName: 'QQ', type: 'qq', channel: 'redirect' },
    { providerKey: 'noname', type: 'x', channel: 'redirect' },
  ];

  test('快照 displayName 优先；displayName 缺失 / 未知 key 回显 providerKey（§9 第 18 条）', () => {
    expect(providerDisplayName(providers, 'qq')).toBe('QQ');
    expect(providerDisplayName(providers, 'noname')).toBe('noname');
    expect(providerDisplayName(providers, 'ghost')).toBe('ghost');
    expect(providerDisplayName([], 'qq')).toBe('qq');
  });
});

// ---------------------------------------------------------------------------
// WebAuthnButton（§4.3 行 453；§1.10 行 308 usernameless）
// ---------------------------------------------------------------------------

/** 后端下发的 WebAuthn options（§1.3 行 117 challengeData 形状示例）。 */
const WEBAUTHN_CHALLENGE: JsonObject = {
  challenge: 'k9v0x8',
  rpId: 'example.test',
  timeout: 60000,
};
/** @simplewebauthn 断言对象形状（§12.9 行 1783 credential 透传）。 */
const WEBAUTHN_ASSERTION: JsonObject = {
  id: 'cred-1',
  rawId: 'cred-1',
  type: 'public-key',
  response: { clientDataJSON: 'eyJ9', authenticatorData: 'o2NmbQ' },
};

describe('WebAuthnButton（§4.3 行 453：缺失隐藏 / usernameless 双段按钮）', () => {
  function renderWebauthn(props: Record<string, unknown> = {}): string {
    return renderToStaticMarkup(
      createElement(WebAuthnButton, {
        fields: [],
        loading: false,
        disabled: false,
        onSubmit: () => {},
        ...props,
      }),
    );
  }

  test('window.PublicKeyCredential 缺失 → 隐藏（需求 §4.1.6 行 105，无「不支持」提示）', () => {
    const markup = renderWebauthn();
    expect(markup).not.toContain('<button');
    expect(markup).not.toContain('通行密钥');
  });

  test('challenge 步（无 challengeData）：发起按钮；不走通用字段渲染器（§2.6 行 547）', () => {
    rs.stubGlobal('window', { PublicKeyCredential: {} });
    const markup = renderWebauthn();
    expect(markup).toContain('使用通行密钥登录');
    // §4.3 行 453：不使用通用字段渲染器——无表单 / 输入控件、不收集用户名。
    expect(markup).not.toContain('<form');
    expect(markup).not.toContain('<input');
  });

  test('verify 段（challengeData 注入）：断言按钮 + loading / disabled 禁用（§3.2）', () => {
    rs.stubGlobal('window', { PublicKeyCredential: {} });
    expect(renderWebauthn({ challengeData: WEBAUTHN_CHALLENGE })).toContain('验证');
    expect(
      renderWebauthn({ challengeData: WEBAUTHN_CHALLENGE, loading: true }),
    ).toContain('disabled=""');
    expect(
      renderWebauthn({ challengeData: WEBAUTHN_CHALLENGE, disabled: true }),
    ).toContain('disabled=""');
  });

  test('加载视觉：loading → spinner + 「登录中…」（challenge / verify 同帧）', () => {
    rs.stubGlobal('window', { PublicKeyCredential: {} });
    const markup = renderWebauthn({ loading: true });
    expect(markup).toContain('aria-label="加载中…"');
    expect(markup).toContain('登录中…');
    expect(markup).not.toContain('使用通行密钥登录');
  });

  test('isWebAuthnForm：WebAuthn 判定（容器 challengeData / onCredential 注入开关）', () => {
    expect(isWebAuthnForm(lookupFactor('webauthn'))).toBe(true);
    expect(isWebAuthnForm(lookupFactor('password'))).toBe(false);
    expect(isWebAuthnForm(lookupFactor('totp'))).toBe(false);
    expect(isWebAuthnForm(undefined)).toBe(false);
  });
});

describe('authenticate（§12.9 方案 A：challengeData 整体透传；错误语义独立）', () => {
  test('optionsJSON 引用恒等透传（不解析、不复制、不额外传 allowCredentials，§1.10 行 308）→ 断言原样上抛', async () => {
    const seen: JsonObject[] = [];
    const result = await authenticate(WEBAUTHN_CHALLENGE, {
      start: async (optionsJSON) => {
        seen.push(optionsJSON);
        return WEBAUTHN_ASSERTION;
      },
    });
    expect(result).toEqual({ ok: true, credential: WEBAUTHN_ASSERTION });
    expect(seen[0]).toBe(WEBAUTHN_CHALLENGE); // 同一引用：整体透传（§12.9 行 1784）
  });

  test('NotAllowedError → cancelled（用户关闭浏览器原生 UI）；其他异常 → 失败（错误语义独立，§4.3 行 453）', async () => {
    const cancelled = await authenticate(WEBAUTHN_CHALLENGE, {
      start: async () => {
        throw new DOMException(
          'The operation either timed out or was not allowed.',
          'NotAllowedError',
        );
      },
    });
    expect(cancelled).toEqual({ ok: false, cancelled: true });
    const failed = await authenticate(WEBAUTHN_CHALLENGE, {
      start: async () => {
        throw new Error('network');
      },
    });
    expect(failed).toEqual({ ok: false, cancelled: false });
  });
});

// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化落地后移除）。
// @ts-ignore
import { afterAll, describe, expect, test, rs } from 'rstack/test';
import * as React from 'react';
// 本仓 rstest 为 node 环境（无 DOM、未装 happy-dom，rstack.config 不改）：
// 渲染断言走 react-dom/server 的 renderToStaticMarkup（零新依赖，
// 不需要 DOM），交互边界（粘贴拆分 / 退格跳格 / 分派）在纯函数层覆盖。
import { renderToStaticMarkup } from 'react-dom/server';
import { create } from '@bufbuild/protobuf';
import {
  FieldSchema,
  type Field,
} from '../../gen/proto/api/sso/v1/envelope_pb';
import { CodeInput, pasteValue, applyChar, applyBackspace } from './CodeInput';
import { FieldRenderer, controlKindFor, codeLengthOf } from './FieldRenderer';
import { ErrorBanner, errorText, attemptsCount } from './ErrorBanner';
import { CopyButton } from './CopyButton';
import {
  PasswordStrengthMeter,
  meterRules,
} from './PasswordStrengthMeter';

// rstest 对 .tsx 采用 classic JSX runtime（React.createElement），测试链未接
// @rsbuild/plugin-react 的 automatic runtime（rstack.config.mts 为既有配置
// 产物，本次不改）；组件源码沿仓库惯例不 import React（构建期 automatic
// runtime）。渲染断言触发 JSX 前在此提供全局 React（沿 hooks.test.ts 的
// rs.stubGlobal 模式），仅在测试进程内生效。
const { createElement } = React;
rs.stubGlobal('React', React);

afterAll(() => {
  rs.unstubAllGlobals();
});

interface FieldInit {
  name: string;
  label?: string;
  type: string;
  required?: boolean;
  length?: bigint;
}

/** 生成物消息构造（报文类型只从 gen 引用，禁止手写 interface 重复描述）。 */
function makeField(init: FieldInit): Field {
  return create(FieldSchema, init);
}

function renderFields(
  fields: readonly Field[],
  values: Readonly<Record<string, string>> = {},
): string {
  return renderToStaticMarkup(
    createElement(FieldRenderer, { fields, values, onChange: () => {} }),
  );
}

function count(haystack: string, needle: string): number {
  return haystack.split(needle).length - 1;
}

describe('FieldRenderer 分派（§1.11 的 12 种 type + 未知兜底）', () => {
  test('controlKindFor：12 种已知 type 全覆盖', () => {
    expect(controlKindFor('text')).toBe('text');
    expect(controlKindFor('password')).toBe('password');
    expect(controlKindFor('phone')).toBe('tel');
    expect(controlKindFor('email')).toBe('email');
    expect(controlKindFor('otp')).toBe('code');
    expect(controlKindFor('totp')).toBe('code');
    expect(controlKindFor('select')).toBe('select');
    expect(controlKindFor('checkbox')).toBe('checkbox');
    expect(controlKindFor('captcha')).toBe('skip');
    expect(controlKindFor('secret')).toBe('secret');
    expect(controlKindFor('json')).toBe('json');
    expect(controlKindFor('number')).toBe('number');
  });

  test('未知 type 走兜底渲染（单行文本）', () => {
    expect(controlKindFor('future_type_v2')).toBe('text');
    expect(controlKindFor('')).toBe('text');
    const markup = renderFields([
      makeField({ name: 'x', label: '新字段', type: 'future_type_v2' }),
    ]);
    expect(markup).toContain('name="x"');
    expect(markup).toContain('type="text"');
    expect(markup).toContain('新字段');
  });

  test('codeLengthOf：bigint 经 toCount 归一；零值 / 超界 → 默认 6', () => {
    expect(
      codeLengthOf(makeField({ name: 'code', type: 'otp', length: BigInt(6) })),
    ).toBe(6);
    expect(
      codeLengthOf(makeField({ name: 'code', type: 'otp', length: BigInt(4) })),
    ).toBe(4);
    // protojson 省略零值 → 解码为零值 0n → 默认 6。
    expect(codeLengthOf(makeField({ name: 'code', type: 'otp' }))).toBe(6);
    expect(
      codeLengthOf(makeField({ name: 'code', type: 'otp', length: BigInt(0) })),
    ).toBe(6);
    // 超 Number.MAX_SAFE_INTEGER：toCount 抛 RangeError → 体验参数兜底 6
    //（target ES2015 无 bigint 字面量 / 幂运算，沿 hooks.test.ts 的写法）。
    expect(
      codeLengthOf(
        makeField({
          name: 'code',
          type: 'otp',
          length: BigInt(Number.MAX_SAFE_INTEGER) + BigInt(1),
        }),
      ),
    ).toBe(6);
  });
});

describe('FieldRenderer 渲染（正常 + 边界）', () => {
  test('12 种 type 混合表单正常渲染（受控值注入）', () => {
    const fields = [
      makeField({
        name: 'username',
        label: '用户名',
        type: 'text',
        required: true,
      }),
      makeField({
        name: 'password',
        label: '密码',
        type: 'password',
        required: true,
      }),
      makeField({ name: 'phone', label: '手机号', type: 'phone' }),
      makeField({ name: 'email', label: '邮箱', type: 'email' }),
      makeField({
        name: 'code',
        label: '验证码',
        type: 'otp',
        length: BigInt(6),
      }),
      makeField({ name: 'agree', label: '同意条款', type: 'checkbox' }),
      makeField({ name: 'count', label: '数量', type: 'number' }),
      makeField({ name: 'mapping', label: '映射', type: 'json' }),
      makeField({ name: 'secret_key', label: '密钥', type: 'secret' }),
      makeField({ name: 'region', label: '区域', type: 'select' }),
    ];
    const markup = renderFields(fields, { username: 'alice', agree: 'true' });
    // 必填标记 + 受控值。
    expect(markup).toContain('用户名 *');
    expect(markup).toContain('value="alice"');
    expect(markup).toContain('checked=""');
    // 各控件形态。
    expect(markup).toContain('type="password"');
    expect(markup).toContain('type="tel"');
    expect(markup).toContain('type="email"');
    expect(markup).toContain('type="checkbox"');
    expect(markup).toContain('inputMode="decimal"');
    expect(markup).toContain('<textarea');
    expect(markup).toContain('<select');
    expect(markup).toContain('请选择');
    // otp → CodeInput：首格 one-time-code，6 格。
    expect(markup).toContain('autoComplete="one-time-code"');
    expect(count(markup, 'maxLength="1"')).toBe(6);
    // secret：默认掩码（password 型）+ 揭示按钮。
    expect(markup).toContain('显示');
  });

  test('totp 与 otp 同渲染逻辑，长度取 field.length', () => {
    const markup = renderFields([
      makeField({
        name: 'code',
        label: '动态口令',
        type: 'totp',
        length: BigInt(8),
      }),
    ]);
    expect(count(markup, 'maxLength="1"')).toBe(8);
    expect(markup).toContain('动态口令');
  });

  test('边界：空 fields 渲染为空', () => {
    expect(renderFields([])).toBe('');
  });

  test('边界：captcha 不走通用输入渲染（§1.11 由 CaptchaWidget 承接）', () => {
    expect(
      renderFields([
        makeField({ name: 'captcha', label: '人机校验', type: 'captcha' }),
      ]),
    ).toBe('');
    const markup = renderFields([
      makeField({ name: 'username', label: '用户名', type: 'text' }),
      makeField({ name: 'captcha', label: '人机校验', type: 'captcha' }),
    ]);
    expect(markup).toContain('name="username"');
    expect(markup).not.toContain('name="captcha"');
  });

  test('secret 揭示按钮文案走 i18n（common.reveal / common.hide）', () => {
    const markup = renderFields(
      [makeField({ name: 'sk', label: '密钥', type: 'secret' })],
      { sk: 'raw-value' },
    );
    expect(markup).toContain('显示');
    expect(markup).toContain('value="raw-value"');
    expect(markup).not.toContain('隐藏');
  });
});

describe('CodeInput 纯逻辑（交互边界）', () => {
  test('pasteValue：整串拆分 / 剥离非数字 / 超长截断', () => {
    expect(pasteValue('123456', 6)).toBe('123456');
    // 粘贴超长：只取前 6 位。
    expect(pasteValue('1234567890', 6)).toBe('123456');
    // 常见粘贴噪声：空白 / 连字符 / 点号。
    expect(pasteValue('  12 34-56 ', 6)).toBe('123456');
    // 全非数字 → 空串。
    expect(pasteValue('abc-def', 6)).toBe('');
    // length 0 → 空串。
    expect(pasteValue('12', 0)).toBe('');
    expect(pasteValue('123', 4)).toBe('123');
  });

  test('applyChar：追加 / 原位替换 / 非数字忽略 / 末格封顶', () => {
    // 空尾格追加，焦点落到新末位之后。
    expect(applyChar('123', 3, '4', 6)).toEqual({
      value: '1234',
      nextIndex: 4,
    });
    // 已有字符的格原位替换，焦点进一格。
    expect(applyChar('123456', 2, '9', 6)).toEqual({
      value: '129456',
      nextIndex: 3,
    });
    // 非数字：值与焦点都不动。
    expect(applyChar('123', 1, 'a', 6)).toEqual({ value: '123', nextIndex: 1 });
    // 末格替换后焦点封顶在最后一格。
    expect(applyChar('123456', 5, '9', 6)).toEqual({
      value: '123459',
      nextIndex: 5,
    });
    // 追加不超过总长。
    expect(applyChar('12345', 5, '6', 6)).toEqual({
      value: '123456',
      nextIndex: 5,
    });
  });

  test('applyBackspace：空格跳回上一格 / 有字符原位删 / 首格空不变', () => {
    // 当前格为空：删除末位并跳回上一格（§3.3「退格跳转」）。
    expect(applyBackspace('123', 4)).toEqual({ value: '12', nextIndex: 3 });
    expect(applyBackspace('1', 1)).toEqual({ value: '', nextIndex: 0 });
    // 当前格有字符：原位删除（后续左移），焦点停留。
    expect(applyBackspace('123456', 2)).toEqual({
      value: '12456',
      nextIndex: 2,
    });
    // 第 0 格且为空：不变。
    expect(applyBackspace('', 0)).toEqual({ value: '', nextIndex: 0 });
    expect(applyBackspace('123', 0)).toEqual({ value: '23', nextIndex: 0 });
  });
});

describe('CodeInput 渲染', () => {
  test('默认 6 格；首格 one-time-code，其余 off；已输入值分段展示', () => {
    const markup = renderToStaticMarkup(
      createElement(CodeInput, {
        value: '123',
        onChange: () => {},
        ariaLabel: '验证码',
      }),
    );
    expect(markup).toContain('role="group"');
    expect(markup).toContain('aria-label="验证码"');
    expect(count(markup, 'maxLength="1"')).toBe(6);
    expect(count(markup, 'autoComplete="one-time-code"')).toBe(1);
    expect(count(markup, 'autoComplete="off"')).toBe(5);
    expect(markup).toContain('value="1"');
    expect(markup).toContain('value="3"');
  });

  test('自定义长度按 length 渲染格数', () => {
    const markup = renderToStaticMarkup(
      createElement(CodeInput, { value: '', onChange: () => {}, length: 4 }),
    );
    expect(count(markup, 'maxLength="1"')).toBe(4);
  });
});

describe('ErrorBanner（错误文案 + 倒计时 + 可重试）', () => {
  test('errorText：i18n 优先 → 兜底 message → unknown 文案', () => {
    expect(errorText('errors.status.locked')).toBe('密码登录已被暂时锁定');
    // i18n 可译时兜底 message 不参与（§1.5 行 202：i18n 优先）。
    expect(errorText('errors.status.failed', '服务端文案')).toBe(
      '操作失败，请重试',
    );
    // 键不可译：用服务端兜底 message。
    expect(errorText('errors.status.not_a_status', '服务端文案')).toBe(
      '服务端文案',
    );
    // 都没有：unknown 兜底文案，不暴露内部信息（§1.6 行 272）。
    expect(errorText('errors.status.not_a_status')).toBe(
      '操作失败，请稍后重试',
    );
  });

  test('attemptsCount：bigint 经 toCount 归一；缺失 / 非正 / 超界 → 0', () => {
    expect(attemptsCount(undefined)).toBe(0);
    expect(attemptsCount(BigInt(0))).toBe(0);
    expect(attemptsCount(BigInt(3))).toBe(3);
    expect(attemptsCount(BigInt(Number.MAX_SAFE_INTEGER) + BigInt(1))).toBe(0);
  });

  test('locked 剩余时长：retry_after（bigint）驱动倒计时展示（需求 §4.1.7）', () => {
    const markup = renderToStaticMarkup(
      createElement(ErrorBanner, {
        i18nKey: 'errors.status.locked',
        retryAfter: BigInt(3600),
      }),
    );
    expect(markup).toContain('密码登录已被暂时锁定');
    expect(markup).toContain('剩余 3600 秒');
    // locked 不可重试（§1.6）：无按钮。
    expect(markup).not.toContain('<button');
  });

  test('invalid_code：attemptsLeft 展示剩余次数', () => {
    const markup = renderToStaticMarkup(
      createElement(ErrorBanner, {
        i18nKey: 'errors.status.invalid_code',
        attemptsLeft: BigInt(3),
      }),
    );
    expect(markup).toContain('验证码错误');
    expect(markup).toContain('剩余 3 次尝试机会');
  });

  test('可重试动作：无倒计时时按钮可用；倒计时进行中禁用', () => {
    const idle = renderToStaticMarkup(
      createElement(ErrorBanner, {
        i18nKey: 'errors.status.invalid_credentials',
        retryable: true,
        onRetry: () => {},
      }),
    );
    expect(idle).toContain('重试');
    expect(idle).not.toContain('disabled');

    const cooling = renderToStaticMarkup(
      createElement(ErrorBanner, {
        i18nKey: 'errors.status.too_many_requests',
        retryAfter: BigInt(30),
        retryable: true,
        onRetry: () => {},
      }),
    );
    expect(cooling).toContain('disabled');
    expect(cooling).toContain('剩余 30 秒');
  });

  test('role="alert" 语义 + 无 retryable 时不渲染按钮', () => {
    const markup = renderToStaticMarkup(
      createElement(ErrorBanner, { i18nKey: 'errors.code.unauthenticated' }),
    );
    expect(markup).toContain('role="alert"');
    expect(markup).toContain('请先登录');
    expect(markup).not.toContain('<button');
  });
});

describe('CopyButton（消费 useCopy + i18n 文案）', () => {
  test('正常渲染：按钮文案来自 common.copy', () => {
    const markup = renderToStaticMarkup(
      createElement(CopyButton, { text: 'al_9f2z' }),
    );
    expect(markup).toContain('<button');
    expect(markup).toContain('复制');
    expect(markup).not.toContain('已复制');
    // 文本不直接渲染在按钮里（复制内容不外显）。
    expect(markup).not.toContain('al_9f2z');
  });
});

describe('PasswordStrengthMeter（§5.6 同源规则清单）', () => {
  function renderMeter(
    password: string,
    opts?: { username?: string; email?: string },
  ): string {
    return renderToStaticMarkup(
      createElement(PasswordStrengthMeter, { password, ...opts }),
    );
  }

  test('meterRules：与 validatePassword 同源——弱密码列出未满足项，强密码全满足', () => {
    // §5.6 默认策略：8-64 位 + 3 字符类（大写 / 小写 / 数字）。
    const weak = meterRules('abc');
    expect(weak.filter((r) => !r.satisfied).map((r) => r.key)).toEqual([
      'too_short',
      'too_few_classes',
    ]);
    const strong = meterRules('Abcdef12');
    expect(strong.every((r) => r.satisfied)).toBe(true);
  });

  test('meterRules：固定不可配项——空白拒绝、超 64 位拒绝、含用户名 / 与标识相同拒绝', () => {
    expect(
      meterRules('Abc def1').find((r) => r.key === 'contains_whitespace')
        ?.satisfied,
    ).toBe(false);
    expect(
      meterRules(`Abcdef12${'x'.repeat(57)}`).find((r) => r.key === 'too_long')
        ?.satisfied,
    ).toBe(false);
    // username 传入时才适用 contains_username / same_as_identifier。
    const withUser = meterRules('AliceAbc12', { username: 'Alice' });
    expect(withUser.map((r) => r.key)).toContain('contains_username');
    expect(
      meterRules('alice@example.com', { email: 'alice@example.com' }).find(
        (r) => r.key === 'same_as_identifier',
      )?.satisfied,
    ).toBe(false);
    // 未传标识：两规则不适用（不出现在清单中）。
    expect(meterRules('Abcdef12').map((r) => r.key)).not.toContain(
      'contains_username',
    );
  });

  test('渲染：空密码不提示；弱密码逐条打叉；满足项打勾（data-satisfied）', () => {
    expect(renderMeter('')).toBe('');
    const markup = renderMeter('abc');
    expect(markup).toContain('role="status"');
    expect(markup).toContain('长度至少 8 位');
    expect(markup).toContain('✗ 长度至少 8 位');
    expect(markup).toContain('✓ 长度至多 64 位');
    expect(markup).toContain('data-satisfied="false"');
    expect(renderMeter('Abcdef12')).not.toContain('✗');
  });

  test('渲染：username 注入时展示「不能包含用户名」规则（注册 set_password 场景）', () => {
    const markup = renderMeter('Abcdef12', { username: 'alice' });
    expect(markup).toContain('不能包含用户名');
    expect(renderMeter('Abcdef12')).not.toContain('不能包含用户名');
  });
});

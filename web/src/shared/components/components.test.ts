// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化落地后移除）。
// @ts-ignore
import { afterAll, afterEach, describe, expect, test, rs } from 'rstack/test';
import * as React from 'react';
// 本仓 rstest 为 node 环境（无 DOM、未装 happy-dom，rstack.config 不改）：
// 渲染断言走 react-dom/server 的 renderToStaticMarkup（零新依赖，
// 不需要 DOM），交互边界（粘贴拆分 / 退格跳格 / 分派）在纯函数层覆盖。
import { renderToStaticMarkup } from 'react-dom/server';
import { create, type MessageInitShape } from '@bufbuild/protobuf';
import {
  FieldSchema,
  LoginFlowResponseSchema,
  BindResultSchema,
  type Field,
  type LoginFlowResponse,
} from '../../gen/proto/api/sso/v1/envelope_pb';
import {
  CreateQrcodeResponseSchema,
  type CreateQrcodeResponse,
} from '../../gen/proto/api/sso/v1/ticket_pb';
import { CodeInput, pasteValue, applyChar, applyBackspace } from './CodeInput';
import { FieldRenderer, controlKindFor, codeLengthOf } from './FieldRenderer';
import { ErrorBanner, errorText, attemptsCount } from './ErrorBanner';
import { CopyButton } from './CopyButton';
import {
  PasswordStrengthMeter,
  meterRules,
} from './PasswordStrengthMeter';
import {
  QRCodePanel,
  QRCodePanelView,
  createQRPanelController,
  pollTimeoutMsOf,
  ticketPhaseOf,
  qrFailureText,
  fetchFailureText,
  type QRPanelPhase,
} from './QRCodePanel';
import { ProviderIcon, resolveIconMode } from './ProviderIcon';
import { QrImage, buildQrSvg } from './QrImage';
import { ApiError } from '../api/errors';

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

// ---------------------------------------------------------------------------
// QRCodePanel（§3.3 行 345 扫码四态面板；§8.2 行 606 测试约束）
// ---------------------------------------------------------------------------

/** 生成物消息构造（报文类型只从 gen 引用，禁止手写 interface 重复描述）。 */
function envelope(
  init: MessageInitShape<typeof LoginFlowResponseSchema> = {},
): LoginFlowResponse {
  return create(LoginFlowResponseSchema, init);
}

function qrcodeResponse(seq: number): CreateQrcodeResponse {
  return create(CreateQrcodeResponseSchema, {
    ticket: `tk-${seq}`,
    ticketId: `id-${seq}`,
    qrcodeUrl: `https://cdn.example/q${seq}.jpg`,
    expiresIn: BigInt(600),
  });
}

describe('QRCodePanel 纯逻辑（信封 → 五态 / 超时换算 / 失败文案）', () => {
  test('ticketPhaseOf：ticket.status 五态优先（§2.8 行 717）', () => {
    expect(
      ticketPhaseOf(
        envelope({ status: 'pending', ticket: { status: 'pending', ticketId: 't' } }),
      ),
    ).toBe('pending');
    expect(
      ticketPhaseOf(
        envelope({ status: 'scanned', ticket: { status: 'scanned', ticketId: 't' } }),
      ),
    ).toBe('scanned');
    expect(
      ticketPhaseOf(
        envelope({ status: 'success', ticket: { status: 'success', ticketId: 't' } }),
      ),
    ).toBe('success');
    expect(
      ticketPhaseOf(
        envelope({ status: 'expired', ticket: { status: 'expired', ticketId: 't' } }),
      ),
    ).toBe('expired');
    expect(
      ticketPhaseOf(
        envelope({
          status: 'target_taken',
          ticket: { status: 'failed', ticketId: 't' },
        }),
      ),
    ).toBe('failed');
  });

  test('ticketPhaseOf：ticket 缺失按顶层 status 兜底；未知顶层保守 failed、未知 ticket.status 继续 pending', () => {
    expect(ticketPhaseOf(envelope({ status: 'pending' }))).toBe('pending');
    expect(ticketPhaseOf(envelope({ status: 'scanned' }))).toBe('scanned');
    expect(ticketPhaseOf(envelope({ status: 'success' }))).toBe('success');
    expect(ticketPhaseOf(envelope({ status: 'expired' }))).toBe('expired');
    expect(ticketPhaseOf(envelope({ status: 'target_taken' }))).toBe('failed');
    expect(ticketPhaseOf(envelope({ status: 'brand_new_status' }))).toBe('failed');
    // 未知 ticket.status（可能是服务端新增中间态）→ pending 继续轮询。
    expect(
      ticketPhaseOf(
        envelope({ status: 'confirming', ticket: { status: 'confirming', ticketId: 't' } }),
      ),
    ).toBe('pending');
  });

  test('pollTimeoutMsOf：undefined / 非正 / 超上限 → 15 + 缓冲 5；正常值 = (s+5)*1000（§2.8 行 714 上限 15）', () => {
    expect(pollTimeoutMsOf(undefined)).toBe(20000);
    expect(pollTimeoutMsOf(0)).toBe(20000);
    expect(pollTimeoutMsOf(-3)).toBe(20000);
    expect(pollTimeoutMsOf(16)).toBe(20000);
    expect(pollTimeoutMsOf(15)).toBe(20000);
    expect(pollTimeoutMsOf(5)).toBe(10000);
    expect(pollTimeoutMsOf(1)).toBe(6000);
  });

  test('qrFailureText：i18n 优先（信封 status → errors.status.*）；未知 status 兜底不透出 message（§1.5 行 202）', () => {
    expect(
      qrFailureText(
        envelope({
          status: 'target_taken',
          ticket: { status: 'failed', ticketId: 't' },
          error: { message: '该账号已被其他账号绑定' },
        }),
      ),
    ).toBe('该手机号/邮箱已被占用');
    expect(
      qrFailureText(
        envelope({ status: 'brand_new', error: { message: '内部细节' } }),
      ),
    ).toBe('操作失败，请稍后重试');
  });

  test('fetchFailureText：ApiError 走位置二（errors.code.*）；其余 unknown 兜底（§1.6 两个位置）', () => {
    expect(
      fetchFailureText(
        new ApiError({
          httpStatus: 429,
          code: 'too_many_requests',
          message: 'slow down',
          requestId: 'r-1',
        }),
      ),
    ).toBe('操作过于频繁，请稍后再试');
    expect(fetchFailureText(new Error('network down'))).toBe(
      '操作失败，请稍后重试',
    );
  });
});

describe('QRCodePanel 控制器（§8.2 行 606：两组 props 注入下四态流转一致）', () => {
  afterEach(() => {
    rs.useRealTimers();
  });

  /** 按序列 resolve 的轮询信封（末尾挂起终止微任务链）。 */
  function sequencedPoll(seq: LoginFlowResponse[]) {
    let calls = 0;
    const tickets: string[] = [];
    const pollUrl = (ticket: string): Promise<LoginFlowResponse> => {
      tickets.push(ticket);
      const index = calls;
      calls += 1;
      if (index < seq.length) {
        return Promise.resolve(seq[index]!);
      }
      return new Promise(() => {});
    };
    return { pollUrl, get calls() { return calls; }, tickets };
  }

  test('登录组 props：fetching → active(pending) → active(scanned) → success；onResult 收到完整信封（.login）', async () => {
    rs.useFakeTimers();
    const phases: QRPanelPhase[] = [];
    const results: LoginFlowResponse[] = [];
    let qrCalls = 0;
    const poll = sequencedPoll([
      envelope({ status: 'pending', ticket: { status: 'pending', ticketId: 'id-1' } }),
      envelope({ status: 'scanned', ticket: { status: 'scanned', ticketId: 'id-1' } }),
      envelope({
        status: 'success',
        ticket: { status: 'success', ticketId: 'id-1' },
        login: envelope({ status: 'success' }),
      }),
    ]);
    const controller = createQRPanelController({
      requestQR: async () => {
        qrCalls += 1;
        return qrcodeResponse(qrCalls);
      },
      pollUrl: poll.pollUrl,
      onResult: (e) => results.push(e),
      onPhase: (p) => phases.push(p),
    });
    controller.refresh();
    await rs.advanceTimersByTimeAsync(0);
    expect(phases).toEqual([
      { kind: 'fetching' },
      { kind: 'active', qrcodeUrl: 'https://cdn.example/q1.jpg', ticketStatus: 'pending' },
      { kind: 'active', qrcodeUrl: 'https://cdn.example/q1.jpg', ticketStatus: 'scanned' },
      { kind: 'success' },
    ]);
    expect(poll.calls).toBe(3); // success 终态后轮询停止，不再发起
    expect(poll.tickets.every((t) => t === 'tk-1')).toBe(true); // ticket_id 全程一致
    expect(results).toHaveLength(1);
    expect(results[0]!.login?.status).toBe('success');
    controller.dispose();
  });

  test('绑定组 props：同一状态序列下流转与登录组一致（success 载荷换成 .bind）', async () => {
    rs.useFakeTimers();
    const phases: QRPanelPhase[] = [];
    const results: LoginFlowResponse[] = [];
    let qrCalls = 0;
    const poll = sequencedPoll([
      envelope({ status: 'pending', ticket: { status: 'pending', ticketId: 'id-1' } }),
      envelope({ status: 'scanned', ticket: { status: 'scanned', ticketId: 'id-1' } }),
      envelope({
        status: 'success',
        ticket: { status: 'success', ticketId: 'id-1' },
        bind: create(BindResultSchema, {
          providerKey: 'wechat_mp_scan',
          displayName: '微信',
        }),
      }),
    ]);
    const controller = createQRPanelController({
      requestQR: async () => {
        qrCalls += 1;
        return qrcodeResponse(qrCalls);
      },
      pollUrl: poll.pollUrl,
      onResult: (e) => results.push(e),
      onPhase: (p) => phases.push(p),
    });
    controller.refresh();
    await rs.advanceTimersByTimeAsync(0);
    expect(phases).toEqual([
      { kind: 'fetching' },
      { kind: 'active', qrcodeUrl: 'https://cdn.example/q1.jpg', ticketStatus: 'pending' },
      { kind: 'active', qrcodeUrl: 'https://cdn.example/q1.jpg', ticketStatus: 'scanned' },
      { kind: 'success' },
    ]);
    expect(results).toHaveLength(1);
    expect(results[0]!.bind?.providerKey).toBe('wechat_mp_scan');
    controller.dispose();
  });

  test('expired → refresh 重拉：requestQR 再次调用（新 captcha 由调用方在 requestQR 内携带，§2.8 行 703）', async () => {
    rs.useFakeTimers();
    const phases: QRPanelPhase[] = [];
    let qrCalls = 0;
    let pollCalls = 0;
    const controller = createQRPanelController({
      requestQR: async () => {
        qrCalls += 1;
        return qrcodeResponse(qrCalls);
      },
      pollUrl: (ticket) => {
        pollCalls += 1;
        expect(ticket).toBe(`tk-${qrCalls}`);
        if (pollCalls === 1) {
          return Promise.resolve(
            envelope({ status: 'expired', ticket: { status: 'expired', ticketId: 'id-1' } }),
          );
        }
        return new Promise(() => {}); // 新码轮询在途
      },
      onResult: () => {},
      onPhase: (p) => phases.push(p),
    });
    controller.refresh();
    await rs.advanceTimersByTimeAsync(0);
    expect(phases).toEqual([
      { kind: 'fetching' },
      { kind: 'active', qrcodeUrl: 'https://cdn.example/q1.jpg', ticketStatus: 'pending' },
      { kind: 'expired' },
    ]);
    expect(qrCalls).toBe(1);
    controller.refresh(); // expired 面板的刷新动作
    await rs.advanceTimersByTimeAsync(0);
    expect(qrCalls).toBe(2); // 新码 = 新 requestQR（captcha 由调用方包装）
    expect(phases[3]).toEqual({ kind: 'fetching' });
    expect(phases[4]).toEqual({
      kind: 'active',
      qrcodeUrl: 'https://cdn.example/q2.jpg',
      ticketStatus: 'pending',
    });
    expect(pollCalls).toBe(2); // 新 ticket 的轮询已发起
    controller.dispose();
  });

  test('failed：按信封顶层 status 出文案（§2.8 行 728-729）', async () => {
    rs.useFakeTimers();
    const phases: QRPanelPhase[] = [];
    const controller = createQRPanelController({
      requestQR: async () => qrcodeResponse(1),
      pollUrl: () =>
        Promise.resolve(
          envelope({
            status: 'target_taken',
            ticket: { status: 'failed', ticketId: 'id-1' },
            error: { message: '该账号已被其他账号绑定' },
          }),
        ),
      onResult: () => {},
      onPhase: (p) => phases.push(p),
    });
    controller.refresh();
    await rs.advanceTimersByTimeAsync(0);
    expect(phases[phases.length - 1]).toEqual({
      kind: 'failed',
      message: '该手机号/邮箱已被占用',
    });
    controller.dispose();
  });

  test('拉码失败 → failed（ApiError 走位置二文案）', async () => {
    rs.useFakeTimers();
    const phases: QRPanelPhase[] = [];
    const controller = createQRPanelController({
      requestQR: () =>
        Promise.reject(
          new ApiError({
            httpStatus: 400,
            code: 'provider_disabled',
            message: 'disabled',
            requestId: 'r-2',
          }),
        ),
      pollUrl: () => new Promise(() => {}),
      onResult: () => {},
      onPhase: (p) => phases.push(p),
    });
    controller.refresh();
    await rs.advanceTimersByTimeAsync(0);
    expect(phases).toEqual([
      { kind: 'fetching' },
      { kind: 'failed', message: '该登录渠道未启用' },
    ]);
    controller.dispose();
  });

  test('dispose：中断在途轮询（abort 通知 + 不再发起，§8.2 行 606「卸载中断轮询」）', async () => {
    rs.useFakeTimers();
    let pollCalls = 0;
    let pollSignal: AbortSignal | undefined;
    let aborted = false;
    const controller = createQRPanelController({
      requestQR: async () => qrcodeResponse(1),
      pollUrl: (_ticket, signal) => {
        pollCalls += 1;
        pollSignal = signal;
        return new Promise(() => {}); // 在途挂起
      },
      onResult: () => {},
      onPhase: () => {},
    });
    controller.refresh();
    await rs.advanceTimersByTimeAsync(0);
    expect(pollCalls).toBe(1);
    pollSignal!.addEventListener('abort', () => {
      aborted = true;
    });
    controller.dispose();
    expect(aborted).toBe(true);
    await rs.advanceTimersByTimeAsync(60000); // 含单次超时到点
    expect(pollCalls).toBe(1); // 不再发起
  });

  test('组件自身不发业务请求：请求只来自注入的 props（SSR 不触发，客户端由 effect 驱动）', () => {
    let qrCalls = 0;
    let pollCalls = 0;
    const markup = renderToStaticMarkup(
      createElement(QRCodePanel, {
        requestQR: () => {
          qrCalls += 1;
          return Promise.resolve(qrcodeResponse(1));
        },
        pollUrl: () => {
          pollCalls += 1;
          return Promise.resolve(envelope({ status: 'pending' }));
        },
        onResult: () => {},
      }),
    );
    expect(markup).toContain('正在获取二维码'); // 初始 fetching（effect 客户端才跑）
    expect(qrCalls).toBe(0);
    expect(pollCalls).toBe(0);
  });
});

describe('QRCodePanelView 渲染（四态 + failed）', () => {
  function renderView(phase: QRPanelPhase): string {
    return renderToStaticMarkup(
      createElement(QRCodePanelView, { phase, onRefresh: () => {} }),
    );
  }

  test('fetching / active(pending / scanned) / success', () => {
    expect(renderView({ kind: 'fetching' })).toContain('正在获取二维码');
    const pending = renderView({
      kind: 'active',
      qrcodeUrl: 'https://cdn.example/q1.jpg',
      ticketStatus: 'pending',
    });
    expect(pending).toContain('src="https://cdn.example/q1.jpg"');
    expect(pending).toContain('alt="扫码二维码"');
    expect(pending).toContain('请使用手机扫码');
    expect(
      renderView({
        kind: 'active',
        qrcodeUrl: 'https://cdn.example/q1.jpg',
        ticketStatus: 'scanned',
      }),
    ).toContain('已扫码，请在手机上确认');
    expect(renderView({ kind: 'success' })).toContain('操作成功');
  });

  test('expired：过期提示 + 刷新按钮（重拉经 onRefresh → requestQR，captcha 由调用方）', () => {
    const markup = renderView({ kind: 'expired' });
    expect(markup).toContain('已过期，请刷新后重试');
    expect(markup).toContain('<button');
    expect(markup).toContain('重试');
  });

  test('failed：role="alert" + 文案，不渲染重试按钮（后续动作归调用方）', () => {
    const markup = renderView({
      kind: 'failed',
      message: '该手机号/邮箱已被占用',
    });
    expect(markup).toContain('role="alert"');
    expect(markup).toContain('该手机号/邮箱已被占用');
    expect(markup).not.toContain('<button');
  });
});

describe('ProviderIcon（§3.3 行 344：渠道图标唯一渲染入口）', () => {
  test('resolveIconMode：icon 非空未失败 → image；空 / undefined / 加载失败 → placeholder', () => {
    expect(resolveIconMode('https://cdn.example/wechat.png', false)).toBe('image');
    expect(resolveIconMode('https://cdn.example/wechat.png', true)).toBe('placeholder');
    expect(resolveIconMode('', false)).toBe('placeholder'); // protojson 零值省略
    expect(resolveIconMode(undefined, false)).toBe('placeholder');
  });

  test('icon 非空 → <img>（onError 转占位的翻转在组件壳，纯函数层已覆盖）', () => {
    const markup = renderToStaticMarkup(
      createElement(ProviderIcon, {
        icon: 'https://cdn.example/wechat.png',
        alt: '微信',
      }),
    );
    expect(markup).toContain('<img');
    expect(markup).toContain('src="https://cdn.example/wechat.png"');
    expect(markup).toContain('alt="微信"');
    expect(markup).not.toContain('<svg'); // 无占位图形
  });

  test('icon 空 → 内联 SVG 占位（工程内无渠道图标资源，不做本地文件回落）', () => {
    const markup = renderToStaticMarkup(
      createElement(ProviderIcon, { alt: '微信' }),
    );
    expect(markup).toContain('<svg');
    expect(markup).not.toContain('<img');
    expect(markup).toContain('aria-label="微信"');
    expect(renderToStaticMarkup(createElement(ProviderIcon, {}))).toContain(
      '渠道图标', // alt 缺省内置文案
    );
  });
});

describe('QrImage 文本二维码自绘（接口文档 §3.5 行 922「前端绘制二维码」）', () => {
  /** account.test.tsx 同款 otpauth 样例（challenge 下发的 qrcodeContent）。 */
  const OTPAUTH =
    'otpauth://totp/Authloft:zhang_san?secret=JBSWY3DPEHPK3PXP&issuer=Authloft';

  test('二维码渲染：有效内容 → SVG（role=img + aria-label + 白底黑点 + 静默区 viewBox）', () => {
    const markup = renderToStaticMarkup(
      createElement(QrImage, { content: OTPAUTH, alt: 'TOTP 绑定二维码' }),
    );
    expect(markup).toContain('<svg');
    expect(markup).toContain('role="img"');
    expect(markup).toContain('aria-label="TOTP 绑定二维码"');
    expect(markup).toContain('fill="#fff"'); // 白底（含静默区）
    expect(markup).toContain('fill="#000"'); // 暗模块单 path
    expect(markup).toContain('shape-rendering="crispEdges"');
  });

  test('组件确实消费 content：不同内容 → 不同码点路径；run-length 前缀确定性', () => {
    const a = buildQrSvg(OTPAUTH)!;
    const b = buildQrSvg(
      'otpauth://totp/Authloft:li_si?secret=JBSWY3DPEHPK3PXP%20A&issuer=Authloft',
    )!;
    expect(a.modules).toBeGreaterThanOrEqual(21); // 最小版本 1 = 21 模块
    expect(b.modules).toBeGreaterThanOrEqual(21);
    expect(a.path).not.toBe(b.path);
    // 左上定位图案恒定：首行首段 = 7 个连续暗模块（run-length 编码）。
    expect(a.path.startsWith('M0 0h7v1h-7z')).toBe(true);
    // viewBox 含四周静默区（-4 起点）。
    const markup = renderToStaticMarkup(
      createElement(QrImage, { content: OTPAUTH, alt: 'qr' }),
    );
    expect(markup).toContain(`viewBox="-4 -4 ${a.modules + 8} ${a.modules + 8}"`);
  });

  test('加载失败回退：空串 / 超容量 → 组件渲染为空（调用方文本兜底——TotpBindDialog 密钥 / otpauth 文本展示保留，不随码图失败消失）', () => {
    // 空串：protojson 零值省略语境（§9.18 调用方回退同源 otpauthUrl 后仍可能空）。
    expect(buildQrSvg('')).toBeUndefined();
    expect(
      renderToStaticMarkup(createElement(QrImage, { content: '', alt: 'qr' })),
    ).toBe('');
    // 超容量：QR 40 版 M 级 Byte 模式上限约 2331 字节，4000 字节必失败。
    const oversized = 'x'.repeat(4000);
    expect(buildQrSvg(oversized)).toBeUndefined();
    expect(
      renderToStaticMarkup(
        createElement(QrImage, { content: oversized, alt: 'qr' }),
      ),
    ).toBe('');
  });
});

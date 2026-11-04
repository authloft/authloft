// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化后移除）。
// @ts-ignore
import { beforeEach, describe, expect, rs, test } from 'rstack/test';
import * as React from 'react';
// 本仓 rstest 为 node 环境（无 DOM）：静态渲染走 react-dom/server 的
// renderToStaticMarkup（沿 login-container.test.ts / components.test.ts 惯例）。
import { renderToStaticMarkup } from 'react-dom/server';
import { create } from '@bufbuild/protobuf';
import {
  FieldSchema,
  NextStepSchema,
} from '../../gen/proto/api/sso/v1/envelope_pb';
import { FormStep } from './FormStep';
import { StepDispatcher, STEP_FALLBACK_TEXT } from './StepDispatcher';

const { createElement } = React;

/** kind=form 段的内容（FormStep 空字段 + 提交按钮，可辨识）。 */
function formNode(): React.ReactNode {
  return createElement(FormStep, {
    fields: [],
    loading: false,
    disabled: false,
    onSubmit: () => {},
  });
}

function renderDispatch(kind: string): string {
  return renderToStaticMarkup(
    createElement(StepDispatcher, {
      nextStep: create(NextStepSchema, { kind, method: 'totp' }),
      form: formNode(),
    }),
  );
}

beforeEach(() => {
  // rstest 对 .tsx 走 classic JSX runtime：渲染前 stub 全局 React（仅测试进程）。
  rs.stubGlobal('React', React);
});

describe('StepDispatcher kind 分派（§4.2 行 423；§1.4 行 169-176 六种）', () => {
  test('kind=form → 渲染注入的 form 段（容器构造：FormStep / 因子 verify 段）', () => {
    const markup = renderDispatch('form');
    expect(markup).toContain('<form');
    expect(markup).toContain('登录');
    expect(markup).not.toContain(STEP_FALLBACK_TEXT);
  });

  test('kind=challenge：未实现（ChallengeStep 归后续实现）→ 兜底，不渲染表单', () => {
    expect(renderDispatch('challenge')).toContain(STEP_FALLBACK_TEXT);
  });

  test('kind=redirect / qrcode / poll：未实现（实体组件归后续实现）→ 兜底', () => {
    expect(renderDispatch('redirect')).toContain(STEP_FALLBACK_TEXT);
    expect(renderDispatch('qrcode')).toContain(STEP_FALLBACK_TEXT);
    expect(renderDispatch('poll')).toContain(STEP_FALLBACK_TEXT);
  });

  test('kind=external：宿主承载（§9 第 10 条，login/ 不实现）→ 兜底', () => {
    expect(renderDispatch('external')).toContain(STEP_FALLBACK_TEXT);
  });

  test('未识别 kind → 兜底（§4.2 行 423「未识别 kind 走兜底」）', () => {
    expect(renderDispatch('teleport')).toContain(STEP_FALLBACK_TEXT);
    expect(renderDispatch('')).toContain(STEP_FALLBACK_TEXT);
  });
});

describe('FormStep（kind=form 通用渲染，§4.2 行 424；totp 渲染落点 §4.3 行 434）', () => {
  const totpFields = [
    create(FieldSchema, {
      name: 'code',
      label: '动态口令',
      type: 'totp',
      required: true,
      length: BigInt(6),
    }),
  ];

  function renderForm(props?: { loading?: boolean; disabled?: boolean }): string {
    return renderToStaticMarkup(
      createElement(FormStep, {
        fields: totpFields,
        loading: props?.loading ?? false,
        disabled: props?.disabled ?? false,
        onSubmit: () => {},
      }),
    );
  }

  test('fields[] → FieldRenderer：totp 字段分段输入（CodeInput，one-time-code 由 shared 承担）+ 提交按钮', () => {
    const markup = renderForm();
    expect(markup).toContain('<form');
    expect(markup).toContain('动态口令');
    // §1.11 行 331：totp 与 otp 同渲染逻辑（CodeInput 分段 + one-time-code）。
    // react-dom/server 静态输出保留 camelCase 属性名（autoComplete）。
    expect(markup).toContain('autoComplete="one-time-code"');
    expect(markup).toContain('登录');
  });

  test('loading / disabled 禁用提交（§3.2）', () => {
    expect(renderForm({ loading: true })).toContain('disabled=""');
    expect(renderForm({ disabled: true })).toContain('disabled=""');
    expect(renderForm()).not.toContain('disabled=""');
  });

  test('空 fields → 空表单（不产生字段控件，§1.11 零值兜底）', () => {
    const markup = renderToStaticMarkup(
      createElement(FormStep, {
        fields: [],
        loading: false,
        disabled: false,
        onSubmit: () => {},
      }),
    );
    expect(markup).toContain('<form');
    expect(markup).not.toContain('<label');
  });
});

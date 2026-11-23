// 本仓 rstest 为 node 环境（无 DOM）：交互边界走纯函数与直接调用无 hook
// 组件的事件 prop；渲染断言用 react-dom/server（零新依赖）。
// @ts-ignore
import { describe, expect, test } from 'rstack/test';
import * as React from 'react';
import type { ReactElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import {
  PhoneInput,
  splitE164,
  normalizeNational,
  joinE164,
  onNationalChange,
  DIAL_CODES,
  DEFAULT_DIAL_CODE,
  MAX_NATIONAL_DIGITS,
} from './PhoneInput';

describe('shared/components/PhoneInput E.164 拆分与拼装', () => {
  test('已知区号前缀匹配：取可匹配的最长区号', () => {
    expect(splitE164('+8613800138000')).toEqual({
      dialCode: '+86',
      national: '13800138000',
    });
    expect(splitE164('+85291234567')).toEqual({
      dialCode: '+852',
      national: '91234567',
    });
    expect(splitE164('+12025550100')).toEqual({
      dialCode: '+1',
      national: '2025550100',
    });
    expect(DIAL_CODES.some((entry) => entry.dialCode === '+886')).toBe(true);
  });

  test('空值 / 未知区号 / 裸号回退默认区号，整串当本地号', () => {
    expect(splitE164('')).toEqual({
      dialCode: DEFAULT_DIAL_CODE,
      national: '',
    });
    expect(DEFAULT_DIAL_CODE).toBe('+86');
    expect(splitE164('+999123456')).toEqual({
      dialCode: '+86',
      national: '+999123456',
    });
    expect(splitE164('13800138000')).toEqual({
      dialCode: '+86',
      national: '13800138000',
    });
  });

  test('本地号归一剔空白与非数字；拼装区号 + 数字', () => {
    expect(normalizeNational('138 0013-8000')).toBe('13800138000');
    expect(normalizeNational('abc12+3')).toBe('123');
    expect(joinE164('+86', '138 0013 8000')).toBe('+8613800138000');
    expect(joinE164('+852', '9123 4567')).toBe('+85291234567');
  });

  test('未知区号值编辑保留原前缀，不静默改写成默认 +86', () => {
    const unknown = splitE164('+85512345678');
    expect(unknown).toEqual({
      dialCode: DEFAULT_DIAL_CODE,
      national: '+85512345678',
    });
    // 编辑本地号框：原区号 +855 保留，仅规整数字。
    expect(onNationalChange('+86', unknown.national, '+855 1234 567')).toBe(
      '+8551234567',
    );
    // 已知区号仍走正常拼装路径。
    expect(onNationalChange('+86', '13800138000', '139 0000 0000')).toBe(
      '+8613900000000',
    );
    // 空号清空仍上抛空串。
    expect(onNationalChange('+86', unknown.national, '')).toBe('');
  });
});

describe('shared/components/PhoneInput 渲染与事件输出', () => {
  test('两段控件与无障碍属性就位', () => {
    const html = renderToStaticMarkup(
      <PhoneInput
        id="bind-phone-target"
        value="+8613800138000"
        onChange={() => {}}
        ariaLabel="区号"
        ariaInvalid
        ariaDescribedBy="bind-error"
      />,
    );
    expect(html).toContain('<select');
    expect(html).toContain('aria-label="区号"');
    expect(html).toContain('中国香港');
    expect(html).toContain('中国澳门');
    expect(html).toContain('中国台湾');
    expect(html).toContain('id="bind-phone-target"');
    expect(html).toContain('id="bind-phone-target-dial-code"');
    expect(html).toContain('value="13800138000"');
    expect(html).toContain('aria-invalid="true"');
    expect(html).toContain('aria-describedby="bind-error"');
    expect(html).toContain(`maxLength="${MAX_NATIONAL_DIGITS}"`);
  });

  test('未知区号存量的本地号框编辑保留原前缀', () => {
    const outputs: string[] = [];
    const tree = PhoneInput({
      value: '+85512345678',
      onChange: (v) => outputs.push(v),
    });
    const [, input] = tree.props.children as ReactElement[];
    // @ts-ignore 事件桩只需 target.value。
    input.props.onChange({ target: { value: '+855 1234 5678' } });
    expect(outputs).toEqual(['+85512345678']);
  });

  test('选区号 / 输本地号都输出 E.164（直接触发受控事件 prop）', () => {
    const outputs: string[] = [];
    const tree = PhoneInput({ value: '', onChange: (v) => outputs.push(v) });
    const [select, input] = tree.props.children as ReactElement[];
    // @ts-ignore 事件桩只需 target.value。
    select.props.onChange({ target: { value: '+852' } });
    // @ts-ignore 事件桩只需 target.value。
    input.props.onChange({ target: { value: '9123 4567' } });
    // 空号阶段切区号不构成合法号码 → 上抛空串；随后输入号码才拼 E.164。
    expect(outputs).toEqual(['', '+8691234567']);
  });

  test('空号不输出裸区号：清空本地号 / 仅切区号均输出空串', () => {
    // 展示口径不变：空值仍回退默认区号 +86 供下拉选中。
    expect(splitE164('')).toEqual({
      dialCode: DEFAULT_DIAL_CODE,
      national: '',
    });
    expect(joinE164('+86', '')).toBe('');
    expect(joinE164('+86', '   ')).toBe('');
    expect(joinE164('+852', 'abc')).toBe('');

    const cleared: string[] = [];
    const filled = PhoneInput({
      value: '+8613800138000',
      onChange: (v) => cleared.push(v),
    });
    const [, filledInput] = filled.props.children as ReactElement[];
    // @ts-ignore 事件桩只需 target.value。
    filledInput.props.onChange({ target: { value: '' } });
    expect(cleared).toEqual(['']);

    const switched: string[] = [];
    const blank = PhoneInput({ value: '', onChange: (v) => switched.push(v) });
    const [blankSelect] = blank.props.children as ReactElement[];
    // @ts-ignore 事件桩只需 target.value。
    blankSelect.props.onChange({ target: { value: '+1' } });
    expect(switched).toEqual(['']);
  });
});

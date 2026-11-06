// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化后移除）。
// @ts-ignore
import { describe, expect, test } from 'rstack/test';
import {
  codeErrorText,
  focusField,
  RETRY_RESUBMIT_STATUSES,
  validateFormValues,
} from './validate';

// 评审 P0-2 / P1-4：login 域前置校验组装的纯函数覆盖（组件交互在
// node 静态渲染边界外，提交前校验链路经本层 + FieldRenderer 错误槽落地）。

describe('validateFormValues（P0-2：required → email/phone 格式 → 验证码满格）', () => {
  const fields = [
    { name: 'phone', type: 'phone', required: true },
    { name: 'email', type: 'email', required: false },
  ];

  test('必填空值 → required 文案 + 首错字段定位', () => {
    const result = validateFormValues(fields, { phone: '  ' });
    expect(result.errors).toEqual({ phone: '请填写此项' });
    expect(result.firstField).toBe('phone');
  });

  test('email / phone 格式未过 → 对应文案；非必填空值放行（服务端权威）', () => {
    expect(
      validateFormValues(fields, { phone: '123', email: 'not-an-email' }).errors,
    ).toEqual({ phone: '手机号格式不正确', email: '邮箱格式不正确' });
    // 非必填空值放行。
    expect(
      validateFormValues(fields, { phone: '13800000000', email: '' }).firstField,
    ).toBeUndefined();
  });

  test('otp / totp 满格校验（length 归一：缺省 / bigint 均按位数值）', () => {
    const codeFields = [{ name: 'code', type: 'totp', required: true, length: BigInt(6) }];
    expect(validateFormValues(codeFields, { code: '123' }).errors).toEqual({
      code: '请输入完整验证码',
    });
    expect(
      validateFormValues(codeFields, { code: '123456' }).firstField,
    ).toBeUndefined();
  });

  test('全过 → errors 空、firstField undefined', () => {
    const result = validateFormValues(fields, {
      phone: '13800000000',
      email: 'a@b.com',
    });
    expect(result.errors).toEqual({});
    expect(result.firstField).toBeUndefined();
  });
});

describe('codeErrorText（P0-2：verify 段 6 格未输满不提交）', () => {
  test('未满格 / 非数字 → 错误文案；满格纯数字 → undefined', () => {
    expect(codeErrorText('', 6)).toBe('请输入完整验证码');
    expect(codeErrorText('12345', 6)).toBe('请输入完整验证码');
    expect(codeErrorText('12345a', 6)).toBe('请输入完整验证码');
    expect(codeErrorText('123456', 6)).toBeUndefined();
  });
});

describe('RETRY_RESUBMIT_STATUSES（P1-4：onRetry 白名单）', () => {
  test('captcha_invalid / internal_error 在列；同值必败态不在列', () => {
    expect(RETRY_RESUBMIT_STATUSES.has('captcha_invalid')).toBe(true);
    expect(RETRY_RESUBMIT_STATUSES.has('internal_error')).toBe(true);
    expect(RETRY_RESUBMIT_STATUSES.has('invalid_code')).toBe(false);
    expect(RETRY_RESUBMIT_STATUSES.has('invalid_credentials')).toBe(false);
  });
});

describe('focusField（P0-2 首错字段聚焦；node 无 DOM 静默跳过）', () => {
  test('document 缺失环境调用不炸', () => {
    expect(() => focusField('fr-phone')).not.toThrow();
  });
});

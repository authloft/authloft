// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径；
// 本次不改 tsconfig，故仅在测试文件放宽该 import 的类型解析（既定口径）。
// @ts-ignore
import { describe, expect, test } from 'rstack/test';
import {
  DEFAULT_PASSWORD_POLICY,
  FIELD_ISSUE_I18N_KEY,
  firstInvalidField,
  isCodeComplete,
  isFilled,
  isValidEmail,
  isValidPhone,
  isValidProviderKey,
  isValidUsername,
  PROVIDER_KEY_PATTERN,
  USERNAME_PATTERN,
  validateFields,
  validatePassword,
  type PasswordWeakReason,
  type ValidatableField,
} from './validate';
import { maskEmail, maskPhone } from './mask';
import { toCount, toDisplay } from './int';

describe('utils/validate 用户名（接口文档 §2.3 行 449 唯一定义）', () => {
  test('模式口径：^[A-Za-z0-9_]{5,20}$', () => {
    expect(USERNAME_PATTERN.source).toBe('^[A-Za-z0-9_]{5,20}$');
  });

  test('5 / 20 位边界通过，字母数字下划线均可', () => {
    expect(isValidUsername('abc_1')).toBe(true);
    expect(isValidUsername('a'.repeat(20))).toBe(true);
    expect(isValidUsername('A9_'.repeat(2) + 'z')).toBe(true); // 7 位
  });

  test('4 / 21 位及非法字符拒绝；空串拒绝', () => {
    expect(isValidUsername('abcd')).toBe(false);
    expect(isValidUsername('a'.repeat(21))).toBe(false);
    expect(isValidUsername('ab-cd')).toBe(false);
    expect(isValidUsername('用户名abc')).toBe(false);
    expect(isValidUsername('')).toBe(false);
  });
});

describe('utils/validate provider_key（前端架构 §3.4：^[a-z0-9_]+$）', () => {
  test('小写字母数字下划线通过', () => {
    expect(isValidProviderKey('cf_turnstile')).toBe(true);
    expect(isValidProviderKey('sms01')).toBe(true);
    expect(isValidProviderKey('_')).toBe(true);
    expect(PROVIDER_KEY_PATTERN.test('builtin_image')).toBe(true);
  });

  test('大写 / 连字符 / 空串拒绝', () => {
    expect(isValidProviderKey('Turnstile')).toBe(false);
    expect(isValidProviderKey('cf-turnstile')).toBe(false);
    expect(isValidProviderKey('')).toBe(false);
  });
});

describe('utils/validate 手机号 / 邮箱（§1.11：体验性预校验，后端权威）', () => {
  test('大陆 11 位手机号通过；位数不对 / 号段不对 / 空串拒绝', () => {
    expect(isValidPhone('13800138000')).toBe(true);
    expect(isValidPhone('19912345678')).toBe(true);
    expect(isValidPhone('1380013800')).toBe(false); // 10 位
    expect(isValidPhone('138001380001')).toBe(false); // 12 位
    expect(isValidPhone('12800138000')).toBe(false); // 12 开头
    expect(isValidPhone('')).toBe(false);
  });

  test('常规邮箱通过；缺 @ / 缺点 / 含空白 / 空串拒绝', () => {
    expect(isValidEmail('user@example.com')).toBe(true);
    expect(isValidEmail('a@b.co')).toBe(true);
    expect(isValidEmail('user.example.com')).toBe(false);
    expect(isValidEmail('user@example')).toBe(false);
    expect(isValidEmail('a b@example.com')).toBe(false);
    expect(isValidEmail('')).toBe(false);
  });
});

describe('utils/validate 前置校验（评审 P0-2；服务端权威）', () => {
  test('isFilled：去空白非空；空串 / 纯空白拒绝', () => {
    expect(isFilled('a')).toBe(true);
    expect(isFilled(' a ')).toBe(true);
    expect(isFilled('')).toBe(false);
    expect(isFilled('   ')).toBe(false);
  });

  test('isCodeComplete：满格纯数字通过；短 / 长 / 含非数字 / 空串拒绝', () => {
    expect(isCodeComplete('123456')).toBe(true);
    expect(isCodeComplete('12345')).toBe(false);
    expect(isCodeComplete('1234567')).toBe(false);
    expect(isCodeComplete('12345a')).toBe(false);
    expect(isCodeComplete('')).toBe(false);
    // 自定义长度（totp 8 位场景）。
    expect(isCodeComplete('12345678', 8)).toBe(true);
    expect(isCodeComplete('123456', 8)).toBe(false);
  });

  const FORM: readonly ValidatableField[] = [
    { name: 'username', type: 'text', required: true },
    { name: 'email', type: 'email', required: true },
    { name: 'phone', type: 'phone' },
    { name: 'code', type: 'otp', required: true, length: BigInt(6) },
    { name: 'captcha', type: 'captcha' },
  ];

  test('validateFields：全过返回空对象；captcha 不参与', () => {
    expect(
      validateFields(FORM, {
        username: 'alice',
        email: 'a@b.co',
        code: '123456',
      }),
    ).toEqual({});
  });

  test('validateFields：required 空值 / email 格式 / phone 格式 / 验证码未满格逐项命中', () => {
    const issues = validateFields(FORM, {
      username: '  ',
      email: 'not-an-email',
      phone: '12345',
      code: '123',
    });
    expect(issues).toEqual({
      username: 'required',
      email: 'invalid_email',
      phone: 'invalid_phone',
      code: 'code_incomplete',
    });
  });

  test('validateFields：非必填空值放行；required 优先于格式校验', () => {
    expect(validateFields(FORM, { username: 'u', email: 'a@b.co', code: '123456' })).toEqual({});
    expect(validateFields([{ name: 'e', type: 'email', required: true }], {})).toEqual({
      e: 'required',
    });
    // 验证码长度取字段 length（bigint 归一）；缺省 / 零值 → 默认 6。
    expect(
      validateFields([{ name: 'c', type: 'totp', required: true, length: 8 }], {
        c: '12345678',
      }),
    ).toEqual({});
    expect(
      validateFields([{ name: 'c', type: 'totp', required: true, length: 8 }], {
        c: '123456',
      }),
    ).toEqual({ c: 'code_incomplete' });
    expect(
      validateFields([{ name: 'c', type: 'otp', required: true, length: BigInt(0) }], {
        c: '123456',
      }),
    ).toEqual({});
  });

  test('firstInvalidField：按字段顺序取首错；全过 → undefined', () => {
    const issues = validateFields(FORM, { email: 'bad', code: '1' });
    expect(firstInvalidField(FORM, issues)).toBe('username');
    expect(firstInvalidField(FORM, { code: 'code_incomplete' })).toBe('code');
    expect(firstInvalidField(FORM, {})).toBeUndefined();
  });

  test('FIELD_ISSUE_I18N_KEY：四种原因全覆盖且键在字典存在', () => {
    expect(Object.keys(FIELD_ISSUE_I18N_KEY).sort()).toEqual(
      ['code_incomplete', 'invalid_email', 'invalid_phone', 'required'].sort(),
    );
    // 键存在性由 i18n 测试（字典键集对齐）与组件层消费共同保证。
    for (const key of Object.values(FIELD_ISSUE_I18N_KEY)) {
      expect(key).toMatch(/^common\.err/);
    }
  });
});

describe('utils/validate 密码强度（接口文档 §5.6 策略与默认值）', () => {
  test('默认策略口径：8 / 64 / 3 类 / disallowUsername', () => {
    expect(DEFAULT_PASSWORD_POLICY).toEqual({
      minLength: 8,
      maxLength: 64,
      requireClasses: 3,
      disallowUsername: true,
    });
  });

  test('默认策略通过：8 位且大写/小写/数字三类齐', () => {
    expect(validatePassword('Aa1aaaaa')).toEqual<PasswordWeakReason[]>([]);
  });

  test('too_short：不足最小长度（含空密码）', () => {
    expect(validatePassword('Aa1aaa')).toEqual<PasswordWeakReason[]>(['too_short']);
    expect(validatePassword('')).toEqual<PasswordWeakReason[]>([
      'too_short',
      'too_few_classes',
    ]);
  });

  test('too_long：> 64 一律拒绝（固定项）；恰 64 通过', () => {
    expect(validatePassword(`Aa1${'a'.repeat(61)}`)).toEqual<PasswordWeakReason[]>([]);
    expect(validatePassword(`Aa1${'a'.repeat(62)}`)).toEqual<PasswordWeakReason[]>([
      'too_long',
    ]);
  });

  test('pwd_max_length 可调低不可调高：>policy 且 >64 与 >policy（≤64）均拒绝', () => {
    expect(
      validatePassword('Aa1aaaaaaa', { policy: { maxLength: 10 } }),
    ).toEqual<PasswordWeakReason[]>([]);
    expect(
      validatePassword('Aa1aaaaaaaa', { policy: { maxLength: 10 } }),
    ).toEqual<PasswordWeakReason[]>(['too_long']);
    // 策略给 100 也不越过服务端硬上限 64（§5.6 固定项）。
    expect(
      validatePassword(`Aa1${'a'.repeat(67)}`, { policy: { maxLength: 100 } }),
    ).toEqual<PasswordWeakReason[]>(['too_long']);
  });

  test('too_few_classes：类数不足（符号不计入字符类）', () => {
    expect(validatePassword('aaaaaaaa')).toEqual<PasswordWeakReason[]>([
      'too_few_classes',
    ]);
    expect(validatePassword('Aaaaaaa!')).toEqual<PasswordWeakReason[]>([
      'too_few_classes',
    ]); // 大写+小写=2 类，! 不计入
  });

  test('contains_whitespace：固定项，含空白一律拒绝', () => {
    expect(validatePassword('Aa1 aaaa')).toEqual<PasswordWeakReason[]>([
      'contains_whitespace',
    ]);
  });

  test('pwd_disallow_username（默认 true）：包含用户名拒绝；关闭后放行', () => {
    expect(validatePassword('userAa12', { username: 'user' })).toContain(
      'contains_username',
    );
    expect(
      validatePassword('userAa12', {
        username: 'user',
        policy: { disallowUsername: false },
      }),
    ).toEqual<PasswordWeakReason[]>([]);
  });

  test('固定项：与用户名 / 邮箱完全相同拒绝（same_as_identifier）', () => {
    expect(
      validatePassword('userAa12', { username: 'userAa12' }),
    ).toEqual<PasswordWeakReason[]>(['contains_username', 'same_as_identifier']);
    expect(
      validatePassword('Aa1aaaaa', { email: 'Aa1aaaaa' }),
    ).toEqual<PasswordWeakReason[]>(['same_as_identifier']);
    // 仅包含邮箱（非完全相同）不触发固定项，也不受 pwd_disallow_username 管。
    expect(
      validatePassword('Aa1aaaaa', { email: 'Aa1aaaaa@x.co' }),
    ).toEqual<PasswordWeakReason[]>([]);
  });

  test('pwd_min_length / pwd_require_classes 可按设置覆盖', () => {
    expect(
      validatePassword('Aa1aaa', { policy: { minLength: 6 } }),
    ).toEqual<PasswordWeakReason[]>([]);
    expect(
      validatePassword('aaaaaaaa', { policy: { requireClasses: 1 } }),
    ).toEqual<PasswordWeakReason[]>([]);
  });
});

describe('utils/mask 掩码（前端架构 §3.4；仅本地体验性展示）', () => {
  test('maskPhone：前 3 后 4 明文、总长不变（138****5678 口径）', () => {
    expect(maskPhone('13812345678')).toBe('138****5678');
    expect(maskPhone('12345678')).toBe('123*5678');
  });

  test('maskPhone：不足 8 位整体掩码；空串原样', () => {
    expect(maskPhone('13800')).toBe('*****');
    expect(maskPhone('1234567')).toBe('*******');
    expect(maskPhone('')).toBe('');
  });

  test('maskEmail：本地部分保留首字符 + ***，域名整体保留', () => {
    expect(maskEmail('user@example.com')).toBe('u***@example.com');
    expect(maskEmail('a@b.co')).toBe('a***@b.co');
  });

  test('maskEmail：无 @ / 本地部分为空 → 整体掩码；空串原样', () => {
    expect(maskEmail('no-at-mail')).toBe('**********');
    expect(maskEmail('@example.com')).toBe('*'.repeat(12));
    expect(maskEmail('')).toBe('');
  });
});

describe('utils/int（§1.12 int64 进出 UI 唯一转换点）', () => {
  test('toDisplay：bigint 十进制化；字符串归一（去空白 / 前导零）；空串原样', () => {
    expect(toDisplay(BigInt(60))).toBe('60');
    expect(toDisplay(BigInt(-7))).toBe('-7');
    expect(toDisplay('60')).toBe('60');
    expect(toDisplay(' 42 ')).toBe('42');
    expect(toDisplay('007')).toBe('7');
    expect(toDisplay('+9')).toBe('9');
    expect(toDisplay('')).toBe('');
  });

  test('toDisplay：非法十进制串抛 SyntaxError（fail fast）', () => {
    expect(() => toDisplay('abc')).toThrow(SyntaxError);
    expect(() => toDisplay('1.5')).toThrow(SyntaxError);
  });

  test('toCount：安全整数原样返回（含 0 与负数）', () => {
    expect(toCount(BigInt(60))).toBe(60);
    expect(toCount(BigInt(0))).toBe(0);
    expect(toCount(BigInt(-5))).toBe(-5);
    expect(toCount(BigInt(Number.MAX_SAFE_INTEGER))).toBe(
      Number.MAX_SAFE_INTEGER,
    );
  });

  test('toCount：超 ±Number.MAX_SAFE_INTEGER 抛 RangeError（MAX_SAFE_INTEGER 断言）', () => {
    expect(() => toCount(BigInt(Number.MAX_SAFE_INTEGER) + BigInt(1))).toThrow(
      RangeError,
    );
    expect(() =>
      toCount(BigInt(-Number.MAX_SAFE_INTEGER) - BigInt(1)),
    ).toThrow(RangeError);
  });
});

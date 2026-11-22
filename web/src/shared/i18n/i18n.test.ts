// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化落地后移除）。
// @ts-ignore
import { afterEach, describe, expect, test } from 'rstack/test';
import { zhCN } from './zh-CN';
import { enUS } from './en-US';
import {
  getLocale,
  hasKey,
  initLocale,
  interpolate,
  normalizeLocale,
  setLocale,
  t,
} from './index';
import { CODE_TABLE, FLOW_STATUS_TABLE } from '../api/errors';

// 本文件会切换模块级语言状态：每条用例后复位默认 zh-CN。
afterEach(() => {
  setLocale('zh-CN');
});

describe('i18n 键集全量对齐（缺译不许静默回退）', () => {
  test('zh / en 两套字典键集完全一致', () => {
    expect(Object.keys(enUS).sort()).toEqual(Object.keys(zhCN).sort());
  });

  test('两套字典每个键都是非空字符串', () => {
    for (const value of Object.values(zhCN)) {
      expect(typeof value).toBe('string');
      expect(value.length).toBeGreaterThan(0);
    }
    for (const value of Object.values(enUS)) {
      expect(typeof value).toBe('string');
      expect(value.length).toBeGreaterThan(0);
    }
  });
});

describe('语言选择（zh-CN 默认；setLocale 会话内持久化）', () => {
  test('默认 zh-CN', () => {
    expect(getLocale()).toBe('zh-CN');
  });

  test('normalizeLocale：en 前缀 → en-US；其余归 zh-CN', () => {
    expect(normalizeLocale('en-US')).toBe('en-US');
    expect(normalizeLocale('en')).toBe('en-US');
    expect(normalizeLocale('EN_gb')).toBe('en-US');
    expect(normalizeLocale('zh-CN')).toBe('zh-CN');
    expect(normalizeLocale('zh-TW')).toBe('zh-CN');
    expect(normalizeLocale('fr')).toBe('zh-CN');
    expect(normalizeLocale('')).toBe('zh-CN');
  });

  test('setLocale 切换生效且可复位', () => {
    setLocale('en-US');
    expect(getLocale()).toBe('en-US');
    expect(t('factors.totp')).toBe('Authenticator code');
    setLocale('zh-CN');
    expect(getLocale()).toBe('zh-CN');
    expect(t('factors.totp')).toBe('动态口令');
  });

  /** sessionStorage 假件（al_locale 读写）；缺 window 时代码路径静默降级。 */
  function stubWindowStorage(initial?: [string, string]): Map<string, string> {
    const store = new Map<string, string>(initial ? [initial] : []);
    (globalThis as Record<string, unknown>).window = {
      sessionStorage: {
        getItem: (k: string) => store.get(k) ?? null,
        setItem: (k: string, v: string) => store.set(k, v),
      },
    };
    return store;
  }

  function unstubWindow() {
    delete (globalThis as { window?: unknown }).window;
    setLocale('zh-CN');
  }

  test('setLocale 持久化到 sessionStorage（键 al_locale）', () => {
    const store = stubWindowStorage();
    try {
      setLocale('en-US');
      expect(store.get('al_locale')).toBe('en-US');
    } finally {
      unstubWindow();
    }
  });

  test('initLocale：会话内持久化值优先，缺省回落 fallback（浏览器语言归一）', () => {
    const store = stubWindowStorage(['al_locale', 'en-US']);
    try {
      initLocale('zh-CN');
      expect(getLocale()).toBe('en-US'); // 持久化值优先于浏览器语言
      store.delete('al_locale');
      initLocale('en');
      expect(getLocale()).toBe('en-US'); // 无持久化值 → fallback 归一
      store.set('al_locale', 'zh-CN');
      initLocale('en-US');
      expect(getLocale()).toBe('zh-CN');
    } finally {
      unstubWindow();
    }
  });
});

describe('t() 取文案', () => {
  test('默认语言取中文文案', () => {
    expect(t('factors.password')).toBe('密码登录');
    expect(t('channels.sms')).toBe('短信');
  });

  test('缺键：回显键本身，绝不 undefined（缺译可见可排查）', () => {
    expect(t('no.such.key')).toBe('no.such.key');
    setLocale('en-US');
    expect(t('no.such.key')).toBe('no.such.key');
  });

  test('hasKey：已知键 true / 未知键 false', () => {
    expect(hasKey('errors.status.locked')).toBe(true);
    expect(hasKey('errors.code.internal')).toBe(true);
    expect(hasKey('no.such.key')).toBe(false);
  });

  test('插值：{name} 命中替换、未命中保留占位', () => {
    expect(t('common.remainingSeconds', { seconds: 60 })).toBe('剩余 60 秒');
    expect(interpolate('{seconds} seconds remaining', { seconds: 90 })).toBe(
      '90 seconds remaining',
    );
    expect(interpolate('剩余 {seconds} 秒', {})).toBe('剩余 {seconds} 秒');
    expect(interpolate('剩余 {a} {b} 秒', { a: 1 })).toBe('剩余 1 {b} 秒');
  });
});

describe('schema 字段文案契约（后端下发 i18n 键，文案只在本字典）', () => {
  const schemaKeys = Object.keys(zhCN).filter(
    (key) =>
      key.startsWith('admin.schemaField.') ||
      key.startsWith('admin.schemaOption.'),
  );

  test('全部 schema 字段 / option 键在 zh / en 两套字典都可译（不回显键）', () => {
    expect(schemaKeys.length).toBeGreaterThan(0);
    for (const key of schemaKeys) {
      expect(t(key)).not.toBe(key);
      setLocale('en-US');
      expect(t(key)).not.toBe(key);
      setLocale('zh-CN');
    }
  });

  test('option 显示名按字段命名空间取键，未定义取值原样回显', () => {
    expect(t('admin.schemaOption.scheme.socks5')).toBe('SOCKS5');
    setLocale('en-US');
    expect(t('admin.schemaOption.scheme.socks5')).toBe('SOCKS5');
    setLocale('zh-CN');
    // union_provider 的 options 是自定义 provider_key；即便值恰好叫 socks5，
    // 也不会命中 scheme 的枚举译文。
    expect(hasKey('admin.schemaOption.union_provider.socks5')).toBe(false);
  });

  test('兼容路径：旧版中文字面量 / 缺译键一律回显本身（不静默 undefined）', () => {
    expect(t('唯一标识')).toBe('唯一标识');
    expect(t('admin.schemaField.notYetTranslated')).toBe(
      'admin.schemaField.notYetTranslated',
    );
  });
});

describe('登录字段文案契约（后端下发 login.field.* 键）', () => {
  const loginFieldKeys = Object.keys(zhCN).filter((key) =>
    key.startsWith('login.field.'),
  );

  test('全部登录字段键在 zh / en 两套字典都可译（不回显键）', () => {
    expect(loginFieldKeys.length).toBeGreaterThan(0);
    for (const key of loginFieldKeys) {
      expect(t(key)).not.toBe(key);
      setLocale('en-US');
      expect(t(key)).not.toBe(key);
      setLocale('zh-CN');
    }
  });

  test('zh 译文与迁移前逐字一致（避免既有渲染断言 / UI 文案漂移）', () => {
    expect(t('login.field.usernameOrIdentifier')).toBe('用户名/邮箱/手机号');
    expect(t('login.field.password')).toBe('密码');
    expect(t('login.field.captcha')).toBe('人机校验');
    expect(t('login.field.otpCode')).toBe('验证码');
    expect(t('login.field.recoveryCode')).toBe('恢复码');
    expect(t('login.field.totpCode')).toBe('动态口令');
    expect(t('login.field.phone')).toBe('手机号');
    expect(t('login.field.email')).toBe('邮箱');
    expect(t('login.field.username')).toBe('用户名');
    setLocale('en-US');
    expect(t('login.field.password')).toBe('Password');
    setLocale('zh-CN');
  });

  test('兼容路径：旧版中文字面量 / 缺译键一律回显本身', () => {
    expect(t('密码')).toBe('密码');
    expect(t('login.field.notYetTranslated')).toBe(
      'login.field.notYetTranslated',
    );
  });
});

describe('与 shared/api/errors.ts 的 i18nKey 契约（§1.6 / §1.5，不造第二套）', () => {
  test('FLOW_STATUS_TABLE（§1.6 流程态 31 词）的 i18nKey 两套字典全部可译', () => {
    const resolutions = Object.values(FLOW_STATUS_TABLE);
    expect(resolutions).toHaveLength(31);
    for (const { i18nKey } of resolutions) {
      expect(hasKey(i18nKey)).toBe(true);
      setLocale('en-US');
      expect(t(i18nKey)).not.toBe(i18nKey);
      setLocale('zh-CN');
      expect(t(i18nKey)).not.toBe(i18nKey);
    }
  });

  test('CODE_TABLE（§1.6 失败词 27 + §1.5 标准码 8 = 35 码）的 i18nKey 全部可译', () => {
    const resolutions = Object.values(CODE_TABLE);
    expect(resolutions).toHaveLength(35);
    for (const { i18nKey } of resolutions) {
      expect(hasKey(i18nKey)).toBe(true);
      setLocale('en-US');
      expect(t(i18nKey)).not.toBe(i18nKey);
      setLocale('zh-CN');
      expect(t(i18nKey)).not.toBe(i18nKey);
    }
  });

  test('未知取值兜底键（errors.status.unknown / errors.code.unknown）两套字典齐备', () => {
    expect(hasKey('errors.status.unknown')).toBe(true);
    expect(hasKey('errors.code.unknown')).toBe(true);
    setLocale('en-US');
    expect(t('errors.status.unknown')).toBe(
      'Something went wrong. Please try again later',
    );
    setLocale('zh-CN');
    expect(t('errors.code.unknown')).toBe('操作失败，请稍后重试');
  });
});

describe('跨端切换专键（zh / en 键集全量对齐）', () => {
  test('account.switchToAdmin / admin.switchToAccount 两套字典均可译', () => {
    expect(t('account.switchToAdmin')).toBe('切换到管理后台');
    expect(t('admin.switchToAccount')).toBe('切换到个人中心');
    setLocale('en-US');
    expect(t('account.switchToAdmin')).toBe('Switch to Admin Console');
    expect(t('admin.switchToAccount')).toBe('Switch to Account Center');
    setLocale('zh-CN');
  });
});

describe('模板管理文案契约（zh / en 键集对齐）', () => {
  const templateKeys = Object.keys(zhCN).filter(
    (key) => key.startsWith('admin.template') || key === 'admin.navTemplates',
  );

  test('新增模板键在两套字典均可译（不回显键）', () => {
    expect(templateKeys.length).toBeGreaterThan(0);
    for (const key of templateKeys) {
      expect(t(key)).not.toBe(key);
      setLocale('en-US');
      expect(t(key)).not.toBe(key);
      setLocale('zh-CN');
    }
  });

  test('插值占位符 zh / en 逐字对齐（{max} / {name}）', () => {
    expect(t('admin.templateKeyTooLong', { max: 64 })).toBe(
      '模板 key 不能超过 64 个字符',
    );
    expect(t('admin.editTemplateTitle', { name: 'A' })).toBe('编辑模板「A」');
    setLocale('en-US');
    expect(t('admin.templateKeyTooLong', { max: 64 })).toBe(
      'Template key cannot exceed 64 characters',
    );
    expect(t('admin.editTemplateTitle', { name: 'A' })).toBe(
      'Edit Template "A"',
    );
    setLocale('zh-CN');
  });
});

describe('代理提供商文案契约（五真实字段 + 引用键 + 展示名，zh / en 齐备）', () => {
  // 键清单与后端声明逐字对齐（servicetype.go / schemafield.go 的 Label / Help
  // 字面量即契约来源，缺任一键后端跨端契约测试即红）。
  const fieldKeys = [
    'admin.schemaField.proxySchemeLabel',
    'admin.schemaField.proxyHostLabel',
    'admin.schemaField.proxyHostHelp',
    'admin.schemaField.proxyPortLabel',
    'admin.schemaField.proxyPortHelp',
    'admin.schemaField.proxyUserLabel',
    'admin.schemaField.proxyPasswordLabel',
    'admin.schemaField.proxyPasswordHelp',
    'admin.schemaField.proxyProviderKeyLabel',
    'admin.schemaField.proxyProviderKeyHelp',
  ];
  const optionKeys = [
    'admin.schemaOption.scheme.socks5',
    'admin.schemaOption.scheme.http',
    'admin.schemaOption.scheme.https',
  ];
  const displayKeys = [
    'admin.providerType.proxy',
    'admin.providerCategory.proxy',
  ];

  test('五字段 / 引用键 label / help 键在 zh / en 两套字典齐备且可译（不回显键）', () => {
    for (const key of fieldKeys) {
      expect(hasKey(key)).toBe(true);
      expect(t(key)).not.toBe(key);
      setLocale('en-US');
      expect(hasKey(key)).toBe(true);
      expect(t(key)).not.toBe(key);
      setLocale('zh-CN');
    }
  });

  test('scheme 三 option 显示名在 zh / en 齐备；type / category=proxy 展示名齐备', () => {
    for (const key of [...optionKeys, ...displayKeys]) {
      expect(hasKey(key)).toBe(true);
      setLocale('en-US');
      expect(hasKey(key)).toBe(true);
      setLocale('zh-CN');
    }
  });

  test('help 写明引用键「留空 = 直连」与 host 字符集语义（zh / en 语义对应）', () => {
    expect(t('admin.schemaField.proxyProviderKeyHelp')).toContain('直连');
    expect(t('admin.schemaField.proxyHostHelp')).toContain('IPv6');
    setLocale('en-US');
    expect(t('admin.schemaField.proxyProviderKeyHelp')).toMatch(/direct/i);
    expect(t('admin.schemaField.proxyHostHelp')).toMatch(/IPv6/i);
    setLocale('zh-CN');
  });

  test('label 逐字锚定：删任一键或改文案即变红', () => {
    expect(t('admin.schemaField.proxySchemeLabel')).toBe('代理协议');
    expect(t('admin.schemaField.proxyHostLabel')).toBe('代理地址');
    expect(t('admin.schemaField.proxyPortLabel')).toBe('代理端口');
    expect(t('admin.schemaField.proxyUserLabel')).toBe('代理用户名');
    expect(t('admin.schemaField.proxyPasswordLabel')).toBe('代理密码');
    expect(t('admin.schemaField.proxyProviderKeyLabel')).toBe('出站代理');
    expect(t('admin.providerType.proxy')).toBe('出站代理');
    setLocale('en-US');
    expect(t('admin.schemaField.proxySchemeLabel')).toBe('Proxy scheme');
    expect(t('admin.schemaField.proxyHostLabel')).toBe('Proxy host');
    expect(t('admin.schemaField.proxyPortLabel')).toBe('Proxy port');
    expect(t('admin.schemaField.proxyUserLabel')).toBe('Proxy username');
    expect(t('admin.schemaField.proxyPasswordLabel')).toBe('Proxy password');
    expect(t('admin.schemaField.proxyProviderKeyLabel')).toBe('Outbound proxy');
    expect(t('admin.providerType.proxy')).toBe('Outbound proxy');
    setLocale('zh-CN');
  });
});

describe('拉码模式三字段文案契约（wechat_mp_scan qrcode 三键，zh / en 齐备）', () => {
  // 键清单与后端渠道注册表声明逐字对齐（wechat_mp_scan 的 Label / Help
  // 字面量即契约来源，缺任一键后端跨端契约测试即红）。
  const qrcodeKeys = [
    'admin.schemaField.qrcodeModeLabel',
    'admin.schemaField.qrcodeModeHelp',
    'admin.schemaField.qrcodeFormatLabel',
    'admin.schemaField.qrcodeFormatHelp',
    'admin.schemaField.qrcodeTipLabel',
    'admin.schemaField.qrcodeTipHelp',
  ];

  test('label / help 六键在 zh / en 两套字典齐备且可译（不回显键）', () => {
    for (const key of qrcodeKeys) {
      expect(hasKey(key)).toBe(true);
      expect(t(key)).not.toBe(key);
      setLocale('en-US');
      expect(hasKey(key)).toBe(true);
      expect(t(key)).not.toBe(key);
      setLocale('zh-CN');
    }
  });

  test('label 逐字锚定 + format help 保留 {{TICKET}} 占位符原样（无参数不插值）', () => {
    expect(t('admin.schemaField.qrcodeModeLabel')).toBe('拉码模式');
    expect(t('admin.schemaField.qrcodeFormatLabel')).toBe('二维码内容模板');
    expect(t('admin.schemaField.qrcodeTipLabel')).toBe('扫码提示文案');
    expect(t('admin.schemaField.qrcodeFormatHelp')).toContain('{{TICKET}}');
    setLocale('en-US');
    expect(t('admin.schemaField.qrcodeModeLabel')).toBe('QR Code Mode');
    expect(t('admin.schemaField.qrcodeFormatLabel')).toBe(
      'QR Code Content Template',
    );
    expect(t('admin.schemaField.qrcodeTipLabel')).toBe('Scan Tip');
    expect(t('admin.schemaField.qrcodeFormatHelp')).toContain('{{TICKET}}');
    setLocale('zh-CN');
  });
});

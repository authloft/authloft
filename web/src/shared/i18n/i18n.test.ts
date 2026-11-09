// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化落地后移除）。
// @ts-ignore
import { afterEach, describe, expect, test } from 'rstack/test';
import { zhCN } from './zh-CN';
import { enUS } from './en-US';
import {
  getLocale,
  hasKey,
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

describe('语言选择（最简实现，zh-CN 默认）', () => {
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
    expect(t('admin.schemaOption.ui_group.social')).toBe('社交');
    setLocale('en-US');
    expect(t('admin.schemaOption.ui_group.social')).toBe('Social');
    setLocale('zh-CN');
    // union_provider 的 options 是自定义 provider_key；即便值恰好叫 social，
    // 也不会命中 ui_group 的枚举译文。
    expect(hasKey('admin.schemaOption.union_provider.social')).toBe(false);
  });

  test('兼容路径：旧版中文字面量 / 缺译键一律回显本身（不静默 undefined）', () => {
    expect(t('唯一标识')).toBe('唯一标识');
    expect(t('admin.schemaField.notYetTranslated')).toBe(
      'admin.schemaField.notYetTranslated',
    );
  });
});

describe('与 shared/api/errors.ts 的 i18nKey 契约（§1.6 / §1.5，不造第二套）', () => {
  test('FLOW_STATUS_TABLE（§1.6 全表 33 词）的 i18nKey 两套字典全部可译', () => {
    const resolutions = Object.values(FLOW_STATUS_TABLE);
    expect(resolutions).toHaveLength(33);
    for (const { i18nKey } of resolutions) {
      expect(hasKey(i18nKey)).toBe(true);
      setLocale('en-US');
      expect(t(i18nKey)).not.toBe(i18nKey);
      setLocale('zh-CN');
      expect(t(i18nKey)).not.toBe(i18nKey);
    }
  });

  test('CODE_TABLE（§1.6 失败词 26 + §1.5 标准码 8 = 34 码）的 i18nKey 全部可译', () => {
    const resolutions = Object.values(CODE_TABLE);
    expect(resolutions).toHaveLength(34);
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

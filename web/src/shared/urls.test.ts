// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化落地后移除）。
// @ts-ignore
import { describe, expect, test } from 'rstack/test';
import {
  contextSwitchUrl,
  DEFAULT_ACCOUNT_HOME,
  DEFAULT_ADMIN_HOME,
  LOGIN_PATH,
  LOGOUT_PATH,
  loginUrl,
  logoutUrl,
  normalizeAlRoot,
  OAUTH_CALLBACK_PREFIX,
  sanitizeReturnTo,
  type ContextSwitchTarget,
} from './urls';

/**
 * shared/urls.ts 测试：URL 唯一真值的拼接、归一与
 * returnTo 白名单（防开放重定向）。收编自原 account / admin / setup 三份
 * bootstrap 实现的既有口径（空 / 空白 → location.origin 兜底；node 无
 * location → 空串，见 bootstrap 各 describe 的历史断言）。
 */

describe('路径常量（定稿形态）', () => {
  test('跨域路径常量逐字', () => {
    expect(LOGIN_PATH).toBe('/sso/login');
    expect(LOGOUT_PATH).toBe('/sso/logout');
    expect(OAUTH_CALLBACK_PREFIX).toBe('/sso/oauth/callback/');
    expect(DEFAULT_ACCOUNT_HOME).toBe('/account#/');
  });
});

describe('normalizeAlRoot（收编三份逐字复制实现的统一口径）', () => {
  test('非字符串 / 空串 / 纯空白 → node 环境回落空串（浏览器回落 location.origin）', () => {
    expect(normalizeAlRoot(undefined)).toBe('');
    expect(normalizeAlRoot('')).toBe('');
    expect(normalizeAlRoot('   ')).toBe('');
    expect(normalizeAlRoot(42)).toBe('');
  });

  test('非空 → trim + 去尾斜杠（保留内部斜杠与端口）', () => {
    expect(normalizeAlRoot('https://uc.example.com')).toBe(
      'https://uc.example.com',
    );
    expect(normalizeAlRoot('https://uc.example.com/')).toBe(
      'https://uc.example.com',
    );
    expect(normalizeAlRoot('  https://uc.example.com//  ')).toBe(
      'https://uc.example.com',
    );
    expect(normalizeAlRoot('http://localhost:8080/')).toBe(
      'http://localhost:8080',
    );
  });
});

describe('loginUrl / logoutUrl（§8 行 1418/1420）', () => {
  test('基础拼接：{alRoot} 前缀', () => {
    expect(loginUrl('https://uc.example.com')).toBe(
      'https://uc.example.com/sso/login',
    );
    expect(logoutUrl('https://uc.example.com')).toBe(
      'https://uc.example.com/sso/logout',
    );
  });

  test('returnTo 缺省 → 不带查询参数', () => {
    expect(loginUrl('https://uc.example.com')).not.toContain('returnTo');
  });

  test('returnTo 白名单命中 → encode 后拼装', () => {
    expect(
      loginUrl('https://uc.example.com', '/account#/security?bind=github'),
    ).toBe(
      'https://uc.example.com/sso/login?returnTo=%2Faccount%23%2Fsecurity%3Fbind%3Dgithub',
    );
    expect(loginUrl('', '/admin#/users')).toBe(
      '/sso/login?returnTo=%2Fadmin%23%2Fusers',
    );
  });
});

describe('sanitizeReturnTo（前缀白名单，防开放重定向）', () => {
  test('放行 /account# 与 /admin# 前缀的站内值（原样返回）', () => {
    expect(sanitizeReturnTo('/account#/')).toBe('/account#/');
    expect(sanitizeReturnTo('/admin#/users/123')).toBe('/admin#/users/123');
  });

  test('站外绝对 URL / 协议相对 / 其他站内路径 / 空串 → 回落默认落点', () => {
    expect(sanitizeReturnTo('https://evil.example.com/x')).toBe(
      DEFAULT_ACCOUNT_HOME,
    );
    expect(sanitizeReturnTo('//evil.example.com')).toBe(DEFAULT_ACCOUNT_HOME);
    expect(sanitizeReturnTo('/sso/login')).toBe(DEFAULT_ACCOUNT_HOME);
    expect(sanitizeReturnTo('/account/profile')).toBe(DEFAULT_ACCOUNT_HOME);
    expect(sanitizeReturnTo('')).toBe(DEFAULT_ACCOUNT_HOME);
  });

  test('白名单前缀大小写敏感（大写变体不放行）', () => {
    expect(sanitizeReturnTo('/Account#/')).toBe(DEFAULT_ACCOUNT_HOME);
  });
});

describe('contextSwitchUrl（跨端切换落点，封闭枚举防开放重定向）', () => {
  test('DEFAULT_ADMIN_HOME 逐字 + 两 target 落点正确', () => {
    expect(DEFAULT_ADMIN_HOME).toBe('/admin#/status');
    expect(contextSwitchUrl('https://uc.test', 'account')).toBe(
      'https://uc.test/account#/',
    );
    expect(contextSwitchUrl('https://uc.test', 'admin')).toBe(
      'https://uc.test/admin#/status',
    );
  });

  test('alRoot 归一（trim / 去尾斜杠 / 空值回落）', () => {
    expect(contextSwitchUrl('  https://uc.test//  ', 'admin')).toBe(
      'https://uc.test/admin#/status',
    );
    expect(contextSwitchUrl('', 'account')).toBe('/account#/');
    expect(contextSwitchUrl(undefined, 'admin')).toBe('/admin#/status');
  });

  test('非法 target 与站外值被拒：回落 account 默认落点，不产站外跳转', () => {
    const invalid = [
      'nope',
      '',
      'https://evil.example.com/x',
    ] as unknown as ContextSwitchTarget[];
    for (const target of invalid) {
      expect(contextSwitchUrl('https://uc.test', target)).toBe(
        'https://uc.test/account#/',
      );
    }
  });
});

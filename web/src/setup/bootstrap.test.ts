// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（既定裁决，tsconfig 现代化后移除）。
// @ts-ignore
import { afterEach, describe, expect, rs, test } from 'rstack/test';
import {
  DEFAULT_STATIC_BASE,
  loadSetupInit,
  normalizeAlRoot,
} from './bootstrap';

/**
 * setup bootstrap 直接单测：后端 setup 壳注入
 * al_root 空串属合规设计（接口文档 §8），前端 bootstrap.ts 的兜底回落
 * 此前缺直接单测，本文件锁死——
 * - normalizeAlRoot：空串 / 纯空白 → location.origin 兜底；非空 → trim +
 *   去尾斜杠原值（trim 先于去尾斜杠，§6b / §8）；
 * - loadSetupInit：壳注入空串 / 非字符串 / 未下发 → alRoot 回落当前站点源；
 *   非空 → 归一原值。
 * 单测环境为 node（无全局 location），经 rs.stubGlobal('location', ...)
 * 模拟浏览器站点源；afterEach 统一 unstubAllGlobals + 清注入块防跨用例
 * 泄漏（沿 account.test.tsx 模式）。bootstrap.ts 无模块级副作用
 * （loadSetupInit 调用时才读 globalThis.__AUTHLOFT_INIT__），静态 import。
 */
const FALLBACK_ORIGIN = 'https://setup-fallback.test';

afterEach(() => {
  rs.unstubAllGlobals();
  (globalThis as { __AUTHLOFT_INIT__?: unknown }).__AUTHLOFT_INIT__ = undefined;
});

describe('normalizeAlRoot（setup 壳注入空串 → location.origin 回落）', () => {
  test('空串 / 纯空白 → location.origin 兜底', () => {
    rs.stubGlobal('location', { origin: FALLBACK_ORIGIN });
    expect(normalizeAlRoot('')).toBe(FALLBACK_ORIGIN);
    expect(normalizeAlRoot('   ')).toBe(FALLBACK_ORIGIN);
  });

  test('非空 → trim + 去尾斜杠原值，不回落（node 无 location 也不触碰）', () => {
    expect(normalizeAlRoot('https://uc.example.com')).toBe(
      'https://uc.example.com',
    );
    expect(normalizeAlRoot('https://uc.example.com/')).toBe(
      'https://uc.example.com',
    );
    // trim 先于去尾斜杠：空白裹多重尾斜杠同样归一。
    expect(normalizeAlRoot('  https://uc.example.com//  ')).toBe(
      'https://uc.example.com',
    );
  });
});

describe('loadSetupInit（§6b / §8：壳注入经 globalThis 读取）', () => {
  test('注入 { al_root: "" } → alRoot 回落 location.origin，static_base 缺省 /assets/', () => {
    rs.stubGlobal('location', { origin: FALLBACK_ORIGIN });
    (globalThis as { __AUTHLOFT_INIT__?: unknown }).__AUTHLOFT_INIT__ = {
      al_root: '',
    };
    expect(loadSetupInit()).toEqual({
      alRoot: FALLBACK_ORIGIN,
      staticBase: DEFAULT_STATIC_BASE,
    });
  });

  test('al_root 纯空白 / 非字符串 / 注入块未下发 → 同样回落 location.origin', () => {
    rs.stubGlobal('location', { origin: FALLBACK_ORIGIN });
    const globalWithInit = globalThis as { __AUTHLOFT_INIT__?: unknown };
    globalWithInit.__AUTHLOFT_INIT__ = { al_root: '   ' };
    expect(loadSetupInit().alRoot).toBe(FALLBACK_ORIGIN);
    globalWithInit.__AUTHLOFT_INIT__ = { al_root: 123 };
    expect(loadSetupInit().alRoot).toBe(FALLBACK_ORIGIN);
    globalWithInit.__AUTHLOFT_INIT__ = undefined;
    expect(loadSetupInit().alRoot).toBe(FALLBACK_ORIGIN);
  });

  test('al_root 非空 → 归一原值（trim + 去尾斜杠），不回落', () => {
    (globalThis as { __AUTHLOFT_INIT__?: unknown }).__AUTHLOFT_INIT__ = {
      al_root: 'https://uc.test/',
      static_base: '/cdn',
    };
    expect(loadSetupInit()).toEqual({
      alRoot: 'https://uc.test',
      staticBase: '/cdn/',
    });
  });
});

// deriveRequestStatus 真值表（§5.3 唯一残留纯函数）。
// 覆盖 loading / error / data 三原语的全组合优先级：
// loading 优先 > error 覆盖 > data 落地 success > 皆空 idle。
// tsconfig moduleResolution=node 解析不了 rstack/test 子路径。
// @ts-ignore
import { describe, expect, test } from 'rstack/test';
import { deriveRequestStatus } from './deriveRequestStatus';

describe('deriveRequestStatus 真值表（§5.3）', () => {
  test('loading=true 一律 loading（error/data 已落地也不覆盖在途）', () => {
    expect(deriveRequestStatus(true, undefined, undefined)).toBe('loading');
    expect(deriveRequestStatus(true, new Error('x'), undefined)).toBe('loading');
    expect(deriveRequestStatus(true, undefined, { id: 1 })).toBe('loading');
    expect(deriveRequestStatus(true, new Error('x'), { id: 1 })).toBe('loading');
  });

  test('非在途 + error 已落地 → error', () => {
    expect(deriveRequestStatus(false, new Error('x'), undefined)).toBe('error');
  });

  test('非在途 + 无 error + data 已落地 → success（空数组 / null 均为已落地）', () => {
    expect(deriveRequestStatus(false, undefined, [])).toBe('success');
    expect(deriveRequestStatus(false, undefined, null)).toBe('success');
    expect(deriveRequestStatus(false, undefined, { id: 1 })).toBe('success');
  });

  test('三者皆空 → idle（尚未发起）', () => {
    expect(deriveRequestStatus(false, undefined, undefined)).toBe('idle');
  });
});

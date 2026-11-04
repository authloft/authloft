/**
 * 能力检测（docs/前端架构.md §3.2 useCapability 行 305）：按 methods[].capability
 * 表达式（§2.1，如 window.PublicKeyCredential）做检测。表达式按 `.` 拆属性链，
 * 从 window 起逐段取值，整链解析成功且末段为真值 → true；任一段缺失 / 非对象 /
 * 表达式非法 → false。禁止 eval / new Function（CSP 不含 unsafe-eval，能力表达式
 * 不构成可信输入），解析失败不抛错——能力不满足该方式自动隐藏（需求 §4.1.6），
 * 不展示「不支持」提示。
 */
import { useMemo } from 'react';

/** 属性链单段的合法形态（标识符）；非法段即非法表达式，整链 false。 */
const SEGMENT_PATTERN = /^[A-Za-z_$][A-Za-z0-9_$]*$/;

/**
 * 解析能力表达式（纯函数）：
 * - undefined / 空串（protojson 零值省略的同义）= 无能力要求 → true（方式不受限）；
 * - 空段（首尾点 / 连续点）或非标识符段 → false（表达式非法）；
 * - 从 globalThis（浏览器即 window）起逐段取值：任一段缺失（undefined / null）
 *   → false；中间段非对象 / 函数（无法继续取属性）→ false；末段非真值 → false。
 */
export function resolveCapability(expression: string | undefined): boolean {
  if (expression === undefined || expression === '') {
    return true;
  }
  if (typeof expression !== 'string') {
    return false;
  }
  const segments = expression.split('.');
  if (segments.some((segment) => !SEGMENT_PATTERN.test(segment))) {
    return false;
  }
  let current: unknown = globalThis;
  for (let i = 0; i < segments.length; i += 1) {
    const value = (current as Record<string, unknown>)[segments[i]];
    if (value === undefined || value === null) {
      return false;
    }
    const isLast = i === segments.length - 1;
    if (!isLast && typeof value !== 'object' && typeof value !== 'function') {
      return false;
    }
    current = value;
  }
  return Boolean(current);
}

/** hook 壳：能力在页面存活期内视为恒定，表达式不变则结果稳定。 */
export function useCapability(capability: string | undefined): boolean {
  return useMemo(() => resolveCapability(capability), [capability]);
}

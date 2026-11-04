/**
 * int64 字段进出 UI 的唯一转换点（docs/前端架构.md §3.4；docs/接口文档.md §1.12）。
 *
 * 生成的消息里 int64 字段是 bigint，JSON 文本里是十进制字符串；ID 与时间戳
 * 全程保持 bigint 或字符串，禁止 Number(id)（超 2^53 静默丢精度）；时长 / 计数类
 * 转 number 前必经 toCount。
 */

/**
 * int64 → 展示字符串：bigint 直接十进制化；字符串按 §1.12 十进制口径归一
 * （BigInt 解析，容忍首尾空白与前导 +；非法串抛 SyntaxError——fail fast，
 * 正常调用方不会传入非十进制串）；空串原样返回（零值 / 未设置语义）。
 */
export function toDisplay(v: bigint | string): string {
  if (typeof v === 'bigint') {
    return v.toString();
  }
  return v === '' ? '' : BigInt(v).toString();
}

/**
 * int64（bigint）→ 数值计数：时长 / 计数类字段（retryAfter、expiresIn、
 * pageSize、total、length）转 number 的唯一入口；超 Number.MAX_SAFE_INTEGER
 * 抛 RangeError（§1.12：禁止无感知丢精度）。
 */
export function toCount(v: bigint): number {
  const n = Number(v);
  if (!Number.isSafeInteger(n)) {
    throw new RangeError(`int64 ${v} exceeds Number.MAX_SAFE_INTEGER`);
  }
  return n;
}

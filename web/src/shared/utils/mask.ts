/**
 * 手机号 / 邮箱的本地体验性掩码（docs/前端架构.md §3.4 mask.ts 行 339）：
 * 纯函数；仅用于本地输入占位与体验性展示——服务端下发的 phone / email /
 * masked_target 已是掩码值，一律直接展示、不再二次掩码（接口文档 §3.1）。
 */

/**
 * 手机号掩码：保留前 3 后 4（对齐 docs/前端架构.md §3.3 MaskedTarget 的
 * `138****8000` 一类展示），掩码位以 * 补齐、总长度不变；不足 8 位时整体
 * 掩码（无可靠的明文保留余量）。空串原样返回。
 */
export function maskPhone(phone: string): string {
  if (phone.length < 8) {
    return '*'.repeat(phone.length);
  }
  const head = phone.slice(0, 3);
  const tail = phone.slice(-4);
  return `${head}${'*'.repeat(phone.length - 7)}${tail}`;
}

/**
 * 邮箱掩码：本地部分保留首字符 + `***`，域名整体保留。
 * 掩码格式固定（接口文档 §3.1 行 813 唯一定义，前后端同形）：
 * 邮箱 `a***@example.com`——本地部分首字符 + `***`，域名保留。
 * 无 @ 或本地部分为空（非邮箱形状）时整体掩码；空串原样返回。
 */
export function maskEmail(email: string): string {
  const at = email.indexOf('@');
  if (at <= 0) {
    return '*'.repeat(email.length);
  }
  return `${email.slice(0, 1)}***${email.slice(at)}`;
}

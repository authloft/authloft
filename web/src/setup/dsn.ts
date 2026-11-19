/**
 * DB 连接串六字段校验与拼装纯函数（接口文档 §13.3）：前端把
 * 地址 / 端口 / 用户名 / 密码 / 数据库名（五个必填）+ 额外参数（可选）
 * 六个表单项按所选方言拼成单个 `dbDsn` 字符串发往后端。
 *
 * MySQL 拼装口径 = go-sql-driver/mysql DSN：
 * `[user[:password]@][net[(addr)]]/dbname[?param1=value1&…]`。
 *
 * 特殊字符口径（go-sql-driver 既定解析规则，禁止引入解析歧义）：
 * 解析器从右往左取**最后一个 `/`** 分隔 dbname、其前**最后一个 `@`** 分隔
 * userinfo、userinfo 内**第一个 `:`** 分隔 user / password。因此：
 * - 密码含 `@` `:` `/` `?` 空格、用户名含 `@` `/` `?` 空格 → **原样拼接**
 *   （均落在上述规则保护区间内，解析无歧义；DSN 非 URL，不做 percent-encode，
 *   go-sql-driver 也不解码，转义反而产生错误凭证）；
 * - 用户名含 `:` → **拒绝**（第一个 `:` 固定为 user/password 分隔符，无法
 *   无歧义表达，go-sql-driver 不支持转义）；
 * - 数据库名含 `?` 或 `/` → **拒绝**（分别与参数分隔符、dbname 分隔符歧义）。
 *
 * PostgreSQL 拼装口径 = URL 形态（后端 validatePGDSN 以 net/url 校验、
 * pgdriver 按 URL 解析并 percent-decode userinfo）：
 * `postgres://user:password@host:port/dbname[?params]`。userinfo 内的
 * `:` `@` `/` 等分隔字符按 RFC 3986 percent-encode（encodeURIComponent），
 * 与驱动解码对称，含特殊字符的凭证无歧义表达。
 * 额外参数原样追加、不做二次加工，仅归一「是否已带引导 `?`」防双 `?`。
 * 校验为体验性前置检查（编码约束 §9 第 4 条：后端为唯一权威，连接失败
 * 最终由 `db_unreachable` 兜底映射回 DSN 字段组）。
 */

/** DB 方言（§13.3 db_driver；缺省 mysql 与后端回落口径一致）。 */
export type DbDriver = 'mysql' | 'postgres';

/** DB 区六字段表单值（port 为表单原样字符串，校验负责口径）。 */
export interface DbDsnFormFields {
  host: string;
  port: string;
  user: string;
  password: string;
  database: string;
  params: string;
}

export type DbDsnFieldKey =
  'host' | 'port' | 'user' | 'password' | 'database' | 'params';

/** 字段级校验失败项（params 可选，不产生错误）。 */
export type DbDsnFieldError =
  'required' | 'portInvalid' | 'userColon' | 'nameInvalid';

/** 端口口径：纯数字且 1-65535。 */
const PORT_PATTERN = /^\d+$/;

/** 端口是否合法（纯数字 + 值域 1-65535）。 */
export function isValidPort(value: string): boolean {
  if (!PORT_PATTERN.test(value)) {
    return false;
  }
  const port = Number.parseInt(value, 10);
  return port >= 1 && port <= 65535;
}

/**
 * 六字段体验性校验：五项必填（密码按原值判空、不 trim——首尾空格可能是
 * 真实密码的一部分）、端口纯数字 1-65535、用户名拒 `:`、数据库名拒
 * `?` 与 `/`。全部通过返回空对象。
 */
export function validateDbDsnFields(
  fields: DbDsnFormFields,
): Partial<Record<DbDsnFieldKey, DbDsnFieldError>> {
  const errors: Partial<Record<DbDsnFieldKey, DbDsnFieldError>> = {};
  if (fields.host.trim() === '') {
    errors.host = 'required';
  }
  if (fields.port.trim() === '') {
    errors.port = 'required';
  } else if (!isValidPort(fields.port.trim())) {
    errors.port = 'portInvalid';
  }
  if (fields.user.trim() === '') {
    errors.user = 'required';
  } else if (fields.user.includes(':')) {
    errors.user = 'userColon';
  }
  if (fields.password === '') {
    errors.password = 'required';
  }
  if (fields.database.trim() === '') {
    errors.database = 'required';
  } else if (fields.database.includes('?') || fields.database.includes('/')) {
    errors.database = 'nameInvalid';
  }
  return errors;
}

/**
 * 拼装 MySQL DSN：`user:password@tcp(host:port)/dbname[?params]`。
 * host / user / database / params / port 取 trim 值，password 原样；
 * host 含 `:`（IPv6 字面量）且未自带 `[]` 时按 go-sql-driver 惯例包 `[]`。
 * 调用前应先过 validateDbDsnFields（本函数不重复校验）。
 */
export function buildMysqlDsn(fields: DbDsnFormFields): string {
  const host = fields.host.trim();
  const hostExpr =
    host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
  const params = (fields.params || '').trim();
  const paramsPart =
    params === '' ? '' : params.startsWith('?') ? params : `?${params}`;
  return `${fields.user.trim()}:${fields.password}@tcp(${hostExpr}:${fields.port.trim()})/${fields.database.trim()}${paramsPart}`;
}

/** 拼装参数尾段（MySQL / PG URL 共用）：归一「是否已带引导 ?」防双 ?。 */
function paramsPartOf(fields: DbDsnFormFields): string {
  const params = (fields.params || '').trim();
  return params === '' ? '' : params.startsWith('?') ? params : `?${params}`;
}

/**
 * 拼装 PostgreSQL URL DSN：`postgres://user:password@host:port/dbname[?params]`。
 * 与后端 validatePGDSN（net/url）及 pgdriver 解析对齐：user / password /
 * dbname 按 encodeURIComponent percent-encode（RFC 3986，userinfo 与 path
 * 的 `:` `@` `/` 分隔字符不再有歧义，pgdriver 解码后即原始凭证）；host 含
 * `:`（IPv6 字面量）且未自带 `[]` 时按 URL 惯例包 `[]`。调用前应先过
 * validateDbDsnFields（本函数不重复校验）。
 */
export function buildPostgresDsn(fields: DbDsnFormFields): string {
  const host = fields.host.trim();
  const hostExpr =
    host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
  return `postgres://${encodeURIComponent(fields.user.trim())}:${encodeURIComponent(fields.password)}@${hostExpr}:${fields.port.trim()}/${encodeURIComponent(fields.database.trim())}${paramsPartOf(fields)}`;
}

/**
 * 按方言拼装 dbDsn（§13.3）：mysql → go-sql-driver 形态、postgres → URL
 * 形态。未知值按缺省方言 mysql 回落（与后端 db_driver 零值回落口径一致）。
 */
export function buildDbDsn(driver: DbDriver, fields: DbDsnFormFields): string {
  return driver === 'postgres'
    ? buildPostgresDsn(fields)
    : buildMysqlDsn(fields);
}

// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化后移除）。
// @ts-ignore
import { describe, expect, test } from 'rstack/test';
import {
  buildMysqlDsn,
  isValidPort,
  validateDbDsnFields,
  type DbDsnFormFields,
} from './dsn';

/** 典型合法输入基线（各用例按需覆写单项）。 */
const VALID: DbDsnFormFields = {
  host: '127.0.0.1',
  port: '3306',
  user: 'root',
  password: 'secret',
  database: 'authloft',
  params: '',
};

describe('setup/dsn isValidPort（端口须为数字且 1-65535）', () => {
  test('纯数字且值域内 → true（含 1 / 65535 边界与 3306 常规值）', () => {
    expect(isValidPort('1')).toBe(true);
    expect(isValidPort('3306')).toBe(true);
    expect(isValidPort('65535')).toBe(true);
  });

  test('非数字 → false（字母 / 空 / 含符号）', () => {
    expect(isValidPort('abc')).toBe(false);
    expect(isValidPort('33o6')).toBe(false);
    expect(isValidPort('')).toBe(false);
    expect(isValidPort('-1')).toBe(false);
    expect(isValidPort('33.6')).toBe(false);
  });

  test('越界 → false（0 / 65536）', () => {
    expect(isValidPort('0')).toBe(false);
    expect(isValidPort('65536')).toBe(false);
  });
});

describe('setup/dsn validateDbDsnFields（五项必填 + 歧义字符拒绝）', () => {
  test('典型合法输入 → 无错误', () => {
    expect(validateDbDsnFields(VALID)).toEqual({});
  });

  test('五项必填各自为空 → 对应 required', () => {
    expect(validateDbDsnFields({ ...VALID, host: '   ' })).toEqual({
      host: 'required',
    });
    expect(validateDbDsnFields({ ...VALID, port: '' })).toEqual({
      port: 'required',
    });
    expect(validateDbDsnFields({ ...VALID, user: ' ' })).toEqual({
      user: 'required',
    });
    expect(validateDbDsnFields({ ...VALID, password: '' })).toEqual({
      password: 'required',
    });
    expect(validateDbDsnFields({ ...VALID, database: '' })).toEqual({
      database: 'required',
    });
  });

  test('密码仅空格不判空（原样拼接口径，trim 会错杀真实密码）', () => {
    expect(validateDbDsnFields({ ...VALID, password: ' ' })).toEqual({});
  });

  test('端口非法（非数字 / 越界）→ portInvalid', () => {
    expect(validateDbDsnFields({ ...VALID, port: 'abc' })).toEqual({
      port: 'portInvalid',
    });
    expect(validateDbDsnFields({ ...VALID, port: '0' })).toEqual({
      port: 'portInvalid',
    });
    expect(validateDbDsnFields({ ...VALID, port: '65536' })).toEqual({
      port: 'portInvalid',
    });
  });

  test('用户名含 : → userColon（DSN 无法无歧义表达）', () => {
    expect(validateDbDsnFields({ ...VALID, user: 'us:er' })).toEqual({
      user: 'userColon',
    });
  });

  test('数据库名含 ? 或 / → nameInvalid（与参数 / dbname 分隔符歧义）', () => {
    expect(validateDbDsnFields({ ...VALID, database: 'db?x' })).toEqual({
      database: 'nameInvalid',
    });
    expect(validateDbDsnFields({ ...VALID, database: 'db/x' })).toEqual({
      database: 'nameInvalid',
    });
  });

  test('额外参数可空 / 非空 / 自带引导 ? → 不产生错误', () => {
    expect(validateDbDsnFields({ ...VALID, params: '' })).toEqual({});
    expect(
      validateDbDsnFields({
        ...VALID,
        params: 'charset=utf8mb4&parseTime=true',
      }),
    ).toEqual({});
    expect(validateDbDsnFields({ ...VALID, params: '?tls=true' })).toEqual({});
  });
});

describe('setup/dsn buildMysqlDsn（拼装口径）', () => {
  test('典型合法输入 → user:password@tcp(host:port)/dbname', () => {
    expect(buildMysqlDsn(VALID)).toBe(
      'root:secret@tcp(127.0.0.1:3306)/authloft',
    );
  });

  test('域名 host 原样', () => {
    expect(buildMysqlDsn({ ...VALID, host: 'db.example.com' })).toBe(
      'root:secret@tcp(db.example.com:3306)/authloft',
    );
  });

  test('密码含 @ : / ? 空格 → 原样拼接（「最后 @、首 :」规则保护，无歧义）', () => {
    expect(buildMysqlDsn({ ...VALID, password: 'p@ss:wo/rd? x' })).toBe(
      'root:p@ss:wo/rd? x@tcp(127.0.0.1:3306)/authloft',
    );
  });

  test('用户名含 @ → 原样拼接（分隔取最后一个 @）', () => {
    expect(buildMysqlDsn({ ...VALID, user: 'us@er' })).toBe(
      'us@er:secret@tcp(127.0.0.1:3306)/authloft',
    );
  });

  test('额外参数非空（不带 ?）→ 追加 ?params', () => {
    expect(
      buildMysqlDsn({
        ...VALID,
        params: 'charset=utf8mb4&parseTime=true',
      }),
    ).toBe(
      'root:secret@tcp(127.0.0.1:3306)/authloft?charset=utf8mb4&parseTime=true',
    );
  });

  test('额外参数自带引导 ? → 归一为单个 ?（防双 ? 解析歧义）', () => {
    expect(buildMysqlDsn({ ...VALID, params: '?charset=utf8mb4' })).toBe(
      'root:secret@tcp(127.0.0.1:3306)/authloft?charset=utf8mb4',
    );
  });

  test('额外参数为空 / 纯空白 → 无追加', () => {
    expect(buildMysqlDsn({ ...VALID, params: '   ' })).toBe(
      'root:secret@tcp(127.0.0.1:3306)/authloft',
    );
  });

  test('IPv6 host → 按 go-sql-driver 惯例包 []', () => {
    expect(buildMysqlDsn({ ...VALID, host: '::1' })).toBe(
      'root:secret@tcp([::1]:3306)/authloft',
    );
  });

  test('host 已自带 [] → 不重复包裹', () => {
    expect(buildMysqlDsn({ ...VALID, host: '[2001:db8::1]' })).toBe(
      'root:secret@tcp([2001:db8::1]:3306)/authloft',
    );
  });

  test('host/user/database/port/params 首尾空白 trim、password 原样不 trim', () => {
    expect(
      buildMysqlDsn({
        host: ' 127.0.0.1 ',
        port: ' 3306 ',
        user: ' root ',
        password: ' secret ',
        database: ' authloft ',
        params: ' ',
      }),
    ).toBe('root: secret @tcp(127.0.0.1:3306)/authloft');
  });
});

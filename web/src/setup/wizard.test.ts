// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化后移除）。
// @ts-ignore
import { describe, expect, test } from 'rstack/test';
import { ApiError } from '../shared/api/errors';
import {
  classifyInstallError,
  joinRedisAddr,
  validateRedisFields,
} from './wizard';

/** Redis host/port 校验与拼装、请求错误「行内 vs Toast」分派。 */

describe('setup/wizard validateRedisFields（host 必填 + port 1-65535，与 DB 同口径）', () => {
  test('典型合法输入 → 无错误', () => {
    expect(validateRedisFields('127.0.0.1', '6379')).toEqual({});
    expect(validateRedisFields('redis.example.com', '1')).toEqual({});
    expect(validateRedisFields('redis.example.com', '65535')).toEqual({});
  });

  test('host 空 / 纯空白 → host required（trim 口径）', () => {
    expect(validateRedisFields('', '6379')).toEqual({ host: 'required' });
    expect(validateRedisFields('   ', '6379')).toEqual({ host: 'required' });
  });

  test('port 空 → port required', () => {
    expect(validateRedisFields('127.0.0.1', '')).toEqual({ port: 'required' });
    expect(validateRedisFields('127.0.0.1', '  ')).toEqual({ port: 'required' });
  });

  test('port 非数字 / 越界 → portInvalid（0 / 65536 / 字母）', () => {
    expect(validateRedisFields('127.0.0.1', 'abc')).toEqual({
      port: 'portInvalid',
    });
    expect(validateRedisFields('127.0.0.1', '0')).toEqual({
      port: 'portInvalid',
    });
    expect(validateRedisFields('127.0.0.1', '65536')).toEqual({
      port: 'portInvalid',
    });
  });

  test('host 与 port 同时非法 → 两个错误一次返回（不发请求前置拦截依据）', () => {
    expect(validateRedisFields(' ', '0')).toEqual({
      host: 'required',
      port: 'portInvalid',
    });
  });
});

describe('setup/wizard joinRedisAddr（wire 契约：单字符串 host:port，§13.3）', () => {
  test('典型输入 → host:port', () => {
    expect(joinRedisAddr('127.0.0.1', '6379')).toBe('127.0.0.1:6379');
    expect(joinRedisAddr('redis.example.com', '6380')).toBe(
      'redis.example.com:6380',
    );
  });

  test('两侧首尾空白 trim', () => {
    expect(joinRedisAddr(' 127.0.0.1 ', ' 6379 ')).toBe('127.0.0.1:6379');
  });
});

describe('setup/wizard classifyInstallError（字段级留行内，其余走 Toast）', () => {
  function apiError(code: string): ApiError {
    return new ApiError({
      message: `mock ${code}`,
      httpStatus: 400,
      code,
      requestId: 'req-test',
    });
  }

  test('命中 §13 字段映射 → field + 映射后的字段名', () => {
    expect(classifyInstallError(apiError('config_invalid'))).toMatchObject({
      kind: 'field',
      field: 'root',
    });
    expect(classifyInstallError(apiError('username_invalid'))).toMatchObject({
      kind: 'field',
      field: 'adminUsername',
    });
    expect(classifyInstallError(apiError('password_weak'))).toMatchObject({
      kind: 'field',
      field: 'adminPassword',
    });
    expect(classifyInstallError(apiError('db_unreachable'))).toMatchObject({
      kind: 'field',
      field: 'dbHost',
    });
    expect(classifyInstallError(apiError('redis_unreachable'))).toMatchObject({
      kind: 'field',
      field: 'redisHost',
    });
  });

  test('db_unreachable 用字段组专属文案（与 UploadConfig 措辞区分）', () => {
    const action = classifyInstallError(apiError('db_unreachable'));
    expect(action.kind).toBe('field');
    // zh 默认：指向地址 / 端口 / 用户名 / 密码字段组。
    expect(action.message).toContain('地址 / 端口 / 用户名 / 密码');
  });

  test('未命中字段映射的后端错误码 → toast（migration_failed / admin_missing 等）', () => {
    expect(classifyInstallError(apiError('migration_failed')).kind).toBe(
      'toast',
    );
    expect(classifyInstallError(apiError('admin_missing')).kind).toBe('toast');
    expect(classifyInstallError(apiError('unavailable')).kind).toBe('toast');
  });

  test('非 ApiError（网络层异常等）→ toast + internal 兜底文案', () => {
    const action = classifyInstallError(new Error('boom'));
    expect(action.kind).toBe('toast');
    expect(action.message.length).toBeGreaterThan(0);
  });
});

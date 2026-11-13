// 零 Semi / 零 DOM 依赖：只验 login/api.ts 的纯转换函数（Struct 口径）。
// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化后移除）。
// @ts-ignore
import { afterAll, beforeAll, describe, expect, test } from 'rstack/test';
import { create } from '@bufbuild/protobuf';
import { CaptchaPayloadSchema } from '../gen/proto/api/sso/v1/login_pb';

const BASE = 'https://uc.test';
(globalThis as { __AUTHLOFT_INIT__?: unknown }).__AUTHLOFT_INIT__ = {
  al_root: `${BASE}/`,
  static_base: '/assets/',
};

let apiMod: typeof import('./api');

beforeAll(async () => {
  apiMod = await import('./api');
});

afterAll(() => {
  (globalThis as { __AUTHLOFT_INIT__?: unknown }).__AUTHLOFT_INIT__ = undefined;
});

describe('captchaToStruct（§12.9 Struct 口径）', () => {
  test('只拷凭据字段：不含消息 $typeName 与零值 token / id / answer', () => {
    const image = create(CaptchaPayloadSchema, {
      providerKey: 'builtin_image',
      id: 'cap-1',
      answer: '1234',
    });
    const imageStruct = apiMod.captchaToStruct(image);
    expect(Object.keys(imageStruct)).not.toContain('$typeName');
    expect(imageStruct).toEqual({
      providerKey: 'builtin_image',
      id: 'cap-1',
      answer: '1234',
    });

    // token 类凭据：未使用的 id / answer 不得以零值字符串写入 Struct。
    const turnstile = create(CaptchaPayloadSchema, {
      providerKey: 'cf_turnstile',
      token: '0.xyz',
    });
    expect(apiMod.captchaToStruct(turnstile)).toEqual({
      providerKey: 'cf_turnstile',
      token: '0.xyz',
    });
  });
});

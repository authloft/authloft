// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化后移除）。
// @ts-ignore
import { afterAll, afterEach, beforeAll, describe, expect, test } from 'rstack/test';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { create, toBinary, toJson } from '@bufbuild/protobuf';
import { ErrorInfoSchema } from '../gen/proto/api/common/v1/error_info_pb';
import {
  GetStatusRequestSchema,
  RestartingResponseSchema,
} from '../gen/proto/api/setup/v1/setup_pb';
import { ApiError } from '../shared/api/errors';

/**
 * 在模块求值前注入 al_root（transport 在 ./api 模块加载时构造 baseUrl），
 * 故 ./api 经 beforeAll 动态 import（沿 shared/api http.test.ts 模式）；
 * 单测环境为 node（无 location），BASE 与 http.test.ts 取同值防跨文件竞争。
 */
const BASE = 'https://uc.test';
(globalThis as { __AUTHLOFT_INIT__?: unknown }).__AUTHLOFT_INIT__ = {
  al_root: `${BASE}/`, // 带尾斜杠：校验 baseUrl 去尾斜杠归一（§8）
};

const SETUP_GET_STATUS = `${BASE}/api.setup.v1.SetupService/GetStatus`;
const SETUP_UPLOAD_CONFIG = `${BASE}/api.setup.v1.SetupService/UploadConfig`;
const SETUP_INSTALL = `${BASE}/api.setup.v1.SetupService/Install`;

const server = setupServer();

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

async function rejectionOf(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error('expected the promise to reject');
}

let mod: typeof import('./api');

beforeAll(async () => {
  server.listen({ onUnhandledRequest: 'error' });
  mod = await import('./api');
});

afterEach(() => {
  server.resetHandlers();
});

afterAll(() => {
  server.close();
  (globalThis as { __AUTHLOFT_INIT__?: unknown }).__AUTHLOFT_INIT__ = undefined;
});

describe('setup/api fetchSetupStatus（§13.1）', () => {
  test('200 + {"mode":"setup"} → setup 模式；请求 connect 路径（空消息 + JSON）', async () => {
    let captured!: Request;
    server.use(
      http.post(SETUP_GET_STATUS, ({ request }) => {
        captured = request;
        return HttpResponse.json({ mode: 'setup' });
      }),
    );

    expect(await mod.fetchSetupStatus()).toEqual({ kind: 'setup' });

    // baseUrl 取注入 al_root（去尾斜杠归一）；GetStatusRequest 为空消息。
    expect(captured.url).toBe(SETUP_GET_STATUS);
    expect(captured.headers.get('content-type')).toBe('application/json');
    expect(await captured.json()).toEqual(toJson(GetStatusRequestSchema, create(GetStatusRequestSchema)));
  });

  test('gin 原生 404（text/plain）→ gone（§13.4：setup 路由消失 = 重启完成锚点）', async () => {
    server.use(
      http.post(SETUP_GET_STATUS, () =>
        new HttpResponse('404 page not found', {
          status: 404,
          headers: { 'content-type': 'text/plain; charset=utf-8' },
        }),
      ),
    );

    expect(await mod.fetchSetupStatus()).toEqual({ kind: 'gone' });
  });

  test('连接被拒（网络错误）→ unreachable，不 reject', async () => {
    server.use(http.post(SETUP_GET_STATUS, () => HttpResponse.error()));

    expect(await mod.fetchSetupStatus()).toEqual({ kind: 'unreachable' });
  });

  test('非 404 的非 2xx（如 500）→ unreachable，继续轮询口径', async () => {
    server.use(
      http.post(SETUP_GET_STATUS, () =>
        new HttpResponse('internal error', {
          status: 500,
          headers: { 'content-type': 'text/plain; charset=utf-8' },
        }),
      ),
    );

    expect(await mod.fetchSetupStatus()).toEqual({ kind: 'unreachable' });
  });

  test('200 但 mode 非 "setup"（零值兜底，§1.1 省略零值）→ unreachable，继续轮询口径', async () => {
    server.use(http.post(SETUP_GET_STATUS, () => HttpResponse.json({})));

    expect(await mod.fetchSetupStatus()).toEqual({ kind: 'unreachable' });
  });
});

describe('setup/api 安装请求（§13.2 / §13.3）', () => {
  test('requestInstall：载荷 protojson（camelCase + int64 十进制字符串）；成功 → 正常返回', async () => {
    let captured!: Request;
    server.use(
      http.post(SETUP_INSTALL, ({ request }) => {
        captured = request;
        return HttpResponse.json(toJson(RestartingResponseSchema, create(RestartingResponseSchema, { restarting: true })));
      }),
    );

    await mod.requestInstall({
      dbDsn: 'user:pass@tcp(127.0.0.1:3306)/authloft',
      redisAddr: '127.0.0.1:6379',
      redisPassword: 'pw',
      redisDb: 2,
      root: 'https://uc.example.com',
      rpId: 'uc.example.com',
      adminUsername: 'admin',
      adminPassword: 's3cret!',
    });

    expect(captured.url).toBe(SETUP_INSTALL);
    const body = (await captured.json()) as Record<string, unknown>;
    expect(body).toEqual({
      dbDsn: 'user:pass@tcp(127.0.0.1:3306)/authloft',
      redisAddr: '127.0.0.1:6379',
      redisPassword: 'pw',
      redisDb: '2', // int64 → 十进制字符串（§1.12）
      root: 'https://uc.example.com',
      rpId: 'uc.example.com',
      adminUsername: 'admin',
      adminPassword: 's3cret!',
    });
  });

  test('requestInstall：零值字段省略（protojson 省略零值，§1.1）', async () => {
    let captured!: Request;
    server.use(
      http.post(SETUP_INSTALL, ({ request }) => {
        captured = request;
        return HttpResponse.json({ restarting: true });
      }),
    );

    await mod.requestInstall({
      dbDsn: 'user:pass@tcp(127.0.0.1:3306)/authloft',
      redisAddr: '127.0.0.1:6379',
      redisPassword: '',
      redisDb: 0,
      root: '',
      rpId: '',
      adminUsername: 'admin',
      adminPassword: 's3cret!',
    });

    const body = (await captured.json()) as Record<string, unknown>;
    expect(body).toEqual({
      dbDsn: 'user:pass@tcp(127.0.0.1:3306)/authloft',
      redisAddr: '127.0.0.1:6379',
      adminUsername: 'admin',
      adminPassword: 's3cret!',
    });
  });

  test('requestInstall：Connect 错误体 ErrorInfo detail → ApiError（业务码 / 请求号透传）', async () => {
    const info = create(ErrorInfoSchema, {
      domain: 'setup',
      code: 'password_weak',
      message: '密码强度不足',
    });
    server.use(
      http.post(SETUP_INSTALL, () =>
        HttpResponse.json(
          {
            code: 'invalid_argument',
            message: 'install failed',
            details: [
              {
                type: 'api.common.v1.ErrorInfo',
                value: bytesToBase64(toBinary(ErrorInfoSchema, info)),
              },
            ],
          },
          { status: 400, headers: { 'x-request-id': 'req-9' } },
        ),
      ),
    );

    const error = (await rejectionOf(
      mod.requestInstall({
        dbDsn: 'user:pass@tcp(127.0.0.1:3306)/authloft',
        redisAddr: '127.0.0.1:6379',
        redisPassword: '',
        redisDb: 0,
        root: '',
        rpId: '',
        adminUsername: 'admin',
        adminPassword: 'weak',
      }),
    )) as ApiError;

    expect(error).toBeInstanceOf(ApiError);
    expect(error.code).toBe('password_weak'); // 业务码取 ErrorInfo.code（§1.5 行 226）
    expect(error.message).toBe('密码强度不足');
    expect(error.httpStatus).toBe(400);
    expect(error.requestId).toBe('req-9');
  });

  test('requestUploadConfig：请求体 {config}；成功响应 restarting:true → 正常返回', async () => {
    let captured!: Request;
    server.use(
      http.post(SETUP_UPLOAD_CONFIG, ({ request }) => {
        captured = request;
        return HttpResponse.json({ restarting: true });
      }),
    );

    await mod.requestUploadConfig('config: x');

    expect(captured.url).toBe(SETUP_UPLOAD_CONFIG);
    expect(await captured.json()).toEqual({ config: 'config: x' });
  });

  test('requestUploadConfig：Connect 错误体 → code 取自 ErrorInfo.code（config_invalid，§13.2）', async () => {
    const info = create(ErrorInfoSchema, {
      domain: 'setup',
      code: 'config_invalid',
      message: '配置文件校验失败',
    });
    server.use(
      http.post(SETUP_UPLOAD_CONFIG, () =>
        HttpResponse.json(
          {
            code: 'invalid_argument',
            message: 'upload failed',
            details: [
              {
                type: 'api.common.v1.ErrorInfo',
                value: bytesToBase64(toBinary(ErrorInfoSchema, info)),
              },
            ],
          },
          { status: 400 },
        ),
      ),
    );

    const error = (await rejectionOf(
      mod.requestUploadConfig('config: x'),
    )) as ApiError;

    expect(error).toBeInstanceOf(ApiError);
    expect(error.code).toBe('config_invalid');
    expect(error.httpStatus).toBe(400);
  });

  test('requestUploadConfig：无 detail → Connect 标准码兜底，表内码透出 message（§1.5 行 202 / 226）', async () => {
    server.use(
      http.post(SETUP_UPLOAD_CONFIG, () =>
        HttpResponse.json(
          { code: 'unavailable', message: 'upstream down' },
          { status: 503, headers: { 'x-request-id': 'req-2' } },
        ),
      ),
    );

    const error = (await rejectionOf(
      mod.requestUploadConfig('config: x'),
    )) as ApiError;

    expect(error).toBeInstanceOf(ApiError);
    expect(error.code).toBe('unavailable');
    expect(error.message).toBe('upstream down');
    expect(error.httpStatus).toBe(503);
    expect(error.requestId).toBe('req-2');
  });

  test('requestUploadConfig：未知码不透出 message 细节（data_loss 不在 CODE_TABLE）', async () => {
    server.use(
      http.post(SETUP_UPLOAD_CONFIG, () =>
        HttpResponse.json(
          { code: 'data_loss', message: 'secret detail' },
          { status: 500 },
        ),
      ),
    );

    const error = (await rejectionOf(
      mod.requestUploadConfig('config: x'),
    )) as ApiError;

    expect(error).toBeInstanceOf(ApiError);
    expect(error.code).toBe('data_loss');
    expect(error.message).toBe('');
  });

  test('requestUploadConfig：非 Connect JSON 错误响应 → 按规范映射兜底（415 → unknown，不透出原文）', async () => {
    server.use(
      http.post(SETUP_UPLOAD_CONFIG, () =>
        new HttpResponse('unsupported media type', {
          status: 415,
          headers: { 'content-type': 'text/plain; charset=utf-8' },
        }),
      ),
    );

    const error = (await rejectionOf(
      mod.requestUploadConfig('config: x'),
    )) as ApiError;

    expect(error).toBeInstanceOf(ApiError);
    // Connect 协议 HTTP-to-code 表未列 415 → Code.Unknown；归一后 httpStatus
    // 为 Code 反推的 500，原始状态不保留。
    expect(error.code).toBe('unknown');
    expect(error.message).toBe('');
    expect(error.httpStatus).toBe(500);
  });

  test('requestUploadConfig：网络错误 → ApiError（unknown，不透出原文）', async () => {
    server.use(http.post(SETUP_UPLOAD_CONFIG, () => HttpResponse.error()));

    const error = (await rejectionOf(
      mod.requestUploadConfig('config: x'),
    )) as ApiError;

    expect(error).toBeInstanceOf(ApiError);
    // connect-web 对 fetch 网络拒绝按 ConnectError.from 包装为 Code.Unknown
    //（非 AbortError 不映射 Unavailable）；归一后 httpStatus 为 Code 反推的 500。
    expect(error.code).toBe('unknown');
    expect(error.message).toBe('');
    expect(error.httpStatus).toBe(500);
  });
});

describe('setup/api setupMessage（对齐 errors.ts CODE_TABLE/未知兜底口径）', () => {
  test('§13 业务码 / Connect 标准码查表、未知码走兜底（不透出后端 message 原文）', () => {
    expect(mod.setupMessage('config_invalid')).toBe(
      '配置文件校验失败：内容不完整、非法或缺少 sign_key，请修正后重新上传',
    );
    expect(mod.setupMessage('admin_missing')).toBe(
      '版本已最新但缺少管理员账号，请改走全新安装',
    );
    expect(mod.setupMessage('unavailable')).toBe('网络错误，请稍后重试');
    expect(mod.setupMessage('totally_unknown_code')).toBe('操作失败，请检查输入后重试');
  });
});

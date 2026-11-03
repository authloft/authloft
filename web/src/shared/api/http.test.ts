// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径；
// 未改 tsconfig，故仅在测试文件放宽该 import 的类型解析。
// @ts-ignore
import { afterAll, afterEach, beforeAll, describe, expect, rs, test } from 'rstack/test';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { createClient } from '@connectrpc/connect';
import { create, fromBinary, toBinary, toJson } from '@bufbuild/protobuf';
import { ErrorInfoSchema } from '../../gen/proto/api/common/v1/error_info_pb';
import { LoginDefaultRequestSchema } from '../../gen/proto/api/sso/v1/login_pb';
import { LoginFlowResponseSchema } from '../../gen/proto/api/sso/v1/envelope_pb';
import { SsoService } from '../../gen/proto/api/sso/v1/sso_pb';
import { ApiError } from './errors';

/**
 * 在模块求值前注入 al_root（transport 单例在 ./http 模块加载时构造 baseUrl），
 * 故 ./http 经 beforeAll 动态 import；单测环境为 node（无 location）。
 */
const BASE = 'https://uc.test';
(globalThis as { __AUTHLOFT_INIT__?: unknown }).__AUTHLOFT_INIT__ = {
  al_root: `${BASE}/`,
};

const SSO_LOGIN_DEFAULT = `${BASE}/api.sso.v1.SsoService/LoginDefault`;

const loginRequest = create(LoginDefaultRequestSchema, {
  loginToken: 'tok-0',
  method: 'password',
  payload: { username: 'alice', password: 'pw' },
});

const flowResponse = create(LoginFlowResponseSchema, {
  loginToken: 'tok-1',
  status: 'next',
  userId: BigInt(60),
  redirectTo: '/home',
  nextStep: { kind: 'form', method: 'password', retryAfter: BigInt(30) },
});

const server = setupServer();

/** 极简 XHR 桩（复用；send 同步回放 nextResponse，补 upload progress 回放）。 */
class FakeXhr {
  static nextResponse: { status: number; body: string } | null = null;

  static respondWith(status: number, body: string): void {
    FakeXhr.nextResponse = { status, body };
  }

  onabort: (() => void) | null = null;
  ontimeout: (() => void) | null = null;
  onerror: (() => void) | null = null;
  onload: (() => void) | null = null;
  upload: { onprogress: ((event: unknown) => void) | null } = {
    onprogress: null,
  };
  withCredentials = false;
  timeout = 0;
  status = 0;
  statusText = '';
  responseText = '';

  getResponseHeader(_name: string): string | null {
    return null;
  }

  abort(): void {
    this.onabort?.();
  }

  open(_method: string, _url: string): void {}

  send(_formData: FormData): void {
    this.upload.onprogress?.({ loaded: 1, total: 2, lengthComputable: true });
    const response = FakeXhr.nextResponse;
    if (!response) {
      this.onerror?.();
      return;
    }
    this.status = response.status;
    this.responseText = response.body;
    this.onload?.();
  }
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

async function getRejection(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error('expected the promise to reject');
}

let mod: typeof import('./http');

beforeAll(async () => {
  server.listen({ onUnhandledRequest: 'error' });
  mod = await import('./http');
});

afterEach(() => {
  server.resetHandlers();
  FakeXhr.nextResponse = null;
  rs.unstubAllGlobals();
});

afterAll(() => {
  server.close();
  (globalThis as { __AUTHLOFT_INIT__?: unknown }).__AUTHLOFT_INIT__ = undefined;
});

describe('shared/api/http transport/client（Connect 协议，§8.2 A ①②③⑤）', () => {
  test('JSON 往返：请求体 camelCase + 省略零值，响应按生成消息解码（int64 → bigint）', async () => {
    let captured!: Request;
    server.use(
      http.post(SSO_LOGIN_DEFAULT, ({ request }) => {
        captured = request;
        return HttpResponse.json(toJson(LoginFlowResponseSchema, flowResponse));
      }),
    );

    const client = createClient(
      SsoService,
      mod.createAuthloftTransport({ baseUrl: BASE }),
    );
    const result = await client.loginDefault(loginRequest);

    expect(captured.url).toBe(SSO_LOGIN_DEFAULT);
    expect(captured.headers.get('content-type')).toBe('application/json');
    expect(captured.credentials).toBe('include');

    const body = (await captured.json()) as Record<string, unknown>;
    expect(body.loginToken).toBe('tok-0');
    expect(body.payload).toEqual({ username: 'alice', password: 'pw' });
    expect(body).not.toHaveProperty('login_token');
    expect(body).not.toHaveProperty('step'); // 省略零值（§1.1）

    expect(result.loginToken).toBe('tok-1');
    expect(result.status).toBe('next');
    expect(result.userId).toBe(BigInt(60)); // int64 十进制字符串解码（§1.12）
    expect(result.redirectTo).toBe('/home');
    expect(result.nextStep?.retryAfter).toBe(BigInt(30));
  });

  test('二进制往返：Content-Type application/proto，请求 / 响应字节按生成消息编解码', async () => {
    let captured!: Request;
    server.use(
      http.post(SSO_LOGIN_DEFAULT, ({ request }) => {
        captured = request;
        return new HttpResponse(toBinary(LoginFlowResponseSchema, flowResponse), {
          headers: { 'content-type': 'application/proto' },
        });
      }),
    );

    const client = createClient(
      SsoService,
      mod.createAuthloftTransport({ baseUrl: BASE, useBinaryFormat: true }),
    );
    const result = await client.loginDefault(loginRequest);

    expect(captured.headers.get('content-type')).toBe('application/proto');
    const bytes = new Uint8Array(await captured.arrayBuffer());
    expect(fromBinary(LoginDefaultRequestSchema, bytes)).toEqual(loginRequest);
    expect(result).toEqual(flowResponse);
  });

  test('非 2xx Connect 错误体：ErrorInfo detail 解出业务码与 retryAfter / attemptsLeft（§1.5 行 199-221）', async () => {
    const info = create(ErrorInfoSchema, {
      domain: 'sso',
      code: 'too_many_attempts',
      message: '尝试次数超限',
      retryAfter: BigInt(60),
      attemptsLeft: BigInt(2),
    });
    server.use(
      http.post(SSO_LOGIN_DEFAULT, () =>
        HttpResponse.json(
          {
            code: 'resource_exhausted',
            message: 'rate limited',
            details: [
              {
                type: 'api.common.v1.ErrorInfo',
                value: bytesToBase64(toBinary(ErrorInfoSchema, info)),
              },
            ],
          },
          { status: 429, headers: { 'x-request-id': 'req-1' } },
        ),
      ),
    );

    const client = createClient(
      SsoService,
      mod.createAuthloftTransport({ baseUrl: BASE }),
    );
    const error = (await getRejection(client.loginDefault(loginRequest))) as ApiError;

    expect(error).toBeInstanceOf(ApiError);
    expect(error.code).toBe('too_many_attempts'); // 业务码取 ErrorInfo.code（行 226）
    expect(error.message).toBe('尝试次数超限');
    expect(error.httpStatus).toBe(429);
    expect(error.requestId).toBe('req-1');
    expect(error.retryAfter).toBe(BigInt(60));
    expect(error.attemptsLeft).toBe(BigInt(2));
  });

  test('无 detail：按 Connect 标准码兜底，表内码透出 message（§1.5 行 202 / 226）', async () => {
    server.use(
      http.post(SSO_LOGIN_DEFAULT, () =>
        HttpResponse.json(
          { code: 'unavailable', message: 'upstream down' },
          { status: 503, headers: { 'x-request-id': 'req-2' } },
        ),
      ),
    );

    const client = createClient(
      SsoService,
      mod.createAuthloftTransport({ baseUrl: BASE }),
    );
    const error = (await getRejection(client.loginDefault(loginRequest))) as ApiError;

    expect(error).toBeInstanceOf(ApiError);
    expect(error.code).toBe('unavailable');
    expect(error.httpStatus).toBe(503);
    expect(error.requestId).toBe('req-2');
    expect(error.message).toBe('upstream down');
  });

  test('未知码不透出 message 细节（data_loss 不在 CODE_TABLE）', async () => {
    server.use(
      http.post(SSO_LOGIN_DEFAULT, () =>
        HttpResponse.json(
          { code: 'data_loss', message: 'secret detail' },
          { status: 500 },
        ),
      ),
    );

    const client = createClient(
      SsoService,
      mod.createAuthloftTransport({ baseUrl: BASE }),
    );
    const error = (await getRejection(client.loginDefault(loginRequest))) as ApiError;

    expect(error).toBeInstanceOf(ApiError);
    expect(error.code).toBe('data_loss');
    expect(error.message).toBe('');
  });

  test('默认超时中断：归一为 deadline_exceeded（§8.2 A ④）', async () => {
    server.use(
      http.post(
        SSO_LOGIN_DEFAULT,
        (): Promise<Response> => new Promise(() => {}),
      ),
    );

    const client = createClient(
      SsoService,
      mod.createAuthloftTransport({ baseUrl: BASE, defaultTimeoutMs: 40 }),
    );
    const error = (await getRejection(client.loginDefault(loginRequest))) as ApiError;

    expect(error).toBeInstanceOf(ApiError);
    expect(error.code).toBe('deadline_exceeded');
    expect(error.httpStatus).toBe(504);
  });

  test('外部 AbortController 中断：归一为 canceled（§8.2 A ④）', async () => {
    server.use(
      http.post(
        SSO_LOGIN_DEFAULT,
        (): Promise<Response> => new Promise(() => {}),
      ),
    );

    const client = createClient(
      SsoService,
      mod.createAuthloftTransport({ baseUrl: BASE, defaultTimeoutMs: 5_000 }),
    );
    const controller = new AbortController();
    const pending = client.loginDefault(loginRequest, {
      signal: controller.signal,
    });
    controller.abort();

    const error = (await getRejection(pending)) as ApiError;
    expect(error).toBeInstanceOf(ApiError);
    expect(error.code).toBe('canceled');
  });

  test('transport 单例：baseUrl 取注入 al_root（去尾斜杠归一，接口文档 §8）', async () => {
    server.use(
      http.post(SSO_LOGIN_DEFAULT, ({ request }) => {
        expect(request.url).toBe(SSO_LOGIN_DEFAULT);
        return HttpResponse.json(toJson(LoginFlowResponseSchema, flowResponse));
      }),
    );

    const result = await mod.ssoClient.loginDefault(loginRequest);
    expect(result.status).toBe('next');
  });
});

describe('shared/api/http postForm（multipart，REST 豁免，§3.1）', () => {
  test('2xx + res：JSON 解码为生成消息；onUploadProgress 收到 XHR upload 事件', async () => {
    rs.stubGlobal('XMLHttpRequest', FakeXhr);
    FakeXhr.respondWith(
      200,
      JSON.stringify(toJson(LoginFlowResponseSchema, flowResponse)),
    );

    const progress: Array<{ loaded: number; total: number }> = [];
    const result = await mod.postForm('/api/account/avatar', new FormData(), {
      res: LoginFlowResponseSchema,
      onUploadProgress: (p) => progress.push(p),
    });

    expect(result.status).toBe('next');
    expect(result.userId).toBe(BigInt(60));
    expect(progress).toEqual([{ loaded: 1, total: 2 }]);
  });

  test('2xx 无 res：返回解析后的 JSON', async () => {
    rs.stubGlobal('XMLHttpRequest', FakeXhr);
    FakeXhr.respondWith(200, '{"ok":true}');

    const result = (await mod.postForm('/upload', new FormData())) as {
      ok: boolean;
    };
    expect(result.ok).toBe(true);
  });

  test('非 200 Connect 错误体：details 的 ErrorInfo（base64）优先归一（§1.5 行 203-209）', async () => {
    rs.stubGlobal('XMLHttpRequest', FakeXhr);
    const info = create(ErrorInfoSchema, {
      domain: 'account',
      code: 'file_too_large',
      message: '文件超限',
      retryAfter: BigInt(30),
    });
    FakeXhr.respondWith(
      413,
      JSON.stringify({
        code: 'invalid_argument',
        message: 'payload too large',
        details: [
          {
            type: 'api.common.v1.ErrorInfo',
            value: bytesToBase64(toBinary(ErrorInfoSchema, info)),
          },
        ],
      }),
    );

    const error = (await getRejection(
      mod.postForm('/api/account/avatar', new FormData()),
    )) as ApiError;

    expect(error).toBeInstanceOf(ApiError);
    expect(error.code).toBe('file_too_large');
    expect(error.message).toBe('文件超限');
    expect(error.httpStatus).toBe(413);
    expect(error.retryAfter).toBe(BigInt(30));
  });

  test('非 200 非 Connect 错误体：按 HTTP 状态映射 Connect 标准码兜底（§1.5 行 184-193）', async () => {
    rs.stubGlobal('XMLHttpRequest', FakeXhr);
    FakeXhr.respondWith(503, '{"oops":1}');

    const error = (await getRejection(
      mod.postForm('/api/account/avatar', new FormData()),
    )) as ApiError;

    expect(error).toBeInstanceOf(ApiError);
    expect(error.code).toBe('unavailable');
    expect(error.httpStatus).toBe(503);
    expect(error.message).toBe(''); // 兜底码场景不透出原文
  });
});

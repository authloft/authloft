import { create, fromBinary, toBinary, toJson } from '@bufbuild/protobuf';
// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径；
// 本卡禁止改 tsconfig，故仅在测试文件放宽该 import 的类型解析。
// @ts-ignore
import { afterEach, describe, expect, rs, test } from 'rstack/test';
import { ErrorEnvelopeSchema } from '../../gen/proto/api/common/response_pb';
import { EnvelopeSchema } from '../../gen/proto/api/sso/envelope_pb';
import { postForm, request } from './http';
import { ApiError } from './errors';
import type { Endpoint } from './endpoints';

type EnvelopeEndpoint = Endpoint<
  typeof EnvelopeSchema,
  typeof EnvelopeSchema
>;

const sample = create(EnvelopeSchema, {
  loginToken: 'tok-1',
  status: 'next',
  userId: BigInt(60),
  redirectTo: '/home',
  nextStep: {
    kind: 'form',
    method: 'password',
    retryAfter: BigInt(30),
  },
});

/** §1.0 错误信封样例（非 200 框架拒绝）：{"status":"error","error":{code,message,request_id}}。 */
const errorEnvelope = create(ErrorEnvelopeSchema, {
  status: 'error',
  error: { code: 'unauthorized', message: 'no session', requestId: 'req-1' },
});

/** §1.0 业务失败信封样例（HTTP 200）：error.code 为 §1.6 业务词（开放非六元）。 */
const businessErrorEnvelope = create(ErrorEnvelopeSchema, {
  status: 'error',
  error: {
    code: 'password_weak',
    message: '密码强度不足',
    requestId: 'req-biz-1',
  },
});

function envelopeEndpoint(format: 'json' | 'binary'): EnvelopeEndpoint {
  return {
    path: '/api/test/envelope',
    method: 'POST',
    req: EnvelopeSchema,
    res: EnvelopeSchema,
    format,
  };
}

function stubFetch(
  handler: (url: string, init: RequestInit) => Response | Promise<Response>,
): Array<{ url: string; init: RequestInit }> {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const stub = (input: RequestInfo | URL, init?: RequestInit) => {
    const resolved = init ?? {};
    calls.push({ url: String(input), init: resolved });
    return Promise.resolve(handler(String(input), resolved));
  };
  rs.stubGlobal('fetch', stub);
  return calls;
}

function jsonEnvelopeResponse(): Response {
  const json = toJson(EnvelopeSchema, sample, {
    alwaysEmitImplicit: true,
    useProtoFieldName: true,
  });
  return new Response(JSON.stringify(json), {
    status: 200,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });
}

function binaryEnvelopeResponse(): Response {
  return new Response(toBinary(EnvelopeSchema, sample), {
    status: 200,
    headers: { 'content-type': 'application/octet-stream' },
  });
}

/** 2xx + 指定顶层 status 的 sso 流程态响应（§1.3）：http 层不得拦截。 */
function jsonFlowStatusResponse(status: string): Response {
  const json = toJson(EnvelopeSchema, sample, {
    alwaysEmitImplicit: true,
    useProtoFieldName: true,
  }) as Record<string, unknown>;
  return new Response(JSON.stringify({ ...json, status }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

/** 2xx / 非 2xx 的统一错误信封响应（§1.0 / §1.5，error 嵌套 + snake_case）。 */
function jsonErrorEnvelopeResponse(
  envelope: typeof errorEnvelope,
  status: number,
): Response {
  const raw = toJson(ErrorEnvelopeSchema, envelope, {
    alwaysEmitImplicit: true,
    useProtoFieldName: true,
  });
  return new Response(JSON.stringify(raw), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

/** 极简 XHR 桩：send 同步回放 nextResponse，只覆盖 postForm 的 onload 路径。 */
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

  abort(): void {
    this.onabort?.();
  }

  open(_method: string, _url: string): void {}

  send(_formData: FormData): void {
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

function hangingResponse(init: RequestInit): Promise<Response> {
  return new Promise((_resolve, reject) => {
    const signal = init.signal;
    if (!signal) {
      return;
    }
    const onAbort = () => {
      reject(new DOMException('Aborted', 'AbortError'));
    };
    if (signal.aborted) {
      onAbort();
    } else {
      signal.addEventListener('abort', onAbort, { once: true });
    }
  });
}

async function getRejection(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error('expected the promise to reject');
}

afterEach(() => {
  FakeXhr.nextResponse = null;
  rs.unstubAllGlobals();
});

describe('shared/api/http', () => {
  test("format:'json' 对同一消息往返等价，且请求体整型为字符串、字段名为 snake_case", async () => {
    const calls = stubFetch(() => jsonEnvelopeResponse());

    const result = await request(envelopeEndpoint('json'), sample);

    const headers = calls[0].init.headers as Record<string, string>;
    const body = JSON.parse(calls[0].init.body as string) as Record<
      string,
      unknown
    >;

    expect(calls[0].init.credentials).toBe('include');
    expect(headers['Content-Type']).toBe('application/json');
    expect(headers.Accept).toBe('application/json');
    expect(body.login_token).toBe('tok-1');
    expect(body.user_id).toBe('60');
    expect(typeof body.user_id).toBe('string');
    expect(body).not.toHaveProperty('loginToken');
    expect(body).not.toHaveProperty('userId');
    // alwaysEmitImplicit（protobuf-es v2 的 emitDefaultValues）：未设置的标量也出现
    expect(body.session_id).toBe('');

    expect(result.loginToken).toBe('tok-1');
    expect(result.userId).toBe(BigInt(60));
    expect(result.redirectTo).toBe('/home');
    expect(result.nextStep?.retryAfter).toBe(BigInt(30));
  });

  test("format:'binary' 对同一消息往返等价", async () => {
    const calls = stubFetch(() => binaryEnvelopeResponse());

    const result = await request(envelopeEndpoint('binary'), sample);

    const headers = calls[0].init.headers as Record<string, string>;
    expect(headers['Content-Type']).toBe('application/octet-stream');
    expect(headers.Accept).toBe('application/octet-stream');
    expect(calls[0].init.body).toBeInstanceOf(Uint8Array);
    expect(
      fromBinary(
        EnvelopeSchema,
        calls[0].init.body as Uint8Array<ArrayBuffer>,
      ),
    ).toEqual(sample);

    expect(result).toEqual(sample);
  });

  test('Accept 只含所选编码、不含 */*', async () => {
    const jsonCalls = stubFetch(() => jsonEnvelopeResponse());
    await request(envelopeEndpoint('json'), sample);
    const jsonHeaders = jsonCalls[0].init.headers as Record<string, string>;
    expect(jsonHeaders.Accept).toBe('application/json');
    expect(JSON.stringify(jsonHeaders)).not.toContain('*/*');

    rs.unstubAllGlobals();
    const binaryCalls = stubFetch(() => binaryEnvelopeResponse());
    await request(envelopeEndpoint('binary'), sample);
    const binaryHeaders = binaryCalls[0].init.headers as Record<string, string>;
    expect(binaryHeaders.Accept).toBe('application/octet-stream');
    expect(JSON.stringify(binaryHeaders)).not.toContain('*/*');
  });

  test('响应 Content-Type 与所选编码不符时抛 ApiError（不尝试解码）', async () => {
    stubFetch(
      () =>
        new Response(JSON.stringify({ login_token: 'x' }), {
          status: 200,
          headers: { 'content-type': 'text/html; charset=utf-8' },
        }),
    );
    const jsonError = await getRejection(
      request(envelopeEndpoint('json'), sample),
    );
    expect(jsonError).toBeInstanceOf(ApiError);

    rs.unstubAllGlobals();
    stubFetch(
      () =>
        new Response('{"login_token":"x"}', {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
    );
    const binaryError = await getRejection(
      request(envelopeEndpoint('binary'), sample),
    );
    expect(binaryError).toBeInstanceOf(ApiError);
  });

  test('非 2xx（json）按统一错误信封解出 ApiError 的 code / requestId', async () => {
    stubFetch(() => jsonErrorEnvelopeResponse(errorEnvelope, 401));

    const rawError = toJson(ErrorEnvelopeSchema, errorEnvelope, {
      alwaysEmitImplicit: true,
      useProtoFieldName: true,
    }) as unknown as {
      error?: { code?: string; message?: string; request_id?: string };
    };
    expect(rawError.error?.request_id).toBe('req-1');
    expect(rawError.error).not.toHaveProperty('requestId');

    const error = await getRejection(request(envelopeEndpoint('json'), sample));
    expect(error).toBeInstanceOf(ApiError);
    const apiError = error as ApiError;
    expect(apiError.httpStatus).toBe(401);
    expect(apiError.code).toBe('unauthorized');
    expect(apiError.message).toBe('no session');
    expect(apiError.requestId).toBe('req-1');
  });

  test('非 2xx（binary）按统一错误信封解出 ApiError 的 code / requestId', async () => {
    stubFetch(
      () =>
        new Response(toBinary(ErrorEnvelopeSchema, errorEnvelope), {
          status: 401,
          headers: { 'content-type': 'application/octet-stream' },
        }),
    );

    const error = await getRejection(
      request(envelopeEndpoint('binary'), sample),
    );
    expect(error).toBeInstanceOf(ApiError);
    const apiError = error as ApiError;
    expect(apiError.httpStatus).toBe(401);
    expect(apiError.code).toBe('unauthorized');
    expect(apiError.requestId).toBe('req-1');
  });

  test('HTTP 200 内 status:"error"（json）归一 ApiError：业务码 / requestId / message 透传（§1.0 行 57）', async () => {
    stubFetch(() => jsonErrorEnvelopeResponse(businessErrorEnvelope, 200));

    const error = await getRejection(request(envelopeEndpoint('json'), sample));
    expect(error).toBeInstanceOf(ApiError);
    const apiError = error as ApiError;
    expect(apiError.httpStatus).toBe(200);
    expect(apiError.code).toBe('password_weak');
    expect(apiError.message).toBe('密码强度不足');
    expect(apiError.requestId).toBe('req-biz-1');
  });

  test('HTTP 200 流程态（next / failed）不在 http 层拦截，正常解码返回（§1.3 行 129）', async () => {
    for (const status of ['next', 'failed', 'mfa_required']) {
      rs.unstubAllGlobals();
      stubFetch(() => jsonFlowStatusResponse(status));

      const result = await request(envelopeEndpoint('json'), sample);
      expect(result.status).toBe(status);
      expect(result.loginToken).toBe('tok-1');
    }
  });

  test('postForm：2xx 内 status:"error" 归一 ApiError（业务码 / requestId 透传）', async () => {
    FakeXhr.respondWith(
      200,
      JSON.stringify({
        status: 'error',
        error: {
          code: 'file_type_not_allowed',
          message: '类型不合规',
          request_id: 'req-f-1',
        },
      }),
    );
    rs.stubGlobal('XMLHttpRequest', FakeXhr);

    const error = await getRejection(
      postForm('/api/account/avatar', new FormData()),
    );
    expect(error).toBeInstanceOf(ApiError);
    const apiError = error as ApiError;
    expect(apiError.httpStatus).toBe(200);
    expect(apiError.code).toBe('file_type_not_allowed');
    expect(apiError.message).toBe('类型不合规');
    expect(apiError.requestId).toBe('req-f-1');
  });

  test('postForm：非 2xx 按统一错误信封解出 ApiError 的 code / requestId', async () => {
    FakeXhr.respondWith(
      401,
      JSON.stringify(
        toJson(ErrorEnvelopeSchema, errorEnvelope, {
          alwaysEmitImplicit: true,
          useProtoFieldName: true,
        }),
      ),
    );
    rs.stubGlobal('XMLHttpRequest', FakeXhr);

    const error = await getRejection(
      postForm('/api/account/avatar', new FormData()),
    );
    expect(error).toBeInstanceOf(ApiError);
    const apiError = error as ApiError;
    expect(apiError.httpStatus).toBe(401);
    expect(apiError.code).toBe('unauthorized');
    expect(apiError.requestId).toBe('req-1');
  });

  test('超时中断', async () => {
    stubFetch((_url, init) => hangingResponse(init));

    const error = await getRejection(
      request(envelopeEndpoint('json'), sample, { timeoutMs: 10 }),
    );

    expect(error).toBeInstanceOf(DOMException);
    expect((error as DOMException).name).toBe('AbortError');
  });

  test('外部 AbortController 中断', async () => {
    stubFetch((_url, init) => hangingResponse(init));
    const controller = new AbortController();

    const pending = request(envelopeEndpoint('json'), sample, {
      signal: controller.signal,
    });
    controller.abort();

    const error = await getRejection(pending);
    expect(error).toBeInstanceOf(DOMException);
    expect((error as DOMException).name).toBe('AbortError');
  });
});

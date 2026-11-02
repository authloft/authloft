import { create, fromBinary, toBinary, toJson } from '@bufbuild/protobuf';
// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径；
// 本卡禁止改 tsconfig，故仅在测试文件放宽该 import 的类型解析。
// @ts-ignore
import { afterEach, describe, expect, rs, test } from 'rstack/test';
import { ErrorSchema } from '../../gen/proto/api/common/error_pb';
import { EnvelopeSchema } from '../../gen/proto/api/sso/envelope_pb';
import { request } from './http';
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

const errorBody = create(ErrorSchema, {
  code: 'unauthorized',
  message: 'no session',
  requestId: 'req-1',
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

  test('非 2xx（json）解出 ApiError 的 code / requestId', async () => {
    const rawError = toJson(ErrorSchema, errorBody, {
      alwaysEmitImplicit: true,
      useProtoFieldName: true,
    });
    expect(rawError).toHaveProperty('request_id', 'req-1');
    expect(rawError).not.toHaveProperty('requestId');

    stubFetch(
      () =>
        new Response(JSON.stringify(rawError), {
          status: 401,
          headers: { 'content-type': 'application/json' },
        }),
    );

    const error = await getRejection(request(envelopeEndpoint('json'), sample));
    expect(error).toBeInstanceOf(ApiError);
    const apiError = error as ApiError;
    expect(apiError.httpStatus).toBe(401);
    expect(apiError.code).toBe('unauthorized');
    expect(apiError.requestId).toBe('req-1');
  });

  test('非 2xx（binary）解出 ApiError 的 code / requestId', async () => {
    stubFetch(
      () =>
        new Response(toBinary(ErrorSchema, errorBody), {
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

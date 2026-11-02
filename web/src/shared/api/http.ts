import {
  fromBinary,
  fromJson,
  toBinary,
  toJson,
  type DescMessage,
  type JsonValue,
  type MessageShape,
} from '@bufbuild/protobuf';
import {
  ErrorSchema,
  type Error as ApiErrorBody,
} from '../../gen/proto/api/common/error_pb';

/** 响应 / 请求编码，见 docs/接口文档.md §1.1.1。 */
export type ApiFormat = 'json' | 'binary';

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

/**
 * 端点描述（后续 endpoints.ts 的契约前置）：format 是每端点显式声明的常量，
 * 不做运行时探测（docs/前端架构.md §3.1）。
 */
export interface Endpoint<
  Req extends DescMessage = DescMessage,
  Res extends DescMessage = DescMessage,
> {
  readonly path: string;
  readonly method: HttpMethod;
  readonly req: Req;
  readonly res: Res;
  readonly format: ApiFormat;
}

export interface ApiErrorInit {
  httpStatus: number;
  code: string;
  message: string;
  requestId: string;
}

/** 非 2xx 响应与契约错误的统一错误体（docs/接口文档.md §1.5）。 */
export class ApiError extends Error {
  readonly httpStatus: number;

  readonly code: string;

  readonly requestId: string;

  constructor(init: ApiErrorInit) {
    super(init.message);
    this.name = 'ApiError';
    this.httpStatus = init.httpStatus;
    this.code = init.code;
    this.requestId = init.requestId;
  }
}

export interface RequestOptions {
  signal?: AbortSignal;
  timeoutMs?: number;
}

export interface UploadProgress {
  loaded: number;
  total: number;
}

export interface PostFormOptions<Res extends DescMessage = DescMessage> {
  /** 提供响应 schema 时，JSON 响应会被解码成生成的消息对象。 */
  res?: Res;
  onUploadProgress?: (progress: UploadProgress) => void;
  signal?: AbortSignal;
  timeoutMs?: number;
}

/** 默认超时，调用方可按端点覆盖。 */
export const DEFAULT_TIMEOUT_MS = 15_000;

const CONTENT_TYPE_MISMATCH = 'content_type_mismatch';

/**
 * 按端点的 format 序列化请求、反序列化响应。
 * 非 2xx 一律归一化为 ApiError；Content-Type 与所选编码不符时直接抛 ApiError。
 */
export async function request<
  Req extends DescMessage,
  Res extends DescMessage,
>(
  endpoint: Endpoint<Req, Res>,
  body?: MessageShape<Req>,
  options: RequestOptions = {},
): Promise<MessageShape<Res>> {
  const { format } = endpoint;
  const headers: Record<string, string> = {
    Accept: acceptFor(format),
  };

  let payload: string | Uint8Array | undefined;
  if (body !== undefined) {
    headers['Content-Type'] = contentTypeFor(format);
    payload =
      format === 'json'
        ? JSON.stringify(
            // protobuf-es v2 中 emitDefaultValues 对应 alwaysEmitImplicit。
            toJson(endpoint.req, body, {
              alwaysEmitImplicit: true,
              useProtoFieldName: true,
            }),
          )
        : toBinary(endpoint.req, body);
  }

  const response = await fetchWithTimeout(
    endpoint.path,
    {
      method: endpoint.method,
      headers,
      body: payload,
    },
    options,
  );

  if (!response.ok) {
    throw await readApiError(response, format);
  }

  assertContentType(response, format);

  if (format === 'json') {
    const text = await response.text();
    return fromJson(endpoint.res, JSON.parse(text) as JsonValue);
  }
  const bytes = new Uint8Array(await response.arrayBuffer());
  return fromBinary(endpoint.res, bytes);
}

/**
 * multipart 上传：Content-Type 不手动设置（浏览器自动带 boundary），
 * onUploadProgress 经 XHR 的 upload 事件提供。
 * 提供 options.res 时返回解码后的生成消息，否则返回解析后的 JSON。
 */
export function postForm<Res extends DescMessage>(
  url: string,
  formData: FormData,
  options: PostFormOptions<Res> & { res: Res },
): Promise<MessageShape<Res>>;
export function postForm(
  url: string,
  formData: FormData,
  options?: PostFormOptions<never>,
): Promise<JsonValue>;
export function postForm(
  url: string,
  formData: FormData,
  options: PostFormOptions = {},
): Promise<JsonValue | MessageShape<DescMessage>> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const finish = () => {
      options.signal?.removeEventListener('abort', onAbort);
    };
    const fail = (error: unknown) => {
      finish();
      reject(error);
    };
    const onAbort = () => {
      xhr.abort();
    };

    if (options.signal?.aborted) {
      reject(new DOMException('The operation was aborted', 'AbortError'));
      return;
    }

    xhr.open('POST', url);
    xhr.withCredentials = true;
    xhr.timeout = timeoutMs;
    options.signal?.addEventListener('abort', onAbort, { once: true });

    xhr.upload.onprogress = (event) => {
      options.onUploadProgress?.({
        loaded: event.loaded,
        total: event.lengthComputable ? event.total : 0,
      });
    };

    xhr.onabort = () => {
      fail(new DOMException('The operation was aborted', 'AbortError'));
    };
    xhr.ontimeout = () => {
      fail(new DOMException('The operation timed out', 'AbortError'));
    };
    xhr.onerror = () => {
      fail(
        new ApiError({
          httpStatus: 0,
          code: 'internal_error',
          message: 'network error',
          requestId: '',
        }),
      );
    };
    xhr.onload = () => {
      let parsed: JsonValue;
      try {
        parsed = JSON.parse(xhr.responseText) as JsonValue;
      } catch (error) {
        fail(error);
        return;
      }
      if (xhr.status >= 200 && xhr.status < 300) {
        finish();
        resolve(
          options.res
            ? fromJson(options.res, parsed)
            : parsed,
        );
        return;
      }
      const errorBody = parsed as Record<string, unknown>;
      fail(
        new ApiError({
          httpStatus: xhr.status,
          code:
            typeof errorBody.code === 'string' && errorBody.code
              ? errorBody.code
              : fallbackCode(xhr.status),
          message:
            typeof errorBody.message === 'string' && errorBody.message
              ? errorBody.message
              : xhr.statusText,
          requestId:
            typeof errorBody.request_id === 'string'
              ? errorBody.request_id
              : '',
        }),
      );
    };

    xhr.send(formData);
  });
}

async function fetchWithTimeout(
  input: string,
  init: RequestInit,
  options: RequestOptions,
): Promise<Response> {
  const controller = new AbortController();
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const external = options.signal;
  const onAbort = () => controller.abort();

  if (external) {
    if (external.aborted) {
      controller.abort();
    } else {
      external.addEventListener('abort', onAbort, { once: true });
    }
  }

  try {
    return await fetch(input, {
      ...init,
      credentials: 'include',
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
    external?.removeEventListener('abort', onAbort);
  }
}

function acceptFor(format: ApiFormat): string {
  return format === 'json' ? 'application/json' : 'application/octet-stream';
}

function contentTypeFor(format: ApiFormat): string {
  return format === 'json' ? 'application/json' : 'application/octet-stream';
}

function assertContentType(response: Response, format: ApiFormat): void {
  const expected = contentTypeFor(format);
  const actual = response.headers.get('content-type')?.toLowerCase() ?? '';
  if (!actual.includes(expected)) {
    throw new ApiError({
      httpStatus: response.status,
      code: CONTENT_TYPE_MISMATCH,
      message: `expected ${expected} but got ${actual || '(empty)'}`,
      requestId: response.headers.get('x-request-id') ?? '',
    });
  }
}

async function readApiError(
  response: Response,
  format: ApiFormat,
): Promise<ApiError> {
  let decoded: ApiErrorBody | undefined;
  try {
    const bytes = new Uint8Array(await response.arrayBuffer());
    decoded =
      format === 'json'
        ? fromJson(ErrorSchema, JSON.parse(new TextDecoder().decode(bytes)) as JsonValue)
        : fromBinary(ErrorSchema, bytes);
  } catch {
    decoded = undefined;
  }

  return new ApiError({
    httpStatus: response.status,
    code: decoded?.code || fallbackCode(response.status),
    message: decoded?.message || response.statusText,
    requestId: decoded?.requestId || '',
  });
}

function fallbackCode(status: number): string {
  switch (status) {
    case 400:
      return 'bad_request';
    case 401:
      return 'unauthorized';
    case 403:
      return 'forbidden';
    case 404:
      return 'not_found';
    case 415:
      return 'unsupported_media_type';
    default:
      return 'internal_error';
  }
}

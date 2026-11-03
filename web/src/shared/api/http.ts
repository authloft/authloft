import {
  fromBinary,
  fromJson,
  toBinary,
  toJson,
  type DescMessage,
  type JsonValue,
  type MessageShape,
} from '@bufbuild/protobuf';
import { ApiError } from './errors';
import type { ApiFormat, Endpoint } from './endpoints';

// sso 域 Connect 化：旧统一错误信封 ErrorEnvelope / SuccessEnvelope
//（gen/proto/api/common/response_pb.ts）已删除——非 200 错误体为 Connect 标准体 +
// api.common.v1.ErrorInfo detail（接口文档 §1.5 行 197-211），http 层的 Connect
// 错误体归一化另行重写；此处保留最小结构类型维持既有归一逻辑的可编译性，
// 后端不再产出 status:"error" 形状，解不出即走 fallbackCode 兜底（§1.5 行 226）。
interface ErrorEnvelope {
  error?: { code?: string; message?: string; requestId?: string };
}

// ApiError 与端点描述类型（ApiFormat / HttpMethod / Endpoint / ApiErrorInit）
// 已分别迁入 errors.ts / endpoints.ts；此处 re-export 保持
// 既有 import 路径兼容。
export { ApiError };
export type { ApiErrorInit } from './errors';
export type { ApiFormat, Endpoint, HttpMethod } from './endpoints';

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
 * 非 2xx 与 2xx JSON 响应体内 `status:"error"`（§1.0 业务失败）一律归一化为 ApiError；
 * Content-Type 与所选编码不符时直接抛 ApiError。
 * 登录流程域（/api/sso/**）顶层 status 是流程态（next / failed 等，§1.3），
 * 非 "error" 不在本层拦截，交业务层（reducer）分支（docs/前端架构.md §3.1）。
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
    const parsed = JSON.parse(text) as JsonValue;
    // §1.0 行 57：业务失败（HTTP 200）同为统一错误信封，error.code 为 §1.6 业务词（开放非六元）。
    const businessError = businessErrorFromJson(parsed, response.status);
    if (businessError) {
      throw businessError;
    }
    return fromJson(endpoint.res, parsed);
  }
  // TODO：binary 分支的 2xx 直接按端点消息解码（旧 SuccessEnvelope / ErrorEnvelope
  // 两步解码已随信封删除，§1.0/§1.5）；Connect 错误体归一化随 transport 重写落地。
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
        // §1.0 行 57：multipart 端点（/api/account/**）2xx 业务失败同为统一错误信封。
        const businessError = businessErrorFromJson(parsed, xhr.status);
        if (businessError) {
          fail(businessError);
          return;
        }
        finish();
        resolve(
          options.res
            ? fromJson(options.res, parsed)
            : parsed,
        );
        return;
      }
      // §1.5 行 214：非 200 响应体固定为统一错误信封（error.{code,message,request_id} 嵌套）。
      fail(
        toApiError(
          decodeErrorEnvelopeJson(parsed),
          xhr.status,
          xhr.statusText,
        ),
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

/** §1.0 行 57-58 / §1.5 行 214：统一错误信封 {"status":"error","error":{code,message,request_id}} 的形状判别。 */
function isErrorEnvelopeShaped(parsed: JsonValue): boolean {
  return (
    typeof parsed === 'object' &&
    parsed !== null &&
    !Array.isArray(parsed) &&
    (parsed as { status?: unknown }).status === 'error'
  );
}

/** 从 JSON 原文解旧错误信封（信封消息删除后改为结构判别）；非信封或结构不符返回 undefined。 */
function decodeErrorEnvelopeJson(
  parsed: JsonValue,
): ErrorEnvelope | undefined {
  if (!isErrorEnvelopeShaped(parsed)) {
    return undefined;
  }
  const { error } = parsed as { error?: unknown };
  if (typeof error !== 'object' || error === null) {
    return undefined;
  }
  const record = error as Record<string, unknown>;
  const requestId =
    typeof record.request_id === 'string'
      ? record.request_id
      : typeof record.requestId === 'string'
        ? record.requestId
        : undefined;
  return {
    error: {
      code: typeof record.code === 'string' ? record.code : undefined,
      message: typeof record.message === 'string' ? record.message : undefined,
      requestId,
    },
  };
}

/** 2xx JSON 响应体内识别 §1.0 业务失败信封 → ApiError；非信封（含 sso 流程态）返回 undefined。 */
function businessErrorFromJson(
  parsed: JsonValue,
  httpStatus: number,
): ApiError | undefined {
  if (!isErrorEnvelopeShaped(parsed)) {
    return undefined;
  }
  return toApiError(decodeErrorEnvelopeJson(parsed), httpStatus, '');
}

/** 信封 → ApiError；信封缺失 / 字段缺失时按 HTTP 状态兜底（§1.5 行 218 六元）。 */
function toApiError(
  envelope: ErrorEnvelope | undefined,
  httpStatus: number,
  fallbackMessage: string,
): ApiError {
  return new ApiError({
    httpStatus,
    code: envelope?.error?.code || fallbackCode(httpStatus),
    message: envelope?.error?.message || fallbackMessage,
    requestId: envelope?.error?.requestId || '',
  });
}

/** 非 2xx 响应体按协商编码解旧错误信封；解不出走六元兜底。
 * 旧 binary 信封分支已随 ErrorEnvelope 删除（Connect 错误体归一化另行处理），
 * binary 非 200 一律走 fallbackCode 兜底。 */
async function readApiError(
  response: Response,
  format: ApiFormat,
): Promise<ApiError> {
  let envelope: ErrorEnvelope | undefined;
  try {
    if (format === 'json') {
      const bytes = new Uint8Array(await response.arrayBuffer());
      envelope = decodeErrorEnvelopeJson(
        JSON.parse(new TextDecoder().decode(bytes)) as JsonValue,
      );
    }
  } catch {
    envelope = undefined;
  }

  return toApiError(envelope, response.status, response.statusText);
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

/**
 * transport 单例 + 生成的 service client 构造 + multipart 上传（docs/前端架构.md §3.1）。
 *
 * - Connect 协议：POST <al_root>/<package>.<Service>/<Method>（接口文档 §12.9）；标准
 *   protojson——lowerCamelCase、省略零值、int64 十进制字符串（接口文档 §1.1），
 *   不注自定义 codec；业务代码对缺失字段按零值兜底（§9 第 18 条）。
 * - 错误归一（§3.1「transport 与错误归一」）：非 2xx 由 connect-es 抛 ConnectError →
 *   findDetails(api.common.v1.ErrorInfo) 解出 {domain, code, message, retryAfter,
 *   attemptsLeft} → 抛 ApiError；captcha 失败时 details 并列的
 *   api.common.v1.CaptchaConfig 一并解出挂 ApiError.captcha（§1.5 行 228、§2.5）；
 *   无（有效）detail 时按 Connect 标准码兜底（接口文档
 *   §1.5 行 226），未知码不透出 message 细节。登录流程域 200 的流程
 *   status 分支走业务层（reducer），不在 transport 拦截。
 * - multipart（REST 豁免端点，不用 transport）仍走 postForm：XHR 进度 + 同口径错误归一。
 */
import {
  Code,
  ConnectError,
  createClient,
  type Transport,
} from '@connectrpc/connect';
import { createConnectTransport } from '@connectrpc/connect-web';
import {
  fromBinary,
  fromJson,
  type DescMessage,
  type JsonValue,
  type MessageShape,
} from '@bufbuild/protobuf';
import { ErrorInfoSchema } from '../../gen/proto/api/common/v1/error_info_pb';
import {
  CaptchaConfigSchema,
  type CaptchaConfig,
} from '../../gen/proto/api/common/v1/captcha_pb';
import { SsoService } from '../../gen/proto/api/sso/v1/sso_pb';
import { AccountService } from '../../gen/proto/api/account/v1/account_pb';
import { AdminService } from '../../gen/proto/api/admin/v1/admin_pb';
import { UserService } from '../../gen/proto/api/rpc/v1/user_pb';
import { TokenService } from '../../gen/proto/api/rpc/v1/token_pb';
import { SetupService } from '../../gen/proto/api/setup/v1/setup_pb';
import { ApiError, isKnownCode } from './errors';

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

/** transport 默认超时；单次调用可用 CallOptions.timeoutMs 覆盖。 */
export const DEFAULT_TIMEOUT_MS = 15_000;

// ---------------------------------------------------------------------------
// baseUrl（al_root 注入变量）与 credentials
// ---------------------------------------------------------------------------

/** __AUTHLOFT_INIT__ 的最小形状（接口文档 §8 白名单中的 al_root）。 */
interface RawInit {
  al_root?: unknown;
}

/**
 * al_root 取法（与 setup/bootstrap.ts 同款归一；shared 层禁止 import entry——§9 第 13 条，
 * 故内联）：string 校验 → 去尾斜杠；缺省回落当前站点源；非浏览器环境（单测 node）为空串。
 */
function resolveBaseUrl(): string {
  const raw = (globalThis as { __AUTHLOFT_INIT__?: RawInit }).__AUTHLOFT_INIT__;
  const alRoot =
    typeof raw?.al_root === 'string'
      ? raw.al_root.trim().replace(/\/+$/, '')
      : '';
  if (alRoot !== '') {
    return alRoot;
  }
  return typeof location !== 'undefined' ? location.origin : '';
}

/** credentials: 'include'（跨域携带会话 Cookie）；connect-web v2 无 credentials 选项，经注入 fetch 绑定。 */
const fetchWithCredentials: typeof globalThis.fetch = (input, init) =>
  globalThis.fetch(input, { ...init, credentials: 'include' });

// ---------------------------------------------------------------------------
// Connect Code → 字符串 / HTTP 状态（ApiError 归一取值；§1.5 行 184-193 同源）
// ---------------------------------------------------------------------------

/** Connect Code → snake_case 字符串（Connect 协议规范词表；§1.5 表取其中 8 个入 CODE_TABLE）。 */
const CODE_STRING: Readonly<Record<Code, string>> = {
  [Code.Canceled]: 'canceled',
  [Code.Unknown]: 'unknown',
  [Code.InvalidArgument]: 'invalid_argument',
  [Code.DeadlineExceeded]: 'deadline_exceeded',
  [Code.NotFound]: 'not_found',
  [Code.AlreadyExists]: 'already_exists',
  [Code.PermissionDenied]: 'permission_denied',
  [Code.ResourceExhausted]: 'resource_exhausted',
  [Code.FailedPrecondition]: 'failed_precondition',
  [Code.Aborted]: 'aborted',
  [Code.OutOfRange]: 'out_of_range',
  [Code.Unimplemented]: 'unimplemented',
  [Code.Internal]: 'internal',
  [Code.Unavailable]: 'unavailable',
  [Code.DataLoss]: 'data_loss',
  [Code.Unauthenticated]: 'unauthenticated',
};

/** Connect Code → HTTP 状态（Connect 协议规范映射，与 §1.5 行 184-193 的标准码 → HTTP 列一致）。 */
const CODE_HTTP_STATUS: Readonly<Record<Code, number>> = {
  [Code.Canceled]: 499,
  [Code.Unknown]: 500,
  [Code.InvalidArgument]: 400,
  [Code.DeadlineExceeded]: 504,
  [Code.NotFound]: 404,
  [Code.AlreadyExists]: 409,
  [Code.PermissionDenied]: 403,
  [Code.ResourceExhausted]: 429,
  [Code.FailedPrecondition]: 400,
  [Code.Aborted]: 409,
  [Code.OutOfRange]: 400,
  [Code.Unimplemented]: 501,
  [Code.Internal]: 500,
  [Code.Unavailable]: 503,
  [Code.DataLoss]: 500,
  [Code.Unauthenticated]: 401,
};

// ---------------------------------------------------------------------------
// 错误归一：ConnectError → ApiError（§3.1）
// ---------------------------------------------------------------------------

/** §1.5 行 223：request_id 不在错误体内，统一走 X-Request-Id 响应头（ConnectError.metadata 汇集 headers + trailers）。 */
function requestIdFrom(metadata: Headers): string {
  return metadata.get('x-request-id') ?? '';
}

/**
 * ConnectError → ApiError（§3.1「transport 与错误归一」）：
 * findDetails 解 api.common.v1.ErrorInfo（§1.5 行 199-221）——业务码取 ErrorInfo.code、
 * 展示兜底取 ErrorInfo.message（行 202 / 219：i18n 优先，其次本字段）、retryAfter /
 * attemptsLeft 透传；captcha 失败时 details 并列的 api.common.v1.CaptchaConfig
 * 一并解出挂在 ApiError.captcha（§1.5 行 228、§2.5），供弹窗按权威配置渲染。
 * 无（有效）detail 按 Connect 标准码兜底（行 226），其 message 仅在
 * 标准码属于 CODE_TABLE 封闭集时透出（行 202「其次本字段」），未知码不透出。
 */
function toApiError(error: unknown): unknown {
  if (!(error instanceof ConnectError)) {
    return error;
  }
  const [info] = error.findDetails(ErrorInfoSchema);
  const [captcha] = error.findDetails(CaptchaConfigSchema);
  if (info !== undefined && info.code !== '') {
    return new ApiError({
      httpStatus: CODE_HTTP_STATUS[error.code],
      code: info.code,
      message: info.message,
      requestId: requestIdFrom(error.metadata),
      retryAfter: info.retryAfter,
      attemptsLeft: info.attemptsLeft,
      captcha,
    });
  }
  const standardCode = CODE_STRING[error.code];
  return new ApiError({
    httpStatus: CODE_HTTP_STATUS[error.code],
    code: standardCode,
    message: isKnownCode(standardCode) ? error.rawMessage : '',
    requestId: requestIdFrom(error.metadata),
    captcha,
  });
}

/**
 * transport 外层错误归一（§3.1）：所有经 transport 的失败统一 ConnectError → ApiError。
 * 不用 interceptor 实现——connect-es 的 runUnaryCall 会把 interceptor 抛出的错误
 * 重新包成 ConnectError（abort 处理器强制 ConnectError.from），归一会被覆盖；
 * 包在 transport 之外则处于该机制下游，超时（deadline_exceeded）与外部中断
 * （canceled）的 ConnectError 也一并归一。
 * 本工程 5 个 service 的方法全部 unary（§12.9）；stream 透传不归一，若后续引入
 * 流式方法需在其消息迭代层扩展归一。
 */
function withErrorNormalization(base: Transport): Transport {
  return {
    unary: async (...args) => {
      try {
        return await base.unary(...args);
      } catch (error) {
        throw toApiError(error);
      }
    },
    stream: (...args) => base.stream(...args),
  };
}

// ---------------------------------------------------------------------------
// transport 工厂 + 单例 + service client（§3.1：transport 与 client 只在本文件构造）
// ---------------------------------------------------------------------------

export interface AuthloftTransportOptions {
  /** 缺省取注入变量 al_root（接口文档 §8）→ location.origin。 */
  baseUrl?: string;
  /** Connect 二进制编码（application/proto）；缺省 JSON（标准 protojson）。 */
  useBinaryFormat?: boolean;
  /** 默认超时；单次调用 CallOptions.timeoutMs 覆盖。 */
  defaultTimeoutMs?: number;
}

/** 构造 Connect transport：标准 protojson（不注自定义 codec）、错误归一、credentials include、默认超时。 */
export function createAuthloftTransport(
  options: AuthloftTransportOptions = {},
): Transport {
  return withErrorNormalization(
    createConnectTransport({
      baseUrl: options.baseUrl ?? resolveBaseUrl(),
      useBinaryFormat: options.useBinaryFormat ?? false,
      defaultTimeoutMs: options.defaultTimeoutMs ?? DEFAULT_TIMEOUT_MS,
      fetch: fetchWithCredentials,
    }),
  );
}

/** transport 单例（§3.1 / §9 第 5、16 条：所有发往本系统的请求经此构造）。 */
export const transport: Transport = createAuthloftTransport();

/** service client（api.{sso,account,admin,rpc,setup}.v1，接口文档 §0 / §12.9）：薄封装，业务经 client.<method>(req, options?) 调用。 */
export const ssoClient = createClient(SsoService, transport);
export const accountClient = createClient(AccountService, transport);
export const adminClient = createClient(AdminService, transport);
export const userClient = createClient(UserService, transport);
export const tokenClient = createClient(TokenService, transport);
export const setupClient = createClient(SetupService, transport);

// ---------------------------------------------------------------------------
// multipart 上传（REST 豁免端点，不用 transport；§3.1 / §9 第 5 条）
// ---------------------------------------------------------------------------

/**
 * multipart 上传：Content-Type 不手动设置（浏览器自动带 boundary），
 * onUploadProgress 经 XHR 的 upload 事件提供。
 * 提供 options.res 时返回解码后的生成消息，否则返回解析后的 JSON。
 * 非 200 按 Connect 错误体归一（§1.5 行 197-211）：details 的 ErrorInfo 优先，
 * 解不出错误体时按 HTTP 状态映射 Connect 标准码兜底（行 184-193）。
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
      // 网络不可达按 §1.5 行 193 unavailable（服务不可用）归一；不透出细节。
      fail(
        new ApiError({
          httpStatus: 0,
          code: 'unavailable',
          message: '',
          requestId: '',
        }),
      );
    };
    xhr.onload = () => {
      let parsed: JsonValue | undefined;
      try {
        parsed = JSON.parse(xhr.responseText) as JsonValue;
      } catch (error) {
        fail(error);
        return;
      }
      if (xhr.status >= 200 && xhr.status < 300) {
        // §1.0：成功响应即消息本身，无业务失败信封；流程态分支归业务层。
        finish();
        resolve(options.res ? fromJson(options.res, parsed) : parsed);
        return;
      }
      fail(
        connectBodyToApiError(
          parsed,
          xhr.status,
          xhr.getResponseHeader('x-request-id') ?? '',
        ),
      );
    };

    xhr.send(formData);
  });
}

/** Connect 错误体 JSON 的最小形状（§1.5 行 199-211）。 */
interface ConnectErrorBody {
  code?: unknown;
  message?: unknown;
  details?: unknown;
}

/**
 * XHR 路径的 Connect 错误体 → ApiError（不经过 connect-es，手动同口径归一）：
 * details 的 api.common.v1.ErrorInfo 优先（§1.5 行 203-209）；captcha 失败时
 * 并列的 api.common.v1.CaptchaConfig 一并解出（§1.5 行 228）。无有效 detail 时
 * code 取错误体顶层 code（缺省按 HTTP 状态映射，行 184-193），message 仅在
 * code 属于 CODE_TABLE 封闭集时透出（行 202），未知码不透出。
 */
function connectBodyToApiError(
  parsed: JsonValue | undefined,
  httpStatus: number,
  requestId: string,
): ApiError {
  let body: ConnectErrorBody | undefined;
  if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
    const record = parsed as Record<string, unknown>;
    body = {
      code: record.code,
      message: record.message,
      details: record.details,
    };
  }
  const info = body !== undefined ? errorInfoFromBody(body) : undefined;
  const captcha = body !== undefined ? captchaConfigFromBody(body) : undefined;
  if (info !== undefined && info.code !== '') {
    return new ApiError({
      httpStatus,
      code: info.code,
      message: info.message,
      requestId,
      retryAfter: info.retryAfter,
      attemptsLeft: info.attemptsLeft,
      captcha,
    });
  }
  const code =
    typeof body?.code === 'string' && body.code !== ''
      ? body.code
      : httpFallbackCode(httpStatus);
  const message =
    typeof body?.message === 'string' && isKnownCode(code) ? body.message : '';
  return new ApiError({ httpStatus, code, message, requestId, captcha });
}

/**
 * 从 Connect 错误体 details 解 api.common.v1.ErrorInfo（§1.5 行 203-209：
 * type 匹配、value 为 base64 的 Protobuf 字节，消费方以 value 解码为准；
 * 解码失败视同无 detail）。
 */
function errorInfoFromBody(
  body: ConnectErrorBody,
): ReturnType<typeof fromBinary<typeof ErrorInfoSchema>> | undefined {
  if (!Array.isArray(body.details)) {
    return undefined;
  }
  for (const detail of body.details) {
    if (typeof detail !== 'object' || detail === null) {
      continue;
    }
    const { type, value } = detail as { type?: unknown; value?: unknown };
    if (type !== 'api.common.v1.ErrorInfo' || typeof value !== 'string') {
      continue;
    }
    try {
      return fromBinary(ErrorInfoSchema, base64ToBytes(value));
    } catch {
      // §1.5 行 207：以 value 解码为准，解不出视同无 detail。
    }
  }
  return undefined;
}

/**
 * 从 Connect 错误体 details 解 captcha 失败并列的 api.common.v1.CaptchaConfig
 * （§1.5 行 228、§2.5：type 匹配、value 为 base64 的 Protobuf 字节；解不出视同未携带）。
 */
function captchaConfigFromBody(
  body: ConnectErrorBody,
): CaptchaConfig | undefined {
  if (!Array.isArray(body.details)) {
    return undefined;
  }
  for (const detail of body.details) {
    if (typeof detail !== 'object' || detail === null) {
      continue;
    }
    const { type, value } = detail as { type?: unknown; value?: unknown };
    if (type !== 'api.common.v1.CaptchaConfig' || typeof value !== 'string') {
      continue;
    }
    try {
      return fromBinary(CaptchaConfigSchema, base64ToBytes(value));
    } catch {
      // 以 value 解码为准，解不出视同未携带。
    }
  }
  return undefined;
}

/** base64 → Protobuf 字节（details.value 的解码）。 */
function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/** HTTP 状态 → Connect 标准码（§1.5 行 184-193 反查；未列状态归 internal）。 */
function httpFallbackCode(status: number): string {
  switch (status) {
    case 400:
      return 'invalid_argument';
    case 401:
      return 'unauthenticated';
    case 403:
      return 'permission_denied';
    case 404:
      return 'not_found';
    case 409:
      return 'already_exists';
    case 429:
      return 'resource_exhausted';
    case 503:
      return 'unavailable';
    default:
      return 'internal';
  }
}

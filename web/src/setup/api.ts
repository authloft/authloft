/**
 * /api/setup/** 极简 JSON 封装（docs/前端架构.md §6b / §1.3：**不依赖 shared/api**
 * ——那是业务契约封装（codec 协商 / proto 编解码），安装态无 codec 协商）。
 * 错误按接口文档 §1.0 统一错误信封（error.code）归一，口径对齐
 * shared/api/{http,errors}.ts：HTTP 200 内 `status:"error"` 归一 SetupError；
 * 业务码查表、未知走兜底；非 2xx 解不出信封时按 §1.5 六元兜底。
 * 接口契约：docs/接口文档.md §13（端点 / 字段 / 错误码 / 重启轮询）。
 */

/** 与 shared/api ApiError 同形的统一错误体（§1.0 / §1.5）。 */
export interface SetupErrorInit {
  httpStatus: number;
  code: string;
  message: string;
  requestId: string;
}

export class SetupError extends Error {
  readonly httpStatus: number;

  readonly code: string;

  readonly requestId: string;

  constructor(init: SetupErrorInit) {
    super(init.message);
    this.name = 'SetupError';
    this.httpStatus = init.httpStatus;
    this.code = init.code;
    this.requestId = init.requestId;
  }
}

/** POST /api/setup/install 请求体（§13.3；字段名按契约 snake_case 序列化）。 */
export interface InstallPayload {
  dbDsn: string;
  redisAddr: string;
  redisPassword: string;
  redisDb: number;
  root: string;
  rpId: string;
  adminUsername: string;
  adminPassword: string;
}

/** GET /api/setup/status 的探测结果（§13.1 / §13.4）。 */
export type SetupStatusResult =
  /** 200 + `{"status":"success","mode":"setup"}`：仍处于 setup 模式。 */
  | { kind: 'setup' }
  /** 404：setup 路由消失 → 已进入正常模式（重启完成锚点）。 */
  | { kind: 'gone' }
  /** 连接被拒 / 超时 / 其他异常响应：视为「服务未恢复」。 */
  | { kind: 'unreachable' };

/** 探测超时（§13.4「连接被拒 / 超时」口径：超时按未恢复处理）。 */
const STATUS_TIMEOUT_MS = 15_000;
/**
 * 安装 POST 超时：setup server 写超时 30s（后端架构 §3.15），
 * 前端留 5s 余量，避免先于服务端断开。
 */
const POST_TIMEOUT_MS = 35_000;

/**
 * 探测 /api/setup/status（§13.1）。本函数**不 reject**：
 * 连接被拒 / 超时 / 非 404 异常一律归 `{kind:'unreachable'}`，供轮询继续。
 */
export async function fetchSetupStatus(): Promise<SetupStatusResult> {
  let response: Response;
  try {
    response = await fetchWithTimeout(
      '/api/setup/status',
      { headers: { Accept: 'application/json' } },
      STATUS_TIMEOUT_MS,
    );
  } catch {
    return { kind: 'unreachable' };
  }
  // §13.4：返回 404（setup 路由消失）→ 已进入正常模式。
  if (response.status === 404) {
    return { kind: 'gone' };
  }
  if (!response.ok) {
    return { kind: 'unreachable' };
  }
  try {
    const parsed = (await response.json()) as { status?: unknown; mode?: unknown };
    if (parsed.status === 'success' && parsed.mode === 'setup') {
      return { kind: 'setup' };
    }
  } catch {
    // 非 JSON 响应按未恢复处理，继续轮询。
  }
  return { kind: 'unreachable' };
}

/** POST /api/setup/config（§13.2）：上传已有 config.yaml 全文。 */
export async function requestUploadConfig(config: string): Promise<void> {
  await postSetup('/api/setup/config', { config });
}

/** POST /api/setup/install（§13.3）：全新安装。成功即进入重启流程（§13.4）。 */
export async function requestInstall(payload: InstallPayload): Promise<void> {
  await postSetup('/api/setup/install', {
    db_dsn: payload.dbDsn,
    redis_addr: payload.redisAddr,
    redis_password: payload.redisPassword,
    redis_db: payload.redisDb,
    root: payload.root,
    rp_id: payload.rpId,
    admin_username: payload.adminUsername,
    admin_password: payload.adminPassword,
  });
}

/** §13 域内业务码 + §1.5 六元框架码 → 展示文案（对齐 errors.ts CODE_TABLE 口径）。 */
const SETUP_MESSAGES: Readonly<Record<string, string>> = {
  config_invalid: '配置文件校验失败：内容不完整、非法或缺少 sign_key，请修正后重新上传',
  db_unreachable: '数据库连接失败，请检查连接串后重试',
  redis_unreachable: 'Redis 连接失败，请检查地址与密码后重试',
  migration_failed: '数据库初始化（迁移执行）失败，请检查数据库状态后重试',
  admin_missing: '版本已最新但缺少管理员账号，请改走全新安装',
  username_invalid: '管理员用户名不符合规则',
  password_weak: '密码强度不足，请更换更复杂的密码',
  bad_request: '请求参数错误',
  unauthorized: '请求未授权',
  forbidden: '请求被拒绝',
  not_found: '资源不存在',
  unsupported_media_type: '请求格式不受支持，请以 JSON 提交',
  internal_error: '服务器内部错误，请稍后重试',
};

/** 未知 code 兜底：不透出后端 error.message 原文（errors.ts 同口径）。 */
const SETUP_MESSAGE_FALLBACK = '操作失败，请检查输入后重试';

/** 位置二口径（对齐 shared/api errors.ts）：已知 code 查表，未知 code 走兜底。 */
export function setupMessage(code: string): string {
  return SETUP_MESSAGES[code] ?? SETUP_MESSAGE_FALLBACK;
}

async function postSetup(
  path: string,
  body: Record<string, unknown>,
): Promise<void> {
  let response: Response;
  try {
    response = await fetchWithTimeout(
      path,
      {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      },
      POST_TIMEOUT_MS,
    );
  } catch {
    // 连接被拒 / 超时归一为统一错误体（同 shared/api postForm 网络错误口径）。
    throw new SetupError({
      httpStatus: 0,
      code: 'internal_error',
      message: '网络错误，请稍后重试',
      requestId: '',
    });
  }
  const envelope = await readEnvelope(response);
  if (!envelope.success) {
    throw new SetupError(envelope);
  }
}

/**
 * 按 §1.0 信封读响应：2xx `status:"success"` → 成功；`status:"error"`（HTTP 200
 * 业务失败或非 2xx 框架拒绝，同一形状）→ 错误体；结构不符时非 2xx 按 §1.5
 * 六元兜底、2xx 视为 internal_error。
 */
async function readEnvelope(response: Response): Promise<SetupEnvelope> {
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    body = undefined;
  }
  if (isErrorEnvelopeShaped(body)) {
    const error = (body as { error?: Record<string, unknown> }).error ?? {};
    return {
      success: false,
      httpStatus: response.status,
      code:
        typeof error.code === 'string' && error.code !== ''
          ? error.code
          : fallbackCode(response.status),
      message: typeof error.message === 'string' ? error.message : '',
      requestId:
        typeof error.request_id === 'string' ? error.request_id : '',
    };
  }
  if (
    response.ok &&
    typeof body === 'object' &&
    body !== null &&
    (body as { status?: unknown }).status === 'success'
  ) {
    return {
      success: true,
      httpStatus: response.status,
      code: '',
      message: '',
      requestId: '',
    };
  }
  return {
    success: false,
    httpStatus: response.status,
    code: response.ok ? 'internal_error' : fallbackCode(response.status),
    message: '',
    requestId: '',
  };
}

interface SetupEnvelope extends SetupErrorInit {
  success: boolean;
}

/** §1.0 行 57-58：`{"status":"error","error":{...}}` 的形状判别。 */
function isErrorEnvelopeShaped(parsed: unknown): boolean {
  return (
    typeof parsed === 'object' &&
    parsed !== null &&
    !Array.isArray(parsed) &&
    (parsed as { status?: unknown }).status === 'error'
  );
}

/** 非 2xx 解不出信封时的 §1.5 六元兜底（与 shared/api errors 口径一致）。 */
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

async function fetchWithTimeout(
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

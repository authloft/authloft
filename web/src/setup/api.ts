/**
 * SetupService connect client 薄封装（docs/前端架构.md §6b / 接口文档 §13）。
 * transport 共用 shared/api 的 createAuthloftTransport 工厂——标准
 * protojson + ConnectError → ApiError 归一链，setup 域不重复归一；baseUrl
 * 取注入 al_root，缺省兜底 location.origin（与 bootstrap.ts normalizeAlRoot
 * 同款取法，shared resolveBaseUrl 内联实现）。
 * 接口契约：docs/接口文档.md §13（GetStatus / UploadConfig / Install / 重启轮询）。
 */
import { createClient } from '@connectrpc/connect';
import { createAuthloftTransport } from '../shared/api/http';
import { ApiError } from '../shared/api/errors';
import { SetupService } from '../gen/proto/api/setup/v1/setup_pb';

const client = createClient(SetupService, createAuthloftTransport());

/** SetupService/Install 请求体（§13.3；表单值 → proto 序列化由 connect 层完成）。 */
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

/** GET SetupService/GetStatus 的探测结果（§13.1 / §13.4）。 */
export type SetupStatusResult =
  /** 200 + `{"mode":"setup"}`：仍处于 setup 模式。 */
  | { kind: 'setup' }
  /** 404（setup 路由消失）→ 已进入正常模式（重启完成锚点）。 */
  | { kind: 'gone' }
  /** 连接被拒 / 超时 / 其他异常响应：视为「服务未恢复」。 */
  | { kind: 'unreachable' };

/**
 * 安装 POST 超时：setup server 写超时 30s（后端架构 §3.15），
 * 前端留 5s 余量，避免先于服务端断开。GetStatus 探测用 transport 默认
 * 超时 15s（shared/api DEFAULT_TIMEOUT_MS），超时按未恢复处理（§13.4）。
 */
const POST_TIMEOUT_MS = 35_000;

/**
 * 探测 SetupService/GetStatus（§13.1）。本函数**不 reject**：
 * 连接被拒 / 超时 / 非 404 异常一律归 `{kind:'unreachable'}`，供轮询继续。
 */
export async function fetchSetupStatus(): Promise<SetupStatusResult> {
  try {
    const response = await client.getStatus({});
    // §13.1：正常返回即处于 setup 模式（mode 固定 "setup"）；缺失字段按
    // 零值兜底（§9 第 18 条），非 "setup" 视为异常响应。
    return response.mode === 'setup' ? { kind: 'setup' } : { kind: 'unreachable' };
  } catch (error) {
    // §13.4：返回 404（setup 路由消失）→ 已进入正常模式。gin 原生 404 为
    // text/plain，connect-es 按 Connect 协议规范将其映射为 Code.Unimplemented
    //（HTTP-to-code 表，不读响应体），经 shared 归一链呈
    // ApiError{code:'unimplemented'}——故以 code 判定而非 httpStatus
    //（归一后 httpStatus 为 Code 反推的 501，原始 404 不再保留）。
    if (error instanceof ApiError && error.code === 'unimplemented') {
      return { kind: 'gone' };
    }
    return { kind: 'unreachable' };
  }
}

/**
 * SetupService/UploadConfig（§13.2）：上传已有 config.yaml 全文。
 * 成功响应 RestartingResponse（§1.0：成功响应即消息本身，无业务失败信封，
 * 200 即成功）。
 */
export async function requestUploadConfig(config: string): Promise<void> {
  await client.uploadConfig({ config }, { timeoutMs: POST_TIMEOUT_MS });
}

/**
 * SetupService/Install（§13.3）：全新安装。成功即进入重启流程（§13.4）。
 * 成功响应语义与 UploadConfig 一致（RestartingResponse）。
 */
export async function requestInstall(payload: InstallPayload): Promise<void> {
  await client.install(
    {
      dbDsn: payload.dbDsn,
      redisAddr: payload.redisAddr,
      redisPassword: payload.redisPassword,
      redisDb: BigInt(payload.redisDb),
      root: payload.root,
      rpId: payload.rpId,
      adminUsername: payload.adminUsername,
      adminPassword: payload.adminPassword,
    },
    { timeoutMs: POST_TIMEOUT_MS },
  );
}

/** §13 域内业务码 + §1.5 Connect 标准码（行 184-193）→ 展示文案（对齐 shared/api errors.ts CODE_TABLE 口径）。 */
const SETUP_MESSAGES: Readonly<Record<string, string>> = {
  config_invalid: '配置文件校验失败：内容不完整、非法或缺少 sign_key，请修正后重新上传',
  db_unreachable: '数据库连接失败，请检查连接串后重试',
  redis_unreachable: 'Redis 连接失败，请检查地址与密码后重试',
  migration_failed: '数据库初始化（迁移执行）失败，请检查数据库状态后重试',
  admin_missing: '版本已最新但缺少管理员账号，请改走全新安装',
  username_invalid: '管理员用户名不符合规则',
  password_weak: '密码强度不足，请更换更复杂的密码',
  invalid_argument: '请求参数错误',
  unauthenticated: '请求未授权',
  permission_denied: '请求被拒绝',
  not_found: '资源不存在',
  already_exists: '资源已存在',
  resource_exhausted: '请求过于频繁，请稍后重试',
  internal: '服务器内部错误，请稍后重试',
  unavailable: '网络错误，请稍后重试',
};

/** 未知 code 兜底：不透出后端 error.message 原文（errors.ts 同口径）。 */
const SETUP_MESSAGE_FALLBACK = '操作失败，请检查输入后重试';

/** 位置二口径（对齐 shared/api errors.ts）：已知 code 查表，未知 code 走兜底。 */
export function setupMessage(code: string): string {
  return SETUP_MESSAGES[code] ?? SETUP_MESSAGE_FALLBACK;
}

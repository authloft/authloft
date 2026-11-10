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
import { t } from '../shared/i18n';
import {
  SetupService,
  type InstallRequest,
} from '../gen/proto/api/setup/v1/setup_pb';

const client = createClient(SetupService, createAuthloftTransport());

/**
 * SetupService/Install 请求体（§13.3）：直接以生成消息 InstallRequest 的
 * 字段集为基底——proto 增删字段自动跟随，不再手抄一份会漂移的字段清单。
 * 仅两处 wire 边界适配：
 *  - Omit 掉 protobuf 运行时元数据（$typeName / $unknown，表单无从构造）；
 *  - int64 的 redisDb 由 bigint 放宽为 number（UI 层用 number），
 *    发送前在本层转 BigInt。字段仍全部必填，保留编译期漏传检查。
 */
export type InstallPayload = Omit<
  InstallRequest,
  '$typeName' | '$unknown' | 'redisDb'
> & {
  redisDb: number;
};

/** GET SetupService/GetStatus 的探测结果（§13.1 / §13.4）。 */
export type SetupStatusResult =
  /** 200 且仍处于 setup 模式（响应体 `{"mode":"setup"}`） */
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
 * 连接被拒 / 超时 / 非 404 异常一律归 kind=unreachable，供轮询继续。
 */
export async function fetchSetupStatus(): Promise<SetupStatusResult> {
  try {
    const response = await client.getStatus({});
    // §13.1：正常返回即处于 setup 模式（mode 固定为 setup）；缺失字段按
    // 零值兜底（§9 第 18 条），非 setup 视为异常响应。
    return response.mode === 'setup'
      ? { kind: 'setup' }
      : { kind: 'unreachable' };
  } catch (error) {
    // §13.4：返回 404（setup 路由消失）→ 已进入正常模式。gin 原生 404 为
    // text/plain，connect-es 按 Connect 协议规范将其映射为 Code.Unimplemented
    //（HTTP-to-code 表，不读响应体），经 shared 归一链呈
    // 故以 code 判定而非 httpStatus（归一为 ApiError{code:'unimplemented'}）
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
  // 展开生成的字段集：proto 新增字段时本层无需逐一补写。
  await client.install(
    { ...payload, redisDb: BigInt(payload.redisDb) },
    { timeoutMs: POST_TIMEOUT_MS },
  );
}

/**
 * §13 域内业务码 + §1.5 Connect 标准码（行 184-193）→ i18n 键（文案在
 * shared/i18n zh/setup.ts + en/setup.ts，用法对齐 errors.ts CODE_TABLE 的
 * i18nKey）。zh 文案与 errors.code.not_found / already_exists 逐字相同的
 * 两码直接复用既有键，不造重复键。
 */
const SETUP_MESSAGE_KEYS: Readonly<Record<string, string>> = {
  config_invalid: 'setup.error.configInvalid',
  db_unreachable: 'setup.error.dbUnreachable',
  redis_unreachable: 'setup.error.redisUnreachable',
  migration_failed: 'setup.error.migrationFailed',
  admin_missing: 'setup.error.adminMissing',
  username_invalid: 'setup.error.usernameInvalid',
  password_weak: 'setup.error.passwordWeak',
  invalid_argument: 'setup.error.invalidArgument',
  unauthenticated: 'setup.error.unauthenticated',
  permission_denied: 'setup.error.permissionDenied',
  not_found: 'errors.code.not_found',
  already_exists: 'errors.code.already_exists',
  resource_exhausted: 'setup.error.resourceExhausted',
  internal: 'setup.error.internal',
  unavailable: 'setup.error.unavailable',
};

/** 未知 code 兜底键：不透出后端 error.message 原文（errors.ts 同口径）。 */
const SETUP_MESSAGE_FALLBACK_KEY = 'setup.error.unknown';

/** 位置二口径（对齐 shared/api errors.ts）：已知 code 查表取 i18n 键，未知 code 走兜底键。 */
export function setupMessage(code: string): string {
  return t(SETUP_MESSAGE_KEYS[code] ?? SETUP_MESSAGE_FALLBACK_KEY);
}

/**
 * setup 向导纯逻辑：root 域名预填 / 前置校验（docs/前端架构.md §6b、
 * 接口文档 §13.3）与重启轮询（§13.4）。本文件**零 Semi 依赖**——rstest 工具链
 * 无法加载含 Semi import 的模块图（实测 blocker，见 account.test.tsx
 * 头注），可测逻辑因此从 Semi 化页面（InstallPage / RestartingPage）抽回此处。
 */

import { setupMessage, type SetupStatusResult } from './api';
import { ApiError } from '../shared/api/errors';
import { t } from '../shared/i18n';
import { isValidPort } from './dsn';

// ---------------------------------------------------------------------------
// root 主域名（§6b / §13.3：必填、完整 URL、host 为域名或 localhost、拒 IP）
// ---------------------------------------------------------------------------

/**
 * 域名 host 形状（§13.3：域名或 localhost；label 为字母数字连字符，
 * 不以连字符开头 / 结尾）。IP 由 isIpHost 单独判定。
 */
const DOMAIN_HOST_PATTERN =
  /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$/;

/** host 是否为 IP（§13.3 拒 IP）：v4 点分四段数字；v6 含冒号（hostname 无端口与方括号）。 */
export function isIpHost(host: string): boolean {
  return host.includes(':') || /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
}

/** root 前置校验失败项（§6b：必填 / 拒 IP / 域名格式），文案键见 ROOT_ERROR_KEYS。 */
export type RootCheckError = 'rootRequired' | 'rootIpRejected' | 'rootInvalid';

/** 校验失败项 → i18n 键（体验性校验，§9 第 4 条：后端为唯一权威）。 */
export const ROOT_ERROR_KEYS: Readonly<Record<RootCheckError, string>> = {
  rootRequired: 'setup.error.rootRequired',
  rootIpRejected: 'setup.error.rootIpRejected',
  rootInvalid: 'setup.error.rootInvalid',
};

/**
 * root 前置校验（§6b / §13.3）：必填、完整 URL（http:// 或 https:// 开头）、
 * host 为域名或 localhost（拒 IP v4 / v6）。合法返回 null，非法返回失败项。
 */
export function checkRoot(value: string): RootCheckError | null {
  const trimmed = value.trim();
  if (trimmed === '') {
    return 'rootRequired';
  }
  if (!/^https?:\/\//.test(trimmed)) {
    return 'rootInvalid';
  }
  try {
    const { hostname } = new URL(trimmed);
    if (isIpHost(hostname)) {
      return 'rootIpRejected';
    }
    return DOMAIN_HOST_PATTERN.test(hostname) ? null : 'rootInvalid';
  } catch {
    return 'rootInvalid';
  }
}

/**
 * root 预填（§6b）：仅当 origin 的 host 为域名或 localhost 才回填 origin；
 * host 为 IP（v4 / v6）一律留空。
 */
export function prefillRoot(origin: string): string {
  try {
    const { hostname } = new URL(origin);
    return !isIpHost(hostname) && DOMAIN_HOST_PATTERN.test(hostname)
      ? origin
      : '';
  } catch {
    return '';
  }
}

// ---------------------------------------------------------------------------
// Redis 地址（UI 拆 host + port 两栏对齐 DB；wire 契约不变——§13.3
// 仍为单字符串 redisAddr，提交时拼 `host:port`，接口字段名不动）
// ---------------------------------------------------------------------------

export type RedisFieldKey = 'host' | 'port';

/** Redis 字段级校验失败项（host 必填 / port 必填 + 1-65535，与 dsn.ts 端口同口径）。 */
export type RedisFieldError = 'required' | 'portInvalid';

/**
 * Redis host + port 体验性校验（§9 第 4 条：后端为唯一权威，连接失败最终由
 * redis_unreachable 兜底）：host trim 后非空必填；port 必填且纯数字 1-65535
 * （复用 dsn.ts isValidPort，语义一致）。
 */
export function validateRedisFields(
  host: string,
  port: string,
): Partial<Record<RedisFieldKey, RedisFieldError>> {
  const errors: Partial<Record<RedisFieldKey, RedisFieldError>> = {};
  if (host.trim() === '') {
    errors.host = 'required';
  }
  if (port.trim() === '') {
    errors.port = 'required';
  } else if (!isValidPort(port.trim())) {
    errors.port = 'portInvalid';
  }
  return errors;
}

/** 拼装 wire 契约的单个 redisAddr（`host:port`，两侧 trim）；调用前应先过 validateRedisFields。 */
export function joinRedisAddr(host: string, port: string): string {
  return `${host.trim()}:${port.trim()}`;
}

// ---------------------------------------------------------------------------
// 请求错误分派（字段级校验错误留行内，请求失败 / 后端返回错误走 Toast）
// ---------------------------------------------------------------------------

/** InstallPage 表单字段集（Semi Form 字段名；放此处供错误分派返回带类型的字段名）。 */
export interface InstallFormState {
  dbHost: string;
  dbPort: string;
  dbUser: string;
  dbPassword: string;
  dbName: string;
  dbParams: string;
  redisHost: string;
  redisPort: string;
  redisPassword: string;
  redisDb: string;
  root: string;
  rpId: string;
  adminUsername: string;
  adminPassword: string;
}

/** §13 字段级错误码 → InstallPage 表单字段（root 缺失 / IP / 非法 → config_invalid → 域名组；redis_unreachable → Redis 主机）。 */
export const INSTALL_FIELD_BY_CODE: Readonly<
  Record<string, keyof InstallFormState>
> = {
  config_invalid: 'root',
  username_invalid: 'adminUsername',
  password_weak: 'adminPassword',
  db_unreachable: 'dbHost',
  redis_unreachable: 'redisHost',
};

/** 字段级展示文案键覆盖（db_unreachable 指向 DSN 字段组，措辞与 UploadConfig 区分）。 */
const INSTALL_FIELD_MESSAGE_KEY_BY_CODE: Readonly<Record<string, string>> = {
  db_unreachable: 'setup.error.dbUnreachableFields',
};

export type InstallErrorAction =
  /** 命中 §13 字段映射：行内呈现（用户需知道哪一栏错）。 */
  | {
      readonly kind: 'field';
      readonly field: keyof InstallFormState;
      readonly message: string;
    }
  /** 其余请求 / 后端错误：Toast 弹出。 */
  | { readonly kind: 'toast'; readonly message: string };

/** Install 请求错误分派：ApiError 命中字段映射 → 行内；其余（含非 ApiError）→ Toast。 */
export function classifyInstallError(error: unknown): InstallErrorAction {
  if (error instanceof ApiError) {
    const overrideKey = INSTALL_FIELD_MESSAGE_KEY_BY_CODE[error.code];
    const message = overrideKey ? t(overrideKey) : setupMessage(error.code);
    const field = INSTALL_FIELD_BY_CODE[error.code];
    return field
      ? { kind: 'field', field, message }
      : { kind: 'toast', message };
  }
  return { kind: 'toast', message: setupMessage('internal') };
}

// ---------------------------------------------------------------------------
// 重启轮询（§13.4：2s 间隔 / 120s 超时 / GetStatus 404 视为完成）
// ---------------------------------------------------------------------------

/** §13.4：以 2 秒间隔轮询。 */
export const RESTART_POLL_INTERVAL_MS = 2_000;
/** §13.4：轮询超过 120 秒仍未恢复 → 提示超时，不自动重试安装。 */
export const RESTART_POLL_TIMEOUT_MS = 120_000;

export type RestartPollResult =
  /** status 404：setup 路由消失，已进入正常模式。 */
  | 'restarted'
  /** 超过 120 秒仍未恢复。 */
  | 'timeout'
  /** 调用方 cancel（页面卸载、「重新探测」开启新一轮等）。 */
  | 'cancelled';

export interface RestartPollOptions {
  /** 探测 SetupService/GetStatus（§13.1）并分类；实现不得 reject。 */
  check: () => Promise<SetupStatusResult>;
  intervalMs?: number;
  timeoutMs?: number;
  /** 定时器 / 时钟注入点（单测 mock 定时器用）；缺省 setTimeout / Date.now。 */
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
}

export interface RestartPollHandle {
  readonly done: Promise<RestartPollResult>;
  /** 中断轮询：done 结束后不再发探测（编码约束 §9 第 7 条，结束值 'cancelled'）。 */
  cancel(): void;
}

/**
 * §13.4 重启轮询核心：立即发起首次探测，此后每 intervalMs 一次；
 * 仅 status 404（kind 为 gone）视为重启完成，连接被拒 / 超时 / 其他响应
 * 一律继续轮询；到 deadline（默认 120s）仍未恢复 → 按超时处理，不自动重试。
 * 恰好在 deadline 时刻恢复（「未超过」边界）按完成处理。
 */
export function pollRestart(options: RestartPollOptions): RestartPollHandle {
  const intervalMs = options.intervalMs ?? RESTART_POLL_INTERVAL_MS;
  const timeoutMs = options.timeoutMs ?? RESTART_POLL_TIMEOUT_MS;
  const sleep = options.sleep ?? defaultSleep;
  const now = options.now ?? Date.now;
  let cancelled = false;
  const done = (async (): Promise<RestartPollResult> => {
    const deadline = now() + timeoutMs;
    for (;;) {
      if (cancelled) {
        return 'cancelled';
      }
      const result = await options.check();
      if (cancelled) {
        return 'cancelled';
      }
      if (result.kind === 'gone') {
        return 'restarted';
      }
      if (now() >= deadline) {
        return 'timeout';
      }
      await sleep(intervalMs);
    }
  })();
  return {
    done,
    cancel(): void {
      cancelled = true;
    },
  };
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

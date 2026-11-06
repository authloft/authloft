/**
 * en-US 安装域文案模块（分域底座）：以 zh 侧同名模块为类型约束，
 * 键集编译期对齐（缺译 / 多译都过不了 tsc）；域收口在本模块内追加。
 */
import type { setup as zhSetup } from '../zh/setup';

export const setup: typeof zhSetup = {
  // ---- §13 域内业务码 + Connect 标准码 → 展示文案（setup/api.ts setupMessage 表）----
  // not_found / already_exists 复用 errors.code.* 既有键（与 zh 侧口径一致）。
  'setup.error.configInvalid':
    'Configuration file validation failed: the content is incomplete, invalid, or missing sign_key. Please fix it and upload again',
  'setup.error.dbUnreachable':
    'Cannot connect to the database. Please check the connection string and try again',
  'setup.error.redisUnreachable':
    'Cannot connect to Redis. Please check the address and password, then try again',
  'setup.error.migrationFailed':
    'Database initialization (running migrations) failed. Please check the database status and try again',
  'setup.error.adminMissing':
    'The version is already up to date but no administrator account exists. Please run a fresh install instead',
  'setup.error.usernameInvalid':
    'The administrator username does not meet the requirements',
  'setup.error.passwordWeak': 'The password is too weak. Please choose a stronger one',
  'setup.error.invalidArgument': 'Invalid request parameters',
  'setup.error.unauthenticated': 'The request is not authenticated',
  'setup.error.permissionDenied': 'The request was denied',
  'setup.error.resourceExhausted': 'Too many requests. Please try again later',
  'setup.error.internal': 'Internal server error. Please try again later',
  'setup.error.unavailable': 'Network error. Please try again later',
  'setup.error.unknown': 'Operation failed. Please check your input and try again',

  // ---- 重启页（§13.4，上传配置 / 全新安装两条路径共用）----
  'setup.restartingTitle': 'Restarting',
  'setup.restartingNotice':
    'The program has exited. Please restart it manually; if you use Docker or systemd, it will restart automatically',
  'setup.restartTimeoutNotice': 'Restart timed out. Please check the service status',
  'setup.waitingRestart': 'Waiting for the service to restart…',

  // ---- 上传已有配置页（路径 A，§13.2）----
  'setup.uploadConfigTitle': 'Upload Existing Configuration',
  'setup.uploadConfigIntro':
    'Paste or select the full content of an existing config.yaml. The system will validate the configuration, check the database / Redis connections, and run initialization in order; once it succeeds, the service restarts automatically.',
  'setup.uploadConfigPlaceholder': 'Full config.yaml content',
  'setup.unreadableFile': 'Unable to read the selected file',
  'setup.adminMissingHint':
    'The configuration is already at the latest version but has no administrator account. A fresh install is required to create one.',
  'setup.initializing': 'Initializing…',
  'setup.startInitialize': 'Start Initialization',
  'setup.switchToInstall': 'Switch to Fresh Install',

  // ---- Fresh install page (path B, §13.3) ----
  'setup.installTitle': 'Fresh Install',
  'setup.installIntro':
    'Enter the database and Redis connection details and the administrator account; once it succeeds, the service restarts automatically.',
  // DB six fields (assembled into a single dbDsn on the client; wire contract unchanged).
  'setup.fieldDbHost': 'Database host',
  'setup.fieldDbPort': 'Database port',
  'setup.fieldDbUser': 'Database username',
  'setup.fieldDbPassword': 'Database password',
  'setup.fieldDbName': 'Database name',
  'setup.fieldDbParams': 'Extra parameters',
  'setup.hintDbPort': 'MySQL default 3306; range 1-65535',
  'setup.hintDbParams':
    'Optional; appended to the DSN as-is, e.g. charset=utf8mb4&parseTime=true',
  'setup.fieldRedisAddr': 'Redis address',
  'setup.fieldRedisPassword': 'Redis password',
  'setup.fieldRedisDb': 'Redis database number',
  'setup.fieldRoot': 'Primary domain',
  'setup.fieldAdminUsername': 'Administrator username',
  'setup.fieldAdminPassword': 'Administrator password',
  'setup.hintRedisDb': 'Default: 0',
  'setup.hintRoot':
    'A domain is required (IPs rejected; localhost allowed). Prefilled with the current site when its host is a domain or localhost',
  // root pre-validation messages (client-side hints only; the backend is the sole authority).
  'setup.error.rootRequired': 'Please enter the primary domain',
  'setup.error.rootIpRejected':
    'The primary domain cannot be an IP address. Please use a domain (localhost is allowed)',
  'setup.error.rootInvalid':
    'Invalid primary domain: it must be a full URL starting with http:// or https://, with a domain as its host',
  // DB six-field pre-validation messages (client-side hints only; the backend is the sole authority).
  'setup.error.dbHostRequired': 'Please enter the database host',
  'setup.error.dbPortRequired': 'Please enter the database port',
  'setup.error.dbUserRequired': 'Please enter the database username',
  'setup.error.dbPasswordRequired': 'Please enter the database password',
  'setup.error.dbNameRequired': 'Please enter the database name',
  'setup.error.dbPortInvalid': 'The port must be a number between 1 and 65535',
  'setup.error.dbUserColon':
    'The database username cannot contain a colon (:)',
  'setup.error.dbNameInvalid': 'The database name cannot contain ? or /',
  // Field-level display for db_unreachable (InstallPage points at the DSN field group; UploadConfig keeps dbUnreachable).
  'setup.error.dbUnreachableFields':
    'Cannot connect to the database. Please check the host / port / username / password',
  'setup.hintRpId': 'Defaults to the current domain',
  'setup.requiredMark': '(required)',
  'setup.installing': 'Installing…',
  'setup.startInstall': 'Start Install',

  // ---- Entry page (mode detection + two path entries; buttons reuse uploadConfigTitle / installTitle) ----
  'setup.checkingMode': 'Detecting run mode…',
  'setup.initTitle': 'Authloft Setup',
  'setup.setupModeDetected':
    'First launch detected (setup mode). Choose how to initialize:',
};

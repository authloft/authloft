/**
 * en-US 管理后台域文案模块（分域底座）：以 zh 侧同名模块为类型
 * 约束，键集编译期对齐（缺译 / 多译都过不了 tsc）；域收口在本模块
 * 内追加。
 */
import type { admin as zhAdmin } from '../zh/admin';

export const admin: typeof zhAdmin = {
  // ---- settingsLogic.ts 设置表单（分区 / 字段 label / hint / 单位）----------
  'admin.settingsSectionPasswordPolicy': 'Password policy',
  'admin.settingsSectionAccountRegistration': 'Account & registration',
  'admin.settingsSectionOtpRateLimit': 'Verification code rate limits',
  'admin.settingsSectionLoginAndMfa': 'Sign-in methods & MFA',
  'admin.settingsSectionPwdFailProtection': 'Password failure protection',
  'admin.settingsSectionSessionCookie': 'Session, cookies & domains',
  'admin.settingsSectionQueue': 'Queue parameters',
  'admin.settingsSectionProviderAndGateway': 'Providers & gateway',
  'admin.settingsSectionLogAndStatic': 'Logs & static assets',

  'admin.pwdMinLengthLabel': 'Minimum length',
  'admin.pwdMinLengthHint': 'Default 8',
  'admin.pwdMaxLengthLabel': 'Maximum length',
  'admin.pwdMaxLengthHint': 'Can be lowered but not raised; server hard cap is 64 (default 64)',
  'admin.pwdRequireClassesLabel': 'Required character classes',
  'admin.pwdRequireClassesHint':
    '1-3; classes = uppercase / lowercase / digits; symbols do not count (default 3)',
  'admin.pwdDisallowUsernameLabel': 'Disallow passwords containing the username',
  'admin.pwdDisallowCommonLabel': 'Reject commonly used passwords',
  'admin.allowPasswordResetLabel': 'Allow self-service password reset',
  'admin.allowPasswordResetHint':
    'When off, password reset is always rejected: no code is sent or verified',
  'admin.allowRegistrationLabel': 'Registration master switch',
  'admin.allowRegistrationHint': 'When off, registration is always rejected',
  'admin.allowSignupPasswordLabel': 'Username + password sign-up entry',
  'admin.allowSignupPhoneLabel': 'Phone number sign-up entry',
  'admin.allowSignupEmailLabel': 'Email sign-up entry',
  'admin.otpResendIntervalLabel': 'Resend cooldown per target',
  'admin.otpResendIntervalHint': 'Default 60',
  'admin.otpTtlLabel': 'Verification code validity',
  'admin.otpTtlHint': 'Default 300',
  'admin.otpMaxAttemptsLabel': 'Max failed verification attempts per code',
  'admin.otpMaxAttemptsHint': 'The code is voided once the limit is exceeded (default 5)',
  'admin.otpDailyLimitTargetLabel': 'Daily send limit per target',
  'admin.otpDailyLimitTargetHint': 'Default 10',
  'admin.otpDailyLimitIpLabel': 'Daily send limit per IP',
  'admin.otpDailyLimitIpHint': 'Default 50',
  'admin.loginMethodsLabel': 'Enabled sign-in methods',
  'admin.loginMethodsHint':
    'Controls sign-in only, not sign-up; methods not listed are rejected at sign-in',
  'admin.mfaEnabledLabel': 'Two-factor verification master switch',
  'admin.mfaEnabledHint': 'When off, users are no longer asked for second verification',
  'admin.mfaMethodsLabel': 'Available second factors',
  'admin.mfaMethodsHint': 'Recovery codes are enabled with TOTP and are not listed separately',
  'admin.pwdFailCaptureLabel': 'Daily password failures before captcha is required',
  'admin.pwdFailCaptureHint':
    'Once daily password failures for an account reach this count, sign-in requires captcha (default 3)',
  'admin.pwdFailBanLabel': 'Failures before password sign-in is banned',
  'admin.pwdFailBanHint':
    'Password sign-in is banned after this many cumulative failures (default 6)',
  'admin.pwdBanTtlLabel': 'Password sign-in ban duration',
  'admin.pwdBanTtlHint': 'Default 21600 (6 hours)',
  'admin.sessionTtlLabel': 'Session and cookie lifetime',
  'admin.sessionTtlHint': 'Default 604800 (7 days)',
  'admin.cookieNameLabel': 'Session cookie name',
  'admin.cookieNameHint': 'Default al_session',
  'admin.httpsDeploymentLabel': 'HTTPS deployment',
  'admin.httpsDeploymentHint':
    'Declares the HTTPS deployment of this instance and controls the Secure attribute of session cookies: Auto-detect = marked secure only on HTTPS requests; Force on = treated as deployed over HTTPS, browsers on plain HTTP will not keep the cookie; Force off = treated as plain HTTP, the cookie is set without the Secure flag',
  'admin.ssoDomainsLabel': 'Multi-root-domain sync list',
  'admin.ssoDomainsHint': 'Synced one by one on sign-in / sign-out',
  'admin.queueWorkersLabel': 'Delayed write queue workers',
  'admin.queueWorkersHint': 'Default 4',
  'admin.queueCapacityLabel': 'Queue capacity (ring buffer)',
  'admin.queueCapacityHint': 'Default 8192',
  'admin.queueBatchLabel': 'Batch count threshold',
  'admin.queueBatchHint': 'Default 200',
  'admin.queueFlushMsLabel': 'Batch flush window',
  'admin.queueFlushMsHint': 'Default 2000',
  'admin.captchaProviderKeyLabel': 'Active captcha provider',
  'admin.captchaProviderKeyHint': 'Empty = built-in image captcha',
  'admin.smsProviderKeyLabel': 'Active SMS provider',
  'admin.smsProviderKeyHint': 'Empty = no external SMS channel',
  'admin.emailProviderKeyLabel': 'Active email provider',
  'admin.emailProviderKeyHint': 'Empty = no external email channel',
  'admin.avatarStorageProviderLabel': 'Storage provider for avatars / provider icons',
  'admin.avatarStorageProviderHint': 'Empty = no external storage',
  'admin.gatewayTokensLabel': 'Gateway tokens',
  'admin.gatewayTokensHint': 'Multiple values allowed',
  'admin.eventlogRetentionDaysLabel': 'Event log retention days',
  'admin.eventlogRetentionDaysHint': 'Default 180',
  'admin.staticBaseLabel': 'Static asset base URL (CDN)',
  'admin.staticBaseHint':
    'URL prefix for shell page scripts / styles; refresh the page after changes take effect',

  'admin.unitSeconds': 'seconds',
  'admin.unitTimes': 'times',
  'admin.unitMilliseconds': 'milliseconds',
  'admin.unitDays': 'days',
  'admin.addDomain': 'Add domain',
  'admin.addGatewayToken': 'Add token',
  'admin.gatewayTokenPlaceholder': 'Gateway caller token',

  'admin.httpsDeploymentAuto': 'Auto-detect',
  'admin.httpsDeploymentForceOn': 'Force on',
  'admin.httpsDeploymentForceOff': 'Force off',

  'admin.settingsNumberIssue': 'Numeric settings must be integers no less than 0',
  'admin.pwdRequireClassesIssue': 'Required character classes must be between 1 and 3',
  'admin.pwdMinOverMaxIssue': 'Minimum password length cannot exceed the maximum',
  'admin.pwdMaxOverCapIssue':
    'Maximum password length cannot exceed 64 (server hard cap; can only be lowered)',
  'admin.httpsDeploymentIssue':
    'HTTPS deployment must be one of: auto-detect / force on / force off',

  // ---- api.ts 展示纯函数------------------------------------------------------
  'admin.policyTagAllowSignin': 'Sign-in allowed',
  'admin.policyTagAllowSignup': 'Sign-up allowed',
  'admin.policyTagAutoBind': 'Auto-bind',
  'admin.displayNameFallback': 'Administrator',
  'admin.userStatusEnabled': 'Active',
  'admin.userStatusDisabled': 'Disabled',
  'admin.credentialKindMfaSetting': 'MFA switch',
  'admin.redirectUrisIssue': 'Redirect URIs must be * or start with http:// or https://',
  'admin.scopesIssue': 'Scope entries must be non-empty and must not contain commas',
  'admin.listSummary': '{first} and {count} more',
  'admin.durationDays': '{count} days',
  'admin.durationHours': '{count} hours',
  'admin.durationMinutes': '{count} minutes',
  'admin.durationSeconds': '{count} seconds',
  'admin.tokenTtlSummary': 'Access {access} / refresh {refresh}',
  'admin.ttlDetail': '{duration} ({seconds} s)',

  'admin.eventLoginSuccess': 'Signed in',
  'admin.eventChangePassword': 'Changed password',
  'admin.eventResetPassword': 'Reset password',
  'admin.eventBindPhone': 'Bound phone number',
  'admin.eventBindEmail': 'Bound email',
  'admin.eventEnableMfa': 'Enabled two-factor verification',
  'admin.eventDisableMfa': 'Disabled two-factor verification',
  'admin.eventWebauthnRegister': 'Registered passkey',
  'admin.eventWebauthnDelete': 'Deleted passkey',
  'admin.eventThirdpartyBind': 'Linked third-party account',
  'admin.eventThirdpartyUnbind': 'Unlinked third-party account',
  'admin.eventAdminDisableUser': 'User disabled by administrator',
  'admin.eventAdminResetPassword': 'Password reset by administrator',
  'admin.eventProviderCreate': 'Provider created',
  'admin.eventProviderUpdate': 'Provider updated',
  'admin.eventSettingsUpdate': 'System settings updated',
  'admin.eventOidcAuthorizeNoState': 'OIDC authorize without state',

  'admin.actorUser': 'User',
  'admin.actorAdmin': 'Administrator',
  'admin.actorSystem': 'System',

  // ---- schema/schemaLogic.ts（区块标题 / 校验文案）--------------------------
  'admin.schemaSectionBasic': 'Basic information',
  'admin.schemaSectionCredential': 'Credentials',
  'admin.schemaSectionEndpoint': 'Endpoints',
  'admin.schemaSectionDisplay': 'Display & ordering',
  'admin.schemaSectionPolicy': 'Policy switches',
  'admin.schemaSectionError':
    'Provider schema field {key} has a missing or invalid section: {section}',
  'admin.validateRequired': 'This field is required',
  'admin.validatePattern': 'Invalid format',
  'admin.validateNumber': 'Must be a number',
  'admin.validateJson': 'Not valid JSON',

  // ---- schema/SchemaForm.tsx--------------------------------------------------
  'admin.endpointSummary': 'Endpoint configuration',
  'admin.advancedOptions': 'Advanced options',
  'admin.sectionErrorPrefix': 'Form structure error: ',

  // ---- schema/fields/FieldRenderers.tsx---------------------------------------
  'admin.unsupportedFieldType': 'Unsupported field type: {type}',

  // ---- components/*-----------------------------------------------------------
  'admin.removeAction': 'Delete',
  'admin.dragSortHandle': 'Drag to sort',
  'admin.callbackUrlLabel': 'Third-party sign-in callback URL: ',
  'admin.oidcCallbackExactMatchNote': 'OIDC provider callbacks must match exactly',
};

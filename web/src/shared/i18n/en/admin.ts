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
  'admin.pwdMaxLengthHint':
    'Can be lowered but not raised; server hard cap is 64 (default 64)',
  'admin.pwdRequireClassesLabel': 'Required character classes',
  'admin.pwdRequireClassesHint':
    '1-3; classes = uppercase / lowercase / digits; symbols do not count (default 3)',
  'admin.pwdDisallowUsernameLabel':
    'Disallow passwords containing the username',
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
  'admin.otpMaxAttemptsHint':
    'The code is voided once the limit is exceeded (default 5)',
  'admin.otpDailyLimitTargetLabel': 'Daily send limit per target',
  'admin.otpDailyLimitTargetHint': 'Default 10',
  'admin.otpDailyLimitIpLabel': 'Daily send limit per IP',
  'admin.otpDailyLimitIpHint': 'Default 50',
  'admin.loginMethodsLabel': 'Enabled sign-in methods',
  'admin.loginMethodsHint':
    'Controls sign-in only, not sign-up; methods not listed are rejected at sign-in',
  'admin.mfaEnabledLabel': 'Two-factor verification master switch',
  'admin.mfaEnabledHint':
    'When off, users are no longer asked for second verification',
  'admin.mfaMethodsLabel': 'Available second factors',
  'admin.mfaMethodsHint':
    'Recovery codes are enabled with TOTP and are not listed separately',
  'admin.pwdFailCaptureLabel':
    'Daily password failures before captcha is required',
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
  'admin.avatarStorageProviderLabel':
    'Storage provider for avatars / provider icons',
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

  'admin.settingsNumberIssue':
    'Numeric settings must be integers no less than 0',
  'admin.pwdRequireClassesIssue':
    'Required character classes must be between 1 and 3',
  'admin.pwdMinOverMaxIssue':
    'Minimum password length cannot exceed the maximum',
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
  'admin.redirectUrisIssue':
    'Redirect URIs must be * or start with http:// or https://',
  'admin.scopesIssue':
    'Scope entries must be non-empty and must not contain commas',
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

  // ---- schema field copy (i18n keys sent by GetProviderSchema as label / help) ----
  // The server sends keys only; the same Ext field may have a different label per
  // provider (e.g. client_id: clientIdLabel for OAuth, aliyunAccessKeyIdLabel for
  // Aliyun SMS), so keys are named by meaning rather than derived from field.key.
  // Table-column baselines (dto/admin.go).
  'admin.schemaField.providerKeyLabel': 'Key',
  'admin.schemaField.providerKeyHelp':
    'Cannot be changed after creation; appears in the callback URL',
  'admin.schemaField.displayNameLabel': 'Display Name',
  // category read-only field from the §5.3 contract example (now replaced by the
  // page-level type picker and no longer emitted; kept for legacy schema/contract).
  'admin.schemaField.categoryLabel': 'Category',
  'admin.schemaField.categoryHelp':
    'Determined by the registry from type; read-only',
  'admin.schemaField.unionProviderLabel': 'Union ID Provider',
  'admin.schemaField.unionProviderHelp': 'Leave empty to skip Union ID merging',
  'admin.schemaField.iconUrlLabel': 'Icon URL',
  'admin.schemaField.iconUrlHelp':
    'Leave empty to show a generic placeholder icon',
  'admin.schemaField.uiGroupLabel': 'Display Group',
  'admin.schemaField.sortOrderLabel': 'Sort Order',
  'admin.schemaField.remarkLabel': 'Remark',
  'admin.schemaField.isEnabledLabel': 'Enabled',
  'admin.schemaField.enableSigninLabel': 'Allow sign-in',
  'admin.schemaField.enableSignupLabel': 'Allow sign-up',
  'admin.schemaField.enableSignupHelp':
    'When off, this provider cannot be used to create accounts',
  'admin.schemaField.autoBindLabel': 'Auto-bind by contact info',
  'admin.schemaField.autoBindFieldsLabel': 'Auto-bind fields',
  'admin.schemaField.autoBindFieldsHelp': 'Applies when auto_bind is enabled',

  // OAuth Ext field baselines (oauthcore.NewMeta / wechat_mp / wechat_mp_scan).
  'admin.schemaField.clientIdLabel': 'App ID',
  'admin.schemaField.clientSecretLabel': 'App Secret',
  'admin.schemaField.appIdLabel': 'Mini Program App ID',
  'admin.schemaField.certLabel': 'Certificate / Public Key',
  'admin.schemaField.scopesLabel': 'Scopes',
  'admin.schemaField.providerUrlLabel': 'Service URL',
  'admin.schemaField.customAuthUrlLabel': 'Authorization URL',
  'admin.schemaField.customTokenUrlLabel': 'Token URL',
  'admin.schemaField.customUserInfoUrlLabel': 'UserInfo URL',
  'admin.schemaField.userMappingLabel': 'Field Mapping',
  'admin.schemaField.userMappingHelp':
    'Maps third-party fields to Authloft fields; values are JSONata expressions',
  'admin.schemaField.metadataLabel': 'Extra Key-Values',
  'admin.schemaField.oauth2UserMappingHelp':
    'open_id is required: maps third-party fields to Authloft fields with JSONata expressions (e.g. {"open_id": "$.id"})',
  'admin.schemaField.oidcProviderUrlHelp':
    'IdP issuer URL; endpoints are auto-discovered via .well-known/openid-configuration',

  // wechat_mp_scan extra fields.
  'admin.schemaField.qrcodeAutoDeleteLabel':
    'Delete QR code image after sign-in',
  'admin.schemaField.storageProviderLabel': 'Storage Provider',
  'admin.schemaField.storagePathLabel': 'Storage Path Template',
  'admin.schemaField.storagePathHelp':
    "JSONata expression with built-in variables ticket_id / timestamp, e.g. 'qrcodes_' & $.ticket_id & '.jpg'",

  // Provider-specific overrides (alipay / microsoft).
  'admin.schemaField.alipayPrivateKeyLabel': 'App Private Key (PEM)',
  'admin.schemaField.alipayPrivateKeyHelp':
    'PKCS8 / PKCS1 RSA private key used for RSA2 request signing',
  'admin.schemaField.alipayPublicKeyLabel': 'Alipay Public Key (PEM)',
  'admin.schemaField.alipayPublicKeyHelp':
    'Used to verify gateway responses; leave empty to skip verification (not recommended)',
  'admin.schemaField.alipayGatewayLabel': 'Gateway URL',
  'admin.schemaField.alipayGatewayHelp':
    'Defaults to https://openapi.alipay.com/gateway.do when empty (use the sandbox gateway for testing)',
  'admin.schemaField.microsoftTenantLabel':
    'Tenant (common / organizations / tenant ID)',
  'admin.schemaField.microsoftTenantHelp': 'Leave empty to use common',

  // Messaging Ext fields (smtp / aliyun_sms).
  'admin.schemaField.smtpHostLabel': 'SMTP Server',
  'admin.schemaField.smtpPortLabel': 'Port',
  'admin.schemaField.smtpPortHelp':
    '465 = implicit TLS; other ports connect in plaintext and upgrade via STARTTLS when supported',
  'admin.schemaField.smtpFromLabel': 'From Address',
  'admin.schemaField.smtpDisableSslLabel': 'Disable STARTTLS',
  'admin.schemaField.smtpDisableSslHelp':
    'Skip the STARTTLS upgrade for intranet self-signed certificates',
  'admin.schemaField.smtpMetadataHelp':
    'username / password = SMTP credentials; subject.<tpl> / body.<tpl> = subject and body templates ({code} placeholder)',
  'admin.schemaField.aliyunAccessKeyIdLabel': 'AccessKey ID',
  'admin.schemaField.aliyunAccessKeySecretLabel': 'AccessKey Secret',
  'admin.schemaField.aliyunSignNameLabel': 'SMS Signature',
  'admin.schemaField.aliyunTemplateCodeLabel': 'SMS Template ID',
  'admin.schemaField.aliyunIntranetEndpointLabel': 'Intranet Endpoint',
  'admin.schemaField.aliyunMetadataHelp':
    'template_code.<tpl> overrides the SMS template ID per template key',

  // select option labels (options remain wire values; key =
  // admin.schemaOption.<fieldKey>.<value>, namespaced by field so a custom
  // union_provider provider_key is never mistaken for a generic enum label;
  // values without a key are shown verbatim).
  'admin.schemaOption.ui_group.social': 'Social',
  'admin.schemaOption.ui_group.enterprise': 'Enterprise',
  'admin.schemaOption.ui_group.dev': 'Developer',
  'admin.schemaOption.ui_group.other': 'Other',

  // ---- components/*-----------------------------------------------------------
  'admin.removeAction': 'Delete',
  'admin.dragSortHandle': 'Drag to sort',
  'admin.callbackUrlLabel': 'Third-party sign-in callback URL: ',
  'admin.oidcCallbackExactMatchNote':
    'OIDC provider callbacks must match exactly',

  // ---- layout/AdminLayout.tsx + routes.tsx + entry.tsx（壳层文案）--------
  'admin.appTitle': 'Authloft Admin Console',
  'admin.rootTitle': 'Admin Console',
  'admin.navProviders': 'Providers',
  'admin.navUsers': 'Users',
  'admin.navClients': 'Clients',
  'admin.navSsoClients': 'SSO Clients',
  'admin.navOidcClients': 'OIDC Clients',
  'admin.navSettings': 'Settings',
  'admin.navAudit': 'Event Logs',
  'admin.navStatus': 'Monitoring',
  'admin.navDecode': 'Decode Tool',
  'admin.newAction': 'New',
  'admin.editAction': 'Edit',
  'admin.userDetailTitle': 'User Details',
  'admin.logout': 'Sign Out',
  'admin.loading': 'Loading…',
  'admin.routeNotFound': 'Page not found',
  // back link on the not-found fallback page.
  'admin.backToHome': 'Back to admin home',
  'admin.renderError': 'Something went wrong; please refresh and try again',
  'admin.meAvatarAlt': 'Administrator avatar',

  // ---- pages/{SsoClientsPage,OidcClientsPage}.tsx（客户端族共用）--------
  'admin.clientIdLabel': 'Client ID',
  'admin.clientNameLabel': 'Display Name',
  'admin.redirectUrisLabel': 'Redirect URI Allowlist',
  'admin.scopesLabel': 'Scopes',
  'admin.createdAtLabel': 'Created At',
  'admin.updatedAtLabel': 'Updated At',
  'admin.actionsLabel': 'Actions',
  'admin.viewAction': 'View',
  'admin.clientDeleteConfirm':
    'Delete client "{clientId}"? This cannot be undone',
  'admin.clientsLoadFailed':
    'Failed to load the client list; please refresh and try again',
  'admin.createClientAction': 'New Client',
  'admin.noClients': 'No clients yet',
  'admin.clientDetailTitle': 'Client Details',
  'admin.clientSecretLabel': 'Client Secret',
  'admin.editClientTitle': 'Edit Client "{clientId}"',
  'admin.editClientFallbackTitle': 'Edit Client',
  'admin.clientCreateSuccess':
    'Client created; the secret is generated server-side — click "View" to retrieve it',
  'admin.clientUpdateSuccess': 'Updated client "{clientId}"',
  'admin.clientDeleteSuccess': 'Deleted client "{clientId}"',
  'admin.redirectUrisRequired':
    'The redirect URI allowlist cannot be empty (saving after clearing keeps the previous value)',
  'admin.clientIdAutoGenPlaceholder': 'Leave empty to auto-generate',
  'admin.clientNamePlaceholder': 'Client display name',
  'admin.redirectUriEntryHint':
    'Each entry must be * or start with http:// or https://',
  'admin.redirectUriAriaLabel': 'Redirect URI',
  'admin.addRedirectUri': 'Add Redirect URI',
  'admin.redirectUriPlaceholder': 'https://example.com/callback or *',
  'admin.noRedirectUrisHint':
    'No redirect URIs yet; click the button below to add one',
  'admin.clientIdImmutable': 'Cannot be changed after creation',
  'admin.newSecretLabel': 'New Secret',
  'admin.newSecretPlaceholder': 'Leave empty to keep the current secret',
  'admin.secretRotateHint':
    'Saving a filled-in value rotates the secret; update the integrating party accordingly',
  'admin.cancelAction': 'Cancel',
  'admin.saveAction': 'Save',
  'admin.createAction': 'Create',
  'admin.createSsoClientTitle': 'New SSO Client',

  // ---- pages/OidcClientsPage.tsx（OIDC 增量）------------------------------
  'admin.createOidcClientTitle': 'New OIDC Client',
  'admin.tokenTtlLabel': 'Token Lifetime',
  'admin.accessTokenTtlFieldLabel': 'Access Token Lifetime (seconds)',
  'admin.accessTokenTtlLabel': 'Access Token Lifetime',
  'admin.refreshTokenTtlFieldLabel': 'Refresh Token Lifetime (seconds)',
  'admin.refreshTokenTtlLabel': 'Refresh Token Lifetime',
  'admin.accessTtlIssue':
    'Access token lifetime must be an integer number of seconds within 1-{max}',
  'admin.refreshTtlIssue':
    'Refresh token lifetime must be an integer number of seconds within 1-{max}',
  'admin.scopesRequired':
    'Scopes cannot be empty (saving after clearing keeps the previous value)',
  'admin.scopesDefaultHint':
    'Leave empty to use the default openid,profile,email',
  'admin.addScope': 'Add Scope',
  'admin.scopePlaceholder': 'e.g. openid',
  'admin.scopesEntryHint':
    'Each entry must be non-empty and must not contain commas',
  'admin.ttlPlaceholder': 'Default {value}',
  'admin.ttlRangeHint': '1-{max}; leave empty to use the default {value}',
  'admin.ttlKeepHint': '1-{max}; leave empty to keep the previous value',

  // ---- pages/{UsersPage,UserDetailPage}.tsx 用户族----------------
  'admin.usernameLabel': 'Username',
  'admin.nicknameLabel': 'Nickname',
  'admin.phoneLabel': 'Phone Number',
  'admin.emailLabel': 'Email',
  'admin.statusLabel': 'Status',
  'admin.lastLoginLabel': 'Last Sign-in',
  'admin.userSearchPlaceholder': 'Search username / nickname / phone / email',
  'admin.userSearchAriaLabel': 'Search users',
  'admin.searchAction': 'Search',
  'admin.usersLoadFailed':
    'Failed to load the user list; please refresh and try again',
  'admin.noUsers': 'No users yet',
  'admin.resetPasswordAction': 'Reset Password',
  'admin.resetPasswordTitle': 'Reset the password of "{username}"',
  'admin.resetPasswordHint':
    'The new password must satisfy the system password policy; once the reset succeeds, all existing sessions are invalidated. Please hand the new password to the user.',
  'admin.newPasswordLabel': 'New Password',
  'admin.newPasswordPlaceholder': 'Enter the new password',
  'admin.confirmPasswordLabel': 'Confirm New Password',
  'admin.confirmPasswordPlaceholder': 'Re-enter the new password',
  'admin.passwordMismatchError': 'The two passwords do not match',
  'admin.confirmResetAction': 'Confirm Reset',
  'admin.resetPasswordSuccess':
    'Password of "{username}" has been reset; please hand the new password to the user',
  'admin.unlockAction': 'Remove Sign-in Restriction',
  'admin.unlockConfirm': 'Remove the sign-in restriction on "{username}"?',
  'admin.unlockSuccess': 'Sign-in restriction on "{username}" removed',
  'admin.userStatusToggleColumn': 'Disable/Enable',
  'admin.userDetailLoadFailed':
    'Failed to load the user details; please refresh and try again',
  'admin.basicInfoSection': 'Basic Information',
  'admin.noUserData': 'No user data',
  'admin.mfaRequiredLabel': 'Required Two-Step Verification',
  'admin.verifiedTag': '(verified)',
  'admin.yesText': 'Yes',
  'admin.noText': 'No',
  'admin.mfaStatusSection': 'MFA Status',
  'admin.mfaRequiredNotice': 'Two-step verification is enforced by the system',
  'admin.mfaBoundSummary': 'Bound: {factors}',
  'admin.mfaNoneBound': 'No second factors bound',
  'admin.credentialsSection': 'Credentials',
  'admin.noCredentials': 'No credentials yet',
  'admin.credentialEnabled': 'Enabled',
  'admin.credentialDisabled': 'Disabled',
  'admin.boundAt': 'Bound at {time}',
  'admin.credentialLastUsed': ' · Last used {time}',
  'admin.bindingsSection': 'Third-Party Bindings',
  'admin.noBindings': 'No third-party bindings',
  'admin.unbindConfirm':
    'Unbind "{providerKey}"? It can no longer be used to sign in afterwards.',
  'admin.unbindAction': 'Unbind',
  // unbind success feedback (P1-6).
  'admin.unbindSuccess': 'Unbound "{providerKey}"',
  'admin.loginLogSection': 'Sign-in Log',
  'admin.loginLogLoadFailed':
    'Failed to load the sign-in log; please refresh and try again',
  'admin.noLoginRecords': 'No sign-in records yet',
  'admin.timeColumn': 'Time',
  'admin.eventColumn': 'Event',
  'admin.methodColumn': 'Method',
  'admin.deviceUaColumn': 'Device (UA)',

  // ---- pages/AuditPage.tsx----------------------------------------
  'admin.auditPresetAll': 'All Events',
  'admin.auditPresetLoginRecords': 'Sign-in Records',
  'admin.eventTypeColumn': 'Event Type',
  'admin.actorColumn': 'Actor',
  'admin.targetUserColumn': 'Target User',
  'admin.clientColumn': 'Client',
  'admin.authMethodColumn': 'Auth Method',
  'admin.sourceIpColumn': 'Source IP',
  'admin.actionTargetColumn': 'Action Target',
  'admin.detailColumn': 'Detail',
  'admin.occurredAtColumn': 'Occurred At',
  'admin.auditLoadFailed':
    'Failed to load the event log; please refresh and try again',
  'admin.eventFilterPlaceholder': 'Event type: all',
  'admin.eventFilterAriaLabel': 'Filter by event type',
  'admin.actorFilterPlaceholder': 'Actor type: all',
  'admin.actorFilterAriaLabel': 'Filter by actor type',
  'admin.noEvents': 'No events yet',

  // ---- pages/AuditPage.tsx 四项筛选（actorId/userId/from/to）----
  'admin.actorIdFilterPlaceholder': 'Actor ID',
  'admin.actorIdFilterAriaLabel': 'Filter by actor ID',
  'admin.userIdFilterPlaceholder': 'User ID',
  'admin.userIdFilterAriaLabel': 'Filter by user ID',
  'admin.fromFilterPlaceholder': 'From',
  'admin.toFilterPlaceholder': 'To',

  // ---- pages/AuditPage.tsx Sensitive Operations preset (five-event closed set) ----
  'admin.auditPresetSensitiveRecords': 'Sensitive Operations',
  'admin.auditPresetSensitiveHint':
    'Sensitive operations: change password, reset password, unbind, enable/disable two-factor verification',

  // ---- pages/{ProvidersPage,ProviderEditPage}.tsx 提供商族--------
  'admin.providerColumnDisplayName': 'Display Name',
  'admin.providerColumnKey': 'Key',
  'admin.providerColumnCategory': 'Category',
  'admin.providerColumnType': 'Type',
  'admin.providerColumnPolicyTags': 'Policy Tags',
  'admin.providerColumnSortOrder': 'Sort',
  'admin.providersLoadFailed':
    'Failed to load the provider list; please refresh and try again',
  'admin.providersDragDisabledNote':
    'More than one page of providers (100); drag sorting is disabled',
  'admin.providerDragSortLabel': 'Drag to reorder providers',
  'admin.noProviders': 'No providers yet',
  // success feedback for enable/disable and drag sorting (P1-6; the
  // earlier "no new keys" ruling is resolved here).
  'admin.providerEnableSuccess': 'Enabled "{name}"',
  'admin.providerDisableSuccess': 'Disabled "{name}"',
  'admin.providerSortSuccess': 'Provider order saved',
  'admin.createProviderAction': 'New Provider',
  'admin.providerKeyTaken':
    'The key is already taken; please choose another one',
  'admin.providerTypeRequired': 'Select a provider type first',
  'admin.testTargetRequired': 'Enter a test target',
  'admin.testSent': 'Sent; please check',
  'admin.testNote': 'Send a test message using the saved configuration',
  'admin.iconPreviewAlt': 'Icon preview',
  'admin.providerTypesLoadFailed':
    'Failed to load the provider type list; please refresh and try again',
  'admin.providerLoadFailed':
    'Failed to load the provider; please refresh and try again',
  'admin.schemaLoadFailed':
    'Failed to load the form schema; please refresh and try again',
  'admin.editProviderTitle': 'Edit Provider',
  'admin.createProviderTitle': 'New Provider',
  'admin.providerTypeLabel': 'Type',
  'admin.selectTypePlaceholder': 'Select a type',
  'admin.sendTestAction': 'Send Test',
  'admin.testTargetAriaLabel': 'Test target',

  // ---- pages/{SettingsPage,StatusPage,DecodePage}.tsx-------------
  'admin.settingsTitle': 'System Settings',
  // ---- SettingsPage tabs (4 groups / per-tab save) ----
  'admin.settingsTabAccount': 'Account & password',
  'admin.settingsTabAuth': 'Sign-in & verification',
  'admin.settingsTabSession': 'Session & domains',
  'admin.settingsTabSystem': 'System & integrations',
  'admin.settingsTabUnsaved': 'This tab has unsaved changes',
  'admin.settingsTabSaveAction': 'Save This Tab',
  'admin.settingsSaved': 'Settings saved',
  'admin.settingsLoadFailed':
    'Failed to load the settings; please refresh and try again',
  'admin.saveSettingsAction': 'Save Settings',
  'admin.settingsDiffTitle': 'Confirm Settings Changes',
  'admin.settingsDiffSummary': '{count} setting(s) will be changed:',
  'admin.settingsDiffEmptyValue': '(empty)',
  'admin.statusLoadFailed':
    'Failed to load the metrics; please refresh and try again',
  'admin.statusHint':
    'Queue length excludes batches picked up but not yet persisted; a flush time of 0 means no batch has been persisted since startup',
  'admin.statusQueueLength': 'Queue Length',
  'admin.statusDropped': 'Total Dropped',
  'admin.statusFlushMs': 'Last Flush Time (ms)',
  'admin.refreshAction': 'Refresh',
  'admin.decodePurposeLogin': 'login_token (sign-in token)',
  'admin.decodePurposeSession': 'session_token (session token)',
  'admin.decodePurposeCookie': 'al_login_state (sign-in state Cookie)',
  'admin.decodeResultHint':
    'The decoded result is the token internal payload (Struct passed through as-is), for troubleshooting only; do not disclose the token or its payload.',
  'admin.decodePurposeAriaLabel': 'Decode purpose',
  'admin.decodeTokenPlaceholder': 'Paste the token to decode',
  'admin.decodeTokenAriaLabel': 'Token to decode',
  'admin.decodeAction': 'Decode',
  // ---- unsaved-changes guard (Modal.confirm) ----
  'admin.unsavedChangesTitle': 'Discard unsaved changes?',
  'admin.unsavedChangesContent':
    'Your edits have not been saved and will be lost if you close now.',
};

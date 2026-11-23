/**
 * en-US 管理后台域文案模块（分域底座）：以 zh 侧同名模块为类型
 * 约束，键集编译期对齐（缺译 / 多译都过不了 tsc）；域收口在本模块
 * 内追加。
 */
import type { admin as zhAdmin } from '../zh/admin';

export const admin: typeof zhAdmin = {
  // ---- settingsLogic.ts 设置表单（分区 / 字段 label / hint / 单位）----------
  'admin.settingsSectionSiteInfo': 'Site information',
  'admin.settingsSectionRegistration': 'Registration & recovery',
  'admin.settingsSectionPasswordPolicy': 'Password policy',
  'admin.settingsSectionLoginFailureLock': 'Failed sign-in lockout',
  'admin.settingsSectionLoginMethods': 'Sign-in methods',
  'admin.settingsSectionMfa': 'Two-step verification (MFA)',
  'admin.settingsSectionOtpRateLimit': 'Verification code rate limits',
  'admin.settingsSectionSessionCookie': 'Session & cookies',
  'admin.settingsSectionDomainHttps': 'Domains & HTTPS',
  'admin.settingsSectionQueue': 'Queue parameters',
  'admin.settingsSectionExternalServices': 'External services',
  'admin.settingsSectionGatewayToken': 'Gateway tokens',
  'admin.settingsSectionLogPartition': 'Log partitions',

  'admin.pwdMinLengthLabel': 'Minimum length',
  'admin.pwdMinLengthHint': 'Default 8',
  'admin.pwdMaxLengthLabel': 'Maximum length',
  'admin.pwdMaxLengthHint': 'Server cap is 64 (default 64)',
  'admin.pwdRequireClassesLabel': 'Required character classes',
  'admin.pwdRequireClassesHint':
    '1-3; classes = uppercase / lowercase / digits; symbols do not count (default 3)',
  'admin.pwdDisallowUsernameLabel':
    'Disallow passwords containing the username',
  'admin.pwdDisallowCommonLabel': 'Reject commonly used passwords',
  'admin.allowPasswordResetLabel': 'Allow self-service password reset',
  'admin.allowPasswordResetHint': 'When off, password reset is always rejected',
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
    'When off, two-step verification has no effect and the user toggle is unavailable',
  'admin.mfaMethodsLabel': 'Factors for two-step verification',
  'admin.mfaMethodsHint':
    'Users can use a factor after binding one from the allowlist',
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
  'admin.ssoDomainsLabel': 'Multi-domain sync URL list',
  'admin.ssoDomainsHint':
    'Each entry is the full URL (e.g. https://example.com/prefix/sync_cookie); synced one by one on sign-in / sign-out',
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
  'admin.providerOptionLabel': '{name} ({key})',
  'admin.gatewayTokensLabel': 'Gateway tokens',
  'admin.eventlogPartitionDaysLabel': 'Event log partition days',
  'admin.eventlogPartitionDaysHint':
    'Default 7; the maintenance task rolls partitions forward at this interval',
  'admin.eventlogMaxPartitionsLabel': 'Event log max partitions',
  'admin.eventlogMaxPartitionsHint':
    'Default 26; oldest partitions are dropped beyond this limit',
  'admin.siteNameLabel': 'Site name',
  'admin.siteNameHint':
    'Page title, empty falls back to the default name Authloft',
  'admin.staticBaseLabel': 'Static asset base URL (CDN)',
  'admin.staticBaseHint':
    'URL prefix for page scripts / styles; refresh the page after changes take effect',
  'admin.clientIpHeaderLabel': 'Read the client IP from this header',
  'admin.clientIpHeaderHint':
    'Request header name injected by your reverse proxy (e.g. X-Forwarded-For). Empty = direct-connection address only',

  'admin.unitSeconds': 'seconds',
  'admin.unitTimes': 'times',
  'admin.unitMilliseconds': 'milliseconds',
  'admin.unitDays': 'days',
  'admin.addDomain': 'Add',
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
  'admin.pwdMaxOverCapIssue': 'Maximum password length cannot exceed 64',
  'admin.httpsDeploymentIssue':
    'HTTPS deployment must be one of: auto-detect / force on / force off',

  // ---- api.ts 展示纯函数------------------------------------------------------
  'admin.policyTagAllowSignin': 'Sign-in allowed',
  'admin.policyTagAllowSignup': 'Sign-up allowed',
  'admin.policyTagAutoBind': 'Auto-bind',
  'admin.displayNameFallback': 'Administrator',
  'admin.userStatusEnabled': 'Active',
  'admin.userStatusDisabled': 'Disabled',
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
  // provider (e.g. client_id: clientIdLabel for Auth, aliyunAccessKeyIdLabel for
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

  // Proxy provider five real fields (§5.3 proxy provider and outbound proxy
  // reference convention): closed-set scheme select, host forbids whitespace
  // and /?#@[], port number, user / password optional and collapsed; host /
  // port share field names with the smtp row but carry independent label keys
  // (proxy-row semantics: proxy address).
  'admin.schemaField.proxySchemeLabel': 'Proxy scheme',
  'admin.schemaField.proxyHostLabel': 'Proxy host',
  'admin.schemaField.proxyHostHelp':
    'Hostname / IPv4 / IPv6 literal; whitespace and /?#@[] forbidden; write IPv6 bare (e.g. ::1, without brackets)',
  'admin.schemaField.proxyPortLabel': 'Proxy port',
  'admin.schemaField.proxyPortHelp': '1 ≤ port ≤ 65535',
  'admin.schemaField.proxyUserLabel': 'Proxy username',
  'admin.schemaField.proxyPasswordLabel': 'Proxy password',
  'admin.schemaField.proxyPasswordHelp': 'A password requires a username',
  // Reference key proxy_provider_key (§5.3): candidates = category=proxy rows
  // (including disabled instances).
  'admin.schemaField.proxyProviderKeyLabel': 'Outbound proxy',
  'admin.schemaField.proxyProviderKeyHelp': 'Leave empty for direct connection',

  // Auth Ext field baselines (oauthcore.NewMeta / wechat_mp / wechat_mp_scan).
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

  // wechat_mp_scan extra fields. QR mode trio (接口文档 §5.3 type=wechat_mp_scan
  // row): mode is a three-way choice (empty = url, legacy behavior), format is
  // the ticket-mode content template ({{TICKET}} placeholder filled with the
  // full encrypted ticket), tip is HTML copy delivered with CreateQrcode
  // (site CSP as the safety net, §2.8).
  'admin.schemaField.qrcodeAutoDeleteLabel':
    'Delete QR code image after sign-in',
  'admin.schemaField.needCaptchaLabel': 'Require Human Verification',
  'admin.schemaField.needCaptchaHelp':
    'Ask for a captcha before fetching the QR code; when off the code is fetched directly (applies to both login and binding)',
  'admin.schemaField.storageProviderLabel': 'Storage Provider',
  'admin.schemaField.storagePathLabel': 'Storage Path Template',
  'admin.schemaField.storagePathHelp':
    "JSONata expression with built-in variables ticket_id / timestamp, e.g. 'qrcodes_' & $.ticket_id & '.jpg'",
  'admin.schemaField.qrcodeModeLabel': 'QR Code Mode',
  'admin.schemaField.qrcodeModeHelp':
    'ticket = deliver QR content for client-side drawing; base64 = inline JPEG image; url = serve via storage (empty means url)',
  'admin.schemaField.qrcodeFormatLabel': 'QR Code Content Template',
  'admin.schemaField.qrcodeFormatHelp':
    'Applies in ticket mode: the {{TICKET}} placeholder is replaced with the full encrypted ticket, e.g. https://example.com/scan?ticket={{TICKET}}',
  'admin.schemaField.qrcodeTipLabel': 'Scan Tip',
  'admin.schemaField.qrcodeTipHelp': 'Raw HTML shown next to the QR code',

  // captcha / storage service-type Provider fields (captcha uses client_id as
  // the site key, client_secret as the secret, endpoint as a custom verify URL;
  // storage/local uses bucket as the local directory, domain as the public URL,
  // path_prefix as the object key prefix).
  'admin.schemaField.captchaSiteKeyLabel': 'Site Key',
  'admin.schemaField.captchaSecretLabel': 'Secret Key',
  'admin.schemaField.captchaEndpointLabel': 'Custom Verify URL',
  'admin.schemaField.storageBucketLabel': 'Local Directory',
  'admin.schemaField.storageDomainLabel': 'Public Domain',
  'admin.schemaField.storagePathPrefixLabel': 'Object Key Prefix',

  // S3 storage fields (s3.go): endpoint reuses providerUrlLabel as its label
  // (help text is S3-specific); bucket / addressing / upload-chain limits and
  // the MIME whitelist feed the avatar upload chain.
  'admin.schemaField.s3EndpointHelp':
    'Scheme optional (defaults to https); the default port is stripped before SigV4 signing',
  'admin.schemaField.s3BucketLabel': 'Bucket',
  'admin.schemaField.s3BucketHelp': 'Required; must not contain / or \\',
  'admin.schemaField.s3RegionLabel': 'Region',
  'admin.schemaField.s3RegionHelp':
    'SigV4 region; falls back to us-east-1 when empty',
  'admin.schemaField.s3PathStyleLabel': 'Path Style',
  'admin.schemaField.s3PathStyleHelp':
    'Check to address as host/bucket/key (common for self-hosted MinIO); uncheck for virtual-host bucket.host addressing',
  'admin.schemaField.s3PublicReadLabel': 'Public Read',
  'admin.schemaField.s3PublicReadHelp':
    'Uploaded objects get the public-read ACL and are readable via direct links; do not enable for sensitive content',
  'admin.schemaField.uploadModeLabel': 'Upload Mode',
  'admin.schemaField.uploadModeHelp':
    'proxy = relayed through the server; direct = presigned-URL upload',
  'admin.schemaField.presignTtlLabel': 'Presign TTL (seconds)',
  'admin.schemaField.presignTtlHelp':
    'Presigned URL lifetime in direct mode; default 300, max 604800 (7 days)',
  'admin.schemaField.maxSizeLabel': 'Max File Size (bytes)',
  'admin.schemaField.maxSizeHelp':
    'Per-file limit for avatar uploads; defaults to 2MB when unset',
  'admin.schemaField.allowedTypesLabel': 'MIME Whitelist',
  'admin.schemaField.allowedTypesHelp':
    'Comma-separated MIME types (e.g. image/png,image/jpeg); leave empty to reject all uploads',

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
  'admin.schemaField.smtpFromHelp':
    'Leave empty to use the SMTP username as the sender address',
  'admin.schemaField.smtpSignNameLabel': 'From Name',
  'admin.schemaField.smtpUserLabel': 'SMTP Username',
  'admin.schemaField.smtpPasswordLabel': 'SMTP Password',
  'admin.schemaField.smtpDisableSslLabel': 'Disable STARTTLS',
  'admin.schemaField.smtpDisableSslHelp':
    'Skip the STARTTLS upgrade for intranet self-signed certificates',
  'admin.schemaField.smtpMetadataHelp':
    'subject.<tpl> / body.<tpl> = subject and body templates ({code} placeholder)',
  'admin.schemaField.aliyunAccessKeyIdLabel': 'AccessKey ID',
  'admin.schemaField.aliyunAccessKeySecretLabel': 'AccessKey Secret',
  'admin.schemaField.aliyunSignNameLabel': 'SMS Signature',
  'admin.schemaField.aliyunTemplateCodeLabel': 'SMS Template ID',
  'admin.schemaField.aliyunIntranetEndpointLabel': 'Intranet Endpoint',
  'admin.schemaField.aliyunMetadataHelp':
    'template_code.<tpl> overrides the SMS template ID per template key',

  // New-channel Ext fields (interface doc §12.1, numbers 51-68): credential
  // extensions / messaging extensions / captcha frontend config. Each
  // provider declares them in Schema() on demand; undeclared fields are
  // never sent down (§5.3).
  'admin.schemaField.teamIdLabel': 'Apple Team ID',
  'admin.schemaField.teamIdHelp':
    'Apple Developer Team ID; used to sign the client_secret JWT (iss)',
  'admin.schemaField.keyIdLabel': 'Apple Key ID',
  'admin.schemaField.keyIdHelp':
    'Apple key identifier; used to sign the client_secret JWT (kid)',
  'admin.schemaField.agentIdLabel': 'AgentId',
  'admin.schemaField.agentIdHelp':
    'Wecom app AgentId; required for the snsapi_privateinfo auth scope',
  'admin.schemaField.sdkAppIdLabel': 'SmsSdkAppId',
  'admin.schemaField.sdkAppIdHelp':
    'Tencent Cloud SMS SDK App ID; required on every send',
  'admin.schemaField.accessKeyIdLabel': 'AccessKeyId',
  'admin.schemaField.accessKeyIdHelp':
    'For Aliyun CAPTCHA RPC signing; put the AccessKeySecret in the secret field',
  'admin.schemaField.encryptKeyLabel': 'Encrypt Key (ekey)',
  'admin.schemaField.encryptKeyHelp':
    'Encrypted mode only; the server derives EncryptedSceneId from it (advanced)',
  'admin.schemaField.regionLabel': 'Region',
  'admin.schemaField.regionHelp':
    'Tencent Cloud SMS takes the X-TC-Region region; Aliyun CAPTCHA picks cn / sgp',
  'admin.schemaField.messagingServiceSidLabel': 'Messaging Service SID',
  'admin.schemaField.messagingServiceSidHelp':
    'MG-prefixed; choose either this or the sender number (from)',
  'admin.schemaField.sandboxModeLabel': 'Sandbox Mode',
  'admin.schemaField.sandboxModeHelp':
    'When enabled, sends report success without real delivery (integration testing only)',
  'admin.schemaField.replyToLabel': 'Reply-To Address',
  'admin.schemaField.replyToHelp': 'Email reply address (reply_to.email)',
  'admin.schemaField.addressTypeLabel': 'Address Type',
  'admin.schemaField.addressTypeHelp':
    'Aliyun DM address type; 0 = random account, 1 = sender address',
  'admin.schemaField.replyToAddressLabel': 'Use Reply Address',
  'admin.schemaField.replyToAddressHelp':
    'Reply to the custom reply address; the API string value is converted at build time',
  'admin.schemaField.replyAddressLabel': 'Reply Address',
  'admin.schemaField.replyAddressHelp':
    'Custom reply address; fill in when the console reply address is not enabled',
  'admin.schemaField.widgetApiBaseLabel': 'Capjs Base URL',
  'admin.schemaField.widgetApiBaseHelp':
    'Self-hosted service root URL; the frontend loads the widget and challenge/redeem from it',
  'admin.schemaField.widgetScriptUrlLabel': 'Widget Script URL',
  'admin.schemaField.widgetScriptUrlHelp':
    'Empty = official CDN; for self-hosting point to the assets script under the base URL',
  'admin.schemaField.widgetProductLabel': 'Frontend Mode',
  'admin.schemaField.widgetProductHelp':
    'GeeTest v4 interaction mode; defaults to bind',
  'admin.schemaField.widgetOptionsLabel': 'Frontend Init Options',
  'admin.schemaField.widgetOptionsHelp':
    'JSON text passed through to frontend init (e.g. language / mode), advanced',
  'admin.schemaField.prefixLabel': 'Instance Prefix (prefix)',
  'admin.schemaField.prefixHelp':
    'From the console instance info card; used by the V3 frontend init',

  // select option labels (options remain wire values; key =
  // admin.schemaOption.<fieldKey>.<value>, namespaced by field so a custom
  // union_provider provider_key is never mistaken for a generic enum label;
  // values without a key are shown verbatim).
  // scheme closed set (§5.3 proxy provider and outbound proxy reference
  // convention): protocol names are universal, zh / en identical.
  'admin.schemaOption.scheme.socks5': 'SOCKS5',
  'admin.schemaOption.scheme.http': 'HTTP',
  'admin.schemaOption.scheme.https': 'HTTPS',

  // select values carried by the new fields (region is a pattern text input
  // for Tencent Cloud SMS, no option keys).
  'admin.schemaOption.region.cn': 'China (cn)',
  'admin.schemaOption.region.sgp': 'Singapore (sgp)',
  'admin.schemaOption.address_type.0': 'Random account',
  'admin.schemaOption.address_type.1': 'Sender address',
  'admin.schemaOption.widget_product.bind': 'Hidden (bind)',
  'admin.schemaOption.widget_product.popup': 'Popup (popup)',
  'admin.schemaOption.widget_product.float': 'Float (float)',

  // ---- components/*-----------------------------------------------------------
  'admin.removeAction': 'Delete',
  'admin.dragSortHandle': 'Drag to sort',
  'admin.callbackUrlLabel': 'Callback URL: ',

  // ---- layout/AdminLayout.tsx + routes.tsx + entry.tsx（壳层文案）--------
  'admin.rootTitle': 'Admin Console',
  'admin.switchToAccount': 'Switch to Account Center',
  'admin.navProviders': 'Providers',
  'admin.navUsers': 'Users',
  'admin.navClients': 'Clients',
  'admin.navSsoClients': 'SSO Clients',
  'admin.navOidcClients': 'OIDC Clients',
  'admin.navTemplates': 'Templates',
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

  // ---- pages/SsoClientsPage.tsx 应用级登录配置（编辑 SideSheet；§5.5）----
  'admin.ssoLoginMethodsLabel': 'Login methods',
  'admin.ssoLoginMethodsHint':
    'Controls which sign-in methods this app allows; leave all unchecked to follow the global configuration',
  'admin.ssoMfaRiskHint':
    'Warning: some MFA-capable factors (SMS / email code / passkey) are disabled; users bound only to those factors cannot sign in to this app',
  'admin.ssoAuthProvidersLabel': 'Auth providers',
  'admin.ssoAuthProvidersHint':
    'Fine-grained allowlist for third-party sign-in; leave all unchecked to follow the global configuration',
  'admin.ssoAuthProvidersPlaceholder':
    'Select Auth providers allowed for this app',
  'admin.ssoDefaultRedirectUriLabel': 'Default redirect URI',
  'admin.ssoDefaultRedirectUriPlaceholder':
    'https://example.com/callback (must be in the redirect allowlist)',
  'admin.ssoDefaultRedirectUriHint':
    'Must match the client redirect allowlist (* wildcard supported); used only when sign-in completes without a returnTo',

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

  // ---- api.ts template validation / dropdown labels ----
  'admin.templateKeyRequired': 'Template key is required',
  'admin.templateKeyTooLong': 'Template key cannot exceed {max} characters',
  'admin.templateKeyBuiltinConflict':
    'Template key must not match a built-in template',
  'admin.templateKeyTaken':
    'Template key is already taken; please choose another',
  'admin.templateVarsIssue': 'Template variables must be a valid JSON object',
  'admin.templateUnspecified': 'Unspecified (default file shell)',

  // ---- pages/TemplatesPage.tsx ----
  'admin.templateKeyLabel': 'Template key',
  'admin.templateNameLabel': 'Display name',
  'admin.templateContentLabel': 'Template content',
  'admin.templateKeyPlaceholder': 'e.g. my_login_theme',
  'admin.templateNamePlaceholder': 'Template display name',
  'admin.templateContentHint':
    'The template key cannot be changed after creation',
  'admin.templateKeyImmutable': 'Cannot be changed after creation',
  'admin.templatesLoadFailed':
    'Failed to load the template list; please refresh and try again',
  'admin.noTemplates': 'No custom templates yet',
  'admin.createTemplateAction': 'New Template',
  'admin.createTemplateTitle': 'New Template',
  'admin.editTemplateTitle': 'Edit Template "{name}"',
  'admin.templateDeleteConfirm':
    'Delete template "{name}"? This cannot be undone',
  'admin.templateCreateSuccess': 'Template created',
  'admin.templateUpdateSuccess': 'Template "{name}" updated',
  'admin.templateDeleteSuccess': 'Template "{name}" deleted',
  'admin.templateSearchPlaceholder': 'Search templates by display name',
  'admin.templateSearchAriaLabel': 'Search templates',

  // ---- pages/{SsoClientsPage,OidcClientsPage}.tsx template form ----
  'admin.templateLabel': 'Template',
  'admin.templateVarsLabel': 'Template variables',
  'admin.templateVarsPlaceholder': '{"key": "value"}',
  'admin.templateVarsHint':
    'Enter a JSON object; left empty it is injected as {}',
  'admin.templateSelectHint':
    'Built-in login or a custom template; leave unspecified to use the default file shell',

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
  'admin.mfaRequiredLabel': 'Two-Step Verification',
  'admin.verifiedTag': '(verified)',
  'admin.yesText': 'Yes',
  'admin.noText': 'No',
  'admin.mfaStatusSection': 'MFA Status',
  'admin.mfaRequiredNotice': 'The user has enabled two-step verification',
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
  'admin.unbindSuccess': 'Unbound "{providerKey}"',
  'admin.loginLogSection': 'Sign-in Log',
  'admin.loginLogLoadFailed':
    'Failed to load the sign-in log; please refresh and try again',
  'admin.noLoginRecords': 'No sign-in records yet',
  'admin.timeColumn': 'Time',
  'admin.eventColumn': 'Event',
  'admin.methodColumn': 'Method',
  'admin.deviceUaColumn': 'Device (UA)',

  // ---- UserDetailPage edit mode / rescue write actions ----
  'admin.usernameReservedPrefixHint':
    'Username cannot start with the reserved prefix "deleted_"',
  'admin.avatarUrlLabel': 'Avatar URL',
  'admin.genderLabel': 'Gender',
  'admin.birthdayLabel': 'Birthday',
  'admin.localeLabel': 'Locale',
  'admin.timezoneLabel': 'Time zone',
  'admin.extraLabel': 'Extra profile (JSON object)',
  'admin.extraPlaceholder': '{"key": "value"}',
  'admin.genderUnspecified': 'Unspecified',
  'admin.genderMale': 'Male',
  'admin.genderFemale': 'Female',
  'admin.editNicknameIssue': 'Nickname must be 12 characters or fewer',
  'admin.editAvatarIssue': 'Avatar URL must be 120 characters or fewer',
  'admin.editGenderIssue': 'Gender must be unspecified / male / female',
  'admin.editBirthdayIssue': 'Birthday must be in YYYY-MM-DD format',
  'admin.editExtraIssue': 'Extra profile must be a valid JSON object',
  'admin.editPhoneIssue': 'Invalid phone number',
  'admin.editEmailIssue': 'Invalid email address',
  'admin.editProfileSuccess': 'Profile saved',
  'admin.editContactSuccess': 'Contact details saved',
  'admin.noEditChanges': 'No changes to save',
  'admin.contactEditConfirm':
    'Change contact details? The phone number / email you enter will be marked as verified, and all sessions of this user will be invalidated, requiring a new sign-in.',
  'admin.mfaEnableAction': 'Enable Two-Step Verification',
  'admin.mfaDisableAction': 'Disable Two-Step Verification',
  'admin.mfaEnableConfirm': 'Enable two-step verification for "{username}"?',
  'admin.mfaDisableConfirm':
    'Disable two-step verification for "{username}"? All sessions of this user will be invalidated, requiring a new sign-in.',
  'admin.mfaEnableSuccess': 'Two-step verification enabled',
  'admin.mfaDisableSuccess': 'Two-step verification disabled',
  'admin.unbindTotpAction': 'Unbind Authenticator',
  'admin.unbindTotpConfirm':
    'Unbind the authenticator of "{username}"? All sessions of this user will be invalidated, requiring a new sign-in.',
  'admin.unbindTotpSuccess': 'Authenticator unbound',
  'admin.resetRecoveryCodesAction': 'Reset Recovery Codes',
  'admin.resetRecoveryCodesConfirm':
    'Reset the recovery codes of "{username}"? The old codes will be invalidated immediately.',
  'admin.resetRecoveryCodesSuccess': 'Recovery codes reset',
  'admin.credentialEnableAction': 'Enable',
  'admin.credentialDisableAction': 'Disable',
  'admin.credentialDeleteAction': 'Delete',
  'admin.credentialDisableConfirm': 'Disable the "{kind}" credential?',
  'admin.credentialDeleteConfirm':
    'Delete the "{kind}" credential? All sessions of this user will be invalidated, requiring a new sign-in.',
  'admin.credentialEnabledSuccess': 'Credential enabled',
  'admin.credentialDisabledSuccess': 'Credential disabled',
  'admin.credentialDeletedSuccess': 'Credential deleted',

  // ---- Delete user danger action + four-dimension list filters (§5.4) ----
  'admin.deleteUserAction': 'Delete User',
  'admin.deleteUserTitle': 'Delete user "{username}"',
  'admin.deleteUserWarning':
    'This cannot be undone: the user will be disabled, the username rewritten with a deleted_ prefix marker, and the phone / email / profile / credentials / third-party bindings all cleared. All sessions and tokens are invalidated immediately.',
  'admin.deleteUserConfirmLabel': 'Type "{username}" to confirm deletion',
  'admin.deleteUserInputAriaLabel': 'Type the username to confirm deletion',
  'admin.deleteUserConfirmAction': 'Confirm Delete',
  'admin.deleteUserSuccess': 'User "{username}" deleted',
  'admin.deletedUserNotice':
    'This user has been deleted (username starts with deleted_): the profile is anonymized, credentials are cleared, and all write actions are unavailable.',
  'admin.deletedUserTag': 'Deleted',
  'admin.filterAnyOption': 'Any',
  'admin.createdFromFilterPlaceholder': 'Created from',
  'admin.createdToFilterPlaceholder': 'Created to',
  'admin.lastLoginFromFilterPlaceholder': 'Last sign-in from',
  'admin.lastLoginToFilterPlaceholder': 'Last sign-in to',
  'admin.mfaFilterPlaceholder': 'Two-Step Verification',
  'admin.mfaFilterEnabled': 'Enabled',
  'admin.mfaFilterDisabled': 'Disabled',
  'admin.credentialFilterPlaceholder': 'Credential Type',
  'admin.resetFiltersAction': 'Reset Filters',

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
  // type=proxy display name (§5.3 proxy provider and outbound proxy reference
  // convention).
  'admin.providerType.proxy': 'Outbound proxy',
  // category display names; key set = backend Category* constants (auth |
  // union | sms | email | captcha | storage | proxy); missing keys fall back
  // to the wire value on the page.
  'admin.providerCategory.auth': 'Auth provider',
  'admin.providerCategory.union': 'Union ID merging',
  'admin.providerCategory.sms': 'SMS service',
  'admin.providerCategory.email': 'Email service',
  'admin.providerCategory.captcha': 'Human verification',
  'admin.providerCategory.storage': 'Storage service',
  'admin.providerCategory.proxy': 'Outbound proxy',
  'admin.providerColumnPolicyTags': 'Policy Tags',
  'admin.providerColumnSortOrder': 'Sort',
  'admin.providersLoadFailed':
    'Failed to load the provider list; please refresh and try again',
  'admin.providersDragDisabledNote':
    'More than one page of providers (100); drag sorting is disabled',
  'admin.providerSortFilterDisabledNote':
    'Drag sorting is unavailable while a filter is active; clear the filter to sort',
  'admin.providerDragSortLabel': 'Drag to reorder providers',
  'admin.noProviders': 'No providers yet',
  'admin.providerEnableSuccess': 'Enabled "{name}"',
  'admin.providerDisableSuccess': 'Disabled "{name}"',
  'admin.providerSortSuccess': 'Provider order saved',
  'admin.providerDeleteConfirm':
    'Delete provider "{name}"? This cannot be undone',
  'admin.providerDeleteSuccess': 'Deleted provider "{name}"',
  'admin.providerSortAction': 'Sort',
  'admin.providerSortTitle': 'Provider order',
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
  'admin.settingsTabSite': 'Site & account',
  'admin.settingsTabPassword': 'Password & protection',
  'admin.settingsTabLogin': 'Sign-in & session',
  'admin.settingsTabDeploy': 'Deployment & integrations',
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
  'admin.decodePurposeTicket':
    'ticket (scan-QR ticket / al:ticket storage value)',
  'admin.decodePurposeVerification': 'verification (step-up assertion)',
  'admin.decodePurposeChallenge': 'challenge (challenge token)',
  'admin.decodePurposeSyncPayload': 'sync_payload (multi-domain sync payload)',
  'admin.decodePurposeOidcCode': 'oidc_code (OIDC authorization code)',
  'admin.decodePurposeOidcSub': 'oidc_sub (OIDC pairwise sub)',
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

/**
 * en-US 登录域文案模块（分域底座）：以 zh 侧同名模块为类型约束，
 * 键集编译期对齐（缺译 / 多译都过不了 tsc）；域收口在本模块内追加。
 */
import type { login as zhLogin } from '../zh/login';

export const login: typeof zhLogin = {
  // ---- 容器 / 方式列表（LoginContainer、MethodTabs）------------------------
  'login.title': 'Sign in',
  'login.register': 'Register',
  'login.forgotPassword': 'Forgot password',
  'login.noMethods': 'No sign-in methods available',
  'login.selectMethodHint': 'Please choose a sign-in method',
  // Section title above the step-up dialog method tabs.
  'login.mfaSelectHint': 'Second-factor method',
  'login.backToMethods': 'Back to sign-in options',
  'login.pollPlaceholder': 'QR code sign-in is coming soon',
  'login.redirecting': 'Signed in, redirecting…',
  // Footer language switch (native names, same in both locales).
  'login.langZh': '中文',
  'login.langEn': 'EN',
  // ---- 注册页（RegisterPage）----------------------------------------------
  'login.noRegisterMethods': 'No registration methods available',
  'login.nextStep': 'Next',
  'login.resend': 'Resend',
  'login.resendCountdown': 'Resend available in {seconds}s',
  'login.usernameHint':
    'Username must be 5-20 characters of letters, digits, or underscores',
  'login.registerSuccess': 'Registration complete, redirecting…',
  'login.codeLabel': 'Verification code',
  'login.usernameLabel': 'Username',
  'login.passwordLabel': 'Password',
  'login.confirmPasswordLabel': 'Confirm password',
  'login.errPasswordMismatch': 'Passwords do not match',
  'login.attemptsLeft': '{count} attempts left',
  'login.registerMethodPassword': 'Username and password',
  'login.registerMethodOtpSms': 'Phone number',
  'login.registerMethodOtpEmail': 'Email',
  // ---- 重置页（ResetPage）--------------------------------------------------
  'login.reset': 'Reset password',
  'login.newPasswordLabel': 'New password',
  'login.resetMethodOtpSms': 'Recover via phone number',
  'login.resetMethodOtpEmail': 'Recover via email',
  'login.resetSuccess':
    'Password reset complete. Please sign in with your new password',
  'login.goLogin': 'Go to sign in',
  // ---- 绑定（BindingPage、BindingChoice）-----------------------------------
  'login.createAccount': 'Create account',
  'login.accountCreated': 'Account created, redirecting…',
  'login.bindingIdentity': 'Sign-in method "{name}"',
  'login.createAccountOption': 'Create a new account',
  'login.exitBinding': 'Exit and sign in with a different account',
  'login.channelSignupClosed': 'Sign-up is not available for this channel',
  // ---- OAuth 回调页（OAuthCallbackPage）------------------------------------
  'login.processing': 'Processing, please wait…',
  'login.backToLogin': 'Back to sign in',
  // ---- 因子表单（factors/：OTPForm、PasswordForm、WebAuthnButton、
  //      RecoveryCodeForm、ProviderButtons）------------------------------------
  'login.submit': 'Sign in',
  'login.submitting': 'Signing in…',
  'login.sending': 'Sending…',
  'login.sendCode': 'Send verification code',
  'login.codeWillBeSentTo': 'The verification code will be sent to {target}',
  'login.capsLockOn': 'Caps Lock is on',
  'login.passkeySignIn': 'Sign in with passkey',
  'login.passkeyVerify': 'Verify',
  'login.passkeyCancelled': 'Passkey verification cancelled',
  'login.passkeyFailed': 'Passkey verification failed. Please try again',
  // Redirect failure message carries the provider display name.
  'login.oauthRedirectFailed':
    'Could not redirect to {provider}. Please try again',
  // ---- 步骤杂项（steps/、routes、entry）--------------------------------------
  // 「请刷新重试」复用 common.refreshAndRetry（收口，login.refreshRetry 已删）。
  'login.qrNeedCaptcha': 'Please complete the verification first',
  'login.fetchQrcodeAction': 'Get QR code',
  'login.redirectInProgress': 'Redirecting…',
  'login.initMissing':
    'Initialization data is missing. Please refresh and try again',
  'login.routeNotFound': 'Page not found',
  'login.renderError':
    'This page hit an unexpected error. Please refresh and try again',
  // ---- Step-up dialog used by the QR sign-in flow ---------------------------
  'login.stepUpAttemptsLeft': '{message} ({count} attempts left)',
  'login.stepUpFactorUnsupported':
    'This verification method cannot be completed here. Please choose another method',
  // Explicit re-entry offered on the QR panel after cancelling step-up.
  'login.stepUpReopen': 'Verify again',

  // ---- Backend-supplied field copy (sso.v1.Field.label / snapshot labels) ----
  // The login flow only sends login.field.* keys; all wording lives here and is
  // resolved by shared/components/FieldRenderer via t() at render time. Same
  // contract as admin.schemaField.* on the admin side, scoped to the login
  // dictionary. Missing keys echo themselves (legacy Chinese literals too).
  'login.field.usernameOrIdentifier': 'Username / email / phone',
  'login.field.password': 'Password',
  'login.field.captcha': 'Captcha',
  'login.field.otpCode': 'Verification code',
  'login.field.recoveryCode': 'Recovery code',
  'login.field.totpCode': 'Authenticator code',
  'login.field.phone': 'Phone number',
  'login.field.email': 'Email',
  'login.field.username': 'Username',

  // ---- OIDC consent two-column (§4.2 three states / frontend arch §4.4) ------
  'login.submitAndAgree': 'Sign in and agree',
  'login.consent.title': 'Authorization request',
  'login.consent.accountLabel': 'Current account',
  'login.consent.hint':
    '"{app}" is requesting access to the following, please confirm to continue',
  'login.consent.alwaysAuthorized': 'Authorized',
  'login.consent.approve': 'Allow',
  'login.consent.deny': 'Deny',
  'login.consent.denied': 'Authorization denied, returning…',
  'login.consent.processing': 'Submitting…',
  'login.scope.openid': 'Unique account identifier',
  'login.scope.profile': 'Basic profile (nickname, avatar)',
  'login.scope.email': 'Email address (masked)',
  'login.scope.phone': 'Phone number (masked)',
  'login.scope.phone_plain': 'Phone number (unmasked)',
  'login.scope.email_plain': 'Email address (unmasked)',
  // invalid_scope is an ErrorInfo.code only (§1.6), merged in via the login spread.
  'errors.code.invalid_scope':
    'The requested scope is invalid. Please go back and reselect',
};

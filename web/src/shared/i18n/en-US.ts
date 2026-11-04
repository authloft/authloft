/**
 * en-US 文案字典（docs/前端架构.md §3.4 行 343）。
 * 键集以 I18nMessages（zh-CN.ts 定义）约束：缺译 / 多译都在编译期报错，
 * 不允许静默回退 undefined（既定约束）。
 */
import type { I18nMessages } from './zh-CN';

export const enUS: I18nMessages = {
  // ---- shared 组件公共文案 ------------------------------------------------
  'common.copy': 'Copy',
  'common.copied': 'Copied',
  'common.retry': 'Retry',
  'common.remainingSeconds': '{seconds} seconds remaining',
  'common.remainingAttempts': '{count} attempts remaining',
  'common.reveal': 'Show',
  'common.hide': 'Hide',
  'common.selectPlaceholder': 'Select',

  // ---- 因子名（§1.10）------------------------------------------------------
  'factors.password': 'Password',
  'factors.otp_sms': 'SMS code',
  'factors.otp_email': 'Email code',
  'factors.webauthn': 'Passkey',
  'factors.totp': 'Authenticator code',
  'factors.recovery_code': 'Recovery code',
  'factors.thirdparty': 'Third-party sign-in',

  // ---- 渠道名（兜底；优先用后端下发的 display_name）------------------------
  'channels.sms': 'SMS',
  'channels.email': 'Email',

  // ---- 位置一：登录流程域顶层 status（§1.6 全表 33 词 + unknown 兜底）------
  'errors.status.next': 'Please continue',
  'errors.status.mfa_required': 'Second verification required',
  'errors.status.binding_required':
    'This third-party identity is not linked to an account yet. Choose how to proceed',
  'errors.status.success': 'Success',
  'errors.status.pending': 'Processing, please wait',
  'errors.status.scanned': 'Scanned. Please confirm on your phone',
  'errors.status.expired': 'Expired. Please refresh and try again',
  'errors.status.failed': 'Operation failed. Please try again',
  'errors.status.captcha_required': 'Please complete the verification',
  'errors.status.captcha_invalid': 'Verification failed. Please try again',
  'errors.status.too_many_requests':
    'Too many requests. Please try again later',
  'errors.status.too_many_attempts':
    'Too many attempts. Please request a new code',
  'errors.status.locked': 'Password sign-in is temporarily locked',
  'errors.status.invalid_request':
    'Invalid request. Please check and try again',
  'errors.status.invalid_credentials': 'Incorrect account or password',
  'errors.status.invalid_code': 'Incorrect verification code',
  'errors.status.code_expired':
    'The code has expired. Please request a new one',
  'errors.status.method_disabled': 'This sign-in method is disabled',
  'errors.status.step_invalid':
    'The current step is no longer valid. Please start over',
  'errors.status.token_invalid':
    'Your session is invalid. Please sign in again',
  'errors.status.token_expired':
    'Your session has timed out. Please sign in again',
  'errors.status.state_mismatch': 'State check failed. Please start over',
  'errors.status.user_disabled':
    'This account is disabled. Please contact your administrator',
  'errors.status.user_not_found':
    'Account not found, or this phone number/email is not linked to any account',
  'errors.status.password_weak':
    'The password does not meet the policy. Please adjust and retry',
  'errors.status.username_taken': 'This username is already taken',
  'errors.status.target_taken': 'This phone number/email is already in use',
  'errors.status.signup_disabled': 'Sign-up is disabled',
  'errors.status.reset_disabled': 'Password reset is disabled',
  'errors.status.provider_disabled': 'This provider is disabled',
  'errors.status.file_too_large': 'The file is too large',
  'errors.status.file_type_not_allowed': 'This file type is not allowed',
  'errors.status.internal_error': 'Internal error. Please try again later',
  'errors.status.unknown': 'Something went wrong. Please try again later',

  // ---- 位置二：ErrorInfo.code（§1.6 失败词 26 + §1.5 标准码 8 + unknown）--
  'errors.code.failed': 'Operation failed. Please try again',
  'errors.code.captcha_required': 'Please complete the verification',
  'errors.code.captcha_invalid': 'Verification failed. Please try again',
  'errors.code.too_many_requests': 'Too many requests. Please try again later',
  'errors.code.too_many_attempts':
    'Too many attempts. Please request a new code',
  'errors.code.locked': 'Password sign-in is temporarily locked',
  'errors.code.invalid_request': 'Invalid request. Please check and try again',
  'errors.code.invalid_credentials': 'Incorrect account or password',
  'errors.code.invalid_code': 'Incorrect verification code',
  'errors.code.code_expired': 'The code has expired. Please request a new one',
  'errors.code.method_disabled': 'This sign-in method is disabled',
  'errors.code.step_invalid':
    'The current step is no longer valid. Please start over',
  'errors.code.token_invalid': 'Your session is invalid. Please sign in again',
  'errors.code.token_expired':
    'Your session has timed out. Please sign in again',
  'errors.code.state_mismatch': 'State check failed. Please start over',
  'errors.code.user_disabled':
    'This account is disabled. Please contact your administrator',
  'errors.code.user_not_found':
    'Account not found, or this phone number/email is not linked to any account',
  'errors.code.password_weak':
    'The password does not meet the policy. Please adjust and retry',
  'errors.code.username_taken': 'This username is already taken',
  'errors.code.target_taken': 'This phone number/email is already in use',
  'errors.code.signup_disabled': 'Sign-up is disabled',
  'errors.code.reset_disabled': 'Password reset is disabled',
  'errors.code.provider_disabled': 'This provider is disabled',
  'errors.code.file_too_large': 'The file is too large',
  'errors.code.file_type_not_allowed': 'This file type is not allowed',
  'errors.code.internal_error': 'Internal error. Please try again later',
  'errors.code.invalid_argument': 'Invalid request',
  'errors.code.unauthenticated': 'Please sign in first',
  'errors.code.permission_denied':
    'You do not have permission to perform this action',
  'errors.code.not_found': 'Not found',
  'errors.code.already_exists': 'Already exists',
  'errors.code.resource_exhausted': 'Too many requests. Please try again later',
  'errors.code.internal': 'Internal error. Please try again later',
  'errors.code.unavailable':
    'The service is temporarily unavailable. Please try again later',
  'errors.code.unknown': 'Something went wrong. Please try again later',
};

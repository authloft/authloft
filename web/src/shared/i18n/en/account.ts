/**
 * en-US 安全中心域文案模块（分域底座）：以 zh 侧同名模块为类型
 * 约束，键集编译期对齐（缺译 / 多译都过不了 tsc）；域收口在本模块
 * 内追加。
 */
import type { account as zhAccount } from '../zh/account';

export const account: typeof zhAccount = {
  // ---- Layout / routes / entry ---------------------------------------------
  'account.personalCenter': 'Account Center',
  'account.profileTitle': 'Profile',
  'account.securityTitle': 'Security',
  'account.auditTitle': 'Sign-in History',
  'account.logout': 'Sign out',
  'account.appTitle': 'Authloft User Center',
  'account.routeNotFound': 'Page not found',
  'account.renderError': 'This page hit an unexpected error. Please refresh and try again',

  // ---- SecurityPage (passkey card title reuses factors.webauthn) ----------
  'account.configLoadFailed': 'Failed to load settings. Please refresh and try again',
  'account.close': 'Close',
  'account.twoFactorTitle': 'Two-Step Verification',
  'account.mfaEnabledStatus': 'Two-step verification is on',
  'account.mfaDisabledStatus': 'Two-step verification is off',
  'account.mfaRequiredNote': ' (required by policy and cannot be turned off)',
  'account.trustDeviceNote':
    'Trusted devices: not supported yet (second verification is required at every sign-in)',
  'account.passwordCardTitle': 'Sign-in password',
  'account.contactCardTitle': 'Contact Information',
  'account.thirdpartyCardTitle': 'Third-Party Accounts',

  // ---- ProfilePage ---------------------------------------------------------
  'account.profileLoadFailed': 'Failed to load profile. Please refresh and try again',
  'account.avatarAlt': 'User avatar',
  'account.usernameLabel': 'Username',
  'account.nicknameLabel': 'Nickname',

  // ---- api.ts display helpers (unknown fallback reuses errors.code.unknown)
  'account.mfaNotBound': 'Not bound yet',
  'account.mfaLastUsedAt': ' · Last used {time}',
  'account.boundAt': 'Linked at {time}',
  'account.mfaTarget': 'Target {target}',
  'account.mfaCredentialCount': '{count} credentials linked',
  'account.mfaRemainingCount': '{count} remaining',
  'account.bindTargetTaken': 'This account is already linked to another account',
  'account.bindSuccess': 'Third-party account linked successfully',

  // ---- ThirdPartyList (refresh hint reuses common.refreshAndRetry) ---------
  'account.unionTag': 'Federated identity',
  'account.unbindConfirm': 'Unlink "{name}"? You will no longer be able to sign in with it.',
  'account.unbindAction': 'Unlink',
  // unbind success feedback (P1-6, unified Semi Toast success channel).
  'account.unbindSuccess': 'Unlinked "{name}"',
  'account.bindAction': 'Link',
  'account.thirdpartyLoadFailed':
    'Failed to load third-party accounts. Please refresh and try again',
  'account.thirdpartyEmpty': 'No third-party accounts linked yet',
  'account.thirdpartyAvailableTitle': 'Available third-party accounts',

  // ---- RecoveryCodePanel ---------------------------------------------------
  'account.recoveryNotice': 'Recovery codes are shown only once. Copy and save them somewhere safe',
  'account.recoveryIssuedAt': 'Issued at: {time}',
  'account.recoveryRegenerateConfirm':
    'Regenerating will invalidate all existing recovery codes. Continue?',
  'account.recoveryRegenerate': 'Regenerate',
  // download as text (P2-3, pure frontend Blob download).
  'account.recoveryDownload': 'Download as text',

  // ---- MfaMethodList (factor names reuse factors.*, the recovery-code
  //      modal title reuses factors.recovery_code, the bind button reuses
  //      account.bindAction, the not-bound text reuses account.mfaNotBound,
  //      the "last used" fragment reuses account.mfaLastUsedAt) ---------------
  'account.factorTotp': 'TOTP authenticator code',
  'account.factorBoundTag': 'Linked',
  'account.factorUnboundTag': 'Not linked',
  'account.mfaEnableFactorAria': 'Enable {factor}',
  'account.mfaBindPhoneHint': 'Link a phone number under "Contact Information" first',
  'account.mfaBindEmailHint': 'Link an email address under "Contact Information" first',
  'account.mfaBindWebauthnHint': 'Register one under "Passkeys" below first',
  'account.mfaLocked': 'Policy requires two-step verification; it cannot be fully turned off',
  'account.mfaShowDetails': 'Linked details',
  'account.mfaHideDetails': 'Hide details',
  'account.mfaDetailsLoadFailed': 'Failed to load details: {error}',
  'account.viewRecoveryCodes': 'View recovery codes',
  'account.recoveryIssuedAtLabel': 'Recovery codes issued at',
  'account.recoveryLoadFailed': 'Failed to load recovery codes',

  // ---- WebauthnList ---------------------------------------------------------
  'account.webauthnLabelPlaceholder': 'Name this passkey (optional)',
  'account.webauthnRegisterAction': 'Register passkey',
  'account.webauthnCancelled': 'Passkey registration was cancelled',
  'account.webauthnRegisterFailed': 'Failed to register the passkey. Please try again',
  'account.webauthnLoadFailed': 'Failed to load passkeys. Please refresh and try again',
  'account.webauthnEmpty': 'No passkeys registered yet',
  'account.webauthnUnsupported': 'Passkeys are not supported by this browser or device',
  'account.saveAction': 'Save',
  'account.cancelAction': 'Cancel',
  'account.unnamedCredential': 'Unnamed',
  'account.webauthnAddedAt': 'Added at {time}',
  'account.webauthnRenameAction': 'Rename',
  'account.webauthnDeleteConfirm': 'Delete "{name}"? You will no longer be able to sign in with it.',
  'account.deleteAction': 'Delete',

  // ---- ContactBindForm (the captcha hint reuses errors.status.captcha_required,
  //      the email kind label reuses channels.email) ---------------------------
  'account.phoneLabel': 'Phone number',
  'account.bindInvalidPhone': 'Enter a valid phone number',
  'account.bindInvalidEmail': 'Enter a valid email address',
  'account.bindCodeInvalid': 'Enter the {count}-digit verification code',
  'account.bindDone': '{kind} linked successfully',
  'account.bindContinue': 'Link another / change',
  'account.bindCodeSentToPrefix': 'Verification code sent to',
  'account.bindCodeAria': '{kind} binding code',
  'account.bindConfirmAction': 'Confirm',
  'account.bindResendAction': 'Resend',
  'account.phonePlaceholder': 'Enter a phone number',
  'account.emailPlaceholder': 'Enter an email address',
  'account.sendCodeAction': 'Send code',

  // ---- ThirdPartyBindDialog -------------------------------------------------
  'account.qrNeedCaptcha': 'Please complete the verification first',
  'account.fetchQrcodeAction': 'Get QR code',
  'account.qrBindHint': 'Scanning will link it to your current account',
  'account.scanBindTitle': 'Scan to link',
  'account.bindNameTitle': 'Link {name}',

  // ---- PasswordChangeForm ----------------------------------------------------
  'account.currentPasswordRequired': 'Enter your current password',
  'account.currentPasswordIncorrect': 'The current password is incorrect',
  'account.passwordChangedDone':
    'Password changed. You have been signed out. Please sign in again',
  'account.currentPasswordLabel': 'Current password',
  'account.newPasswordLabel': 'New password',
  'account.changePasswordAction': 'Change password',
  'account.setPasswordAction': 'Set password',

  // ---- AvatarUploader (the avatar alt reuses account.avatarAlt) -------------
  'account.uploadProgress': 'Uploading {percent}%',
  'account.avatarChooseFileAria': 'Choose an avatar file',
  'account.avatarUploadAction': 'Upload avatar',

  // ---- TotpBindDialog (the retry button reuses common.retry, the
  //      code aria-label reuses account.factorTotp) -----------------------------
  'account.totpCodeInvalid': 'Enter the {count}-digit code',
  'account.totpBindTitle': 'Link TOTP authenticator',
  'account.totpBindSuccess':
    'TOTP linked successfully. The 10 recovery codes below are shown only once — save them somewhere safe',
  'account.totpDoneAction': 'Saved. Finish linking',
  'account.totpManualHint':
    'Use an authenticator app (such as Google Authenticator) to enter the key manually or paste the otpauth URL, then enter the current 6-digit code to verify',
  'account.totpSecretLabel': 'Secret key',
  'account.totpOtpauthLabel': 'otpauth URL',
  'account.totpVerifyAction': 'Verify and finish linking',

  // ---- TotpBindDialog QR code (the key / otpauth text fallback keeps
  //      totpSecretLabel / totpOtpauthLabel / totpManualHint, not removed) ------
  'account.totpScanHint':
    'Scan the QR code with your authenticator app (such as Google Authenticator) to add it',
  'account.totpQrImageAlt': 'TOTP binding QR code',

  // ---- EventLogTable -----------------------------------------------------------
  'account.logTimeColumn': 'Time',
  'account.logMethodColumn': 'Method',
  'account.logUaColumn': 'Device (UA)',
  'account.logLoadFailed': 'Failed to load sign-in history. Please refresh and try again',
  'account.logEmpty': 'No sign-in records yet',

  // ---- ProfilePage editing (save / cancel reuse saveAction / cancelAction,
  //      phone label reuses phoneLabel; avatar persist failure reuses
  //      errors.status.failed) --------------------------------------------------
  'account.profileEditAction': 'Edit Profile',
  // save success feedback (P1-6, unified Semi Toast success channel).
  'account.profileSaved': 'Profile saved',
  'account.emailLabel': 'Email',
  'account.genderLabel': 'Gender',
  'account.genderSecret': 'Prefer not to say',
  'account.genderMale': 'Male',
  'account.genderFemale': 'Female',
  'account.birthdayLabel': 'Birthday',
  'account.localeLabel': 'Locale',
  'account.timezoneLabel': 'Time Zone',
  'account.extraLabel': 'Extra',
  'account.extraPlaceholder': '{"key": "value"}',
  'account.extraInvalidJson': 'Extra must be a valid JSON object',
  'account.birthdayInvalid': 'Enter a valid date (YYYY-MM-DD)',
};

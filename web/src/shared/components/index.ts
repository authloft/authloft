/**
 * shared/components 桶导出（docs/前端架构.md §3.3）：零第三方 UI 依赖的
 * login / account 共用表单组件。
 *
 * 禁止在本桶 re-export 任何依赖 Semi 的模块：login 族页面经本桶导入，
 * semi-ui 大包入口被 sideEffects 标记为有副作用（tree-shaking 摇不掉），
 * 一旦进桶会把整包 semi 夹带进 login 族三张壳的 initial chunks。依赖 Semi
 * 的共用组件落 shared/app-ui（CopyButton 先例），消费方深路径直引。
 */
export {
  CodeInput,
  DEFAULT_CODE_LENGTH,
  pasteValue,
  applyChar,
  applyBackspace,
  type CodeInputProps,
  type CodeEditResult,
} from './CodeInput';
export {
  FieldRenderer,
  controlKindFor,
  codeLengthOf,
  type FieldRendererProps,
  type ControlKind,
} from './FieldRenderer';
export {
  PhoneInput,
  splitE164,
  normalizeNational,
  joinE164,
  DIAL_CODES,
  DEFAULT_DIAL_CODE,
  type PhoneInputProps,
  type DialCodeEntry,
} from './PhoneInput';
export {
  ErrorBanner,
  errorText,
  attemptsCount,
  type ErrorBannerProps,
} from './ErrorBanner';
export { Spinner, type SpinnerProps } from './Spinner';
export { Tabs } from './Tabs';
export {
  StepUpDialog,
  StepUpDialogView,
  factorLabel,
  isStepUpOtpMethod,
  isStepUpWebAuthn,
  runStepUpStart,
  stepUpAuthenticate,
  stepUpErrorText,
  stepUpFields,
  stepUpOkDisabled,
  stepUpPayload,
  stepUpStartMode,
  type StepUpAuthResult,
  type StepUpAuthenticateDeps,
  type StepUpDialogProps,
  type StepUpDialogViewProps,
  type StepUpPhase,
} from './StepUpDialog';
export {
  QRCodeDialog,
  createQRDialogController,
  qrDialogPhase,
  qrPanelLifecycle,
  type QRCodeDialogProps,
} from './QRCodeDialog';

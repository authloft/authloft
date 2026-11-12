/**
 * shared/components 桶导出（docs/前端架构.md §3.3）：零第三方 UI 依赖的
 * login / account 共用表单组件。
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
  ErrorBanner,
  errorText,
  attemptsCount,
  type ErrorBannerProps,
} from './ErrorBanner';
export { CopyButton, type CopyButtonProps } from './CopyButton';
export { Spinner, type SpinnerProps } from './Spinner';
export {
  StepUpDialog,
  StepUpDialogView,
  factorLabel,
  stepUpFields,
  stepUpPayload,
  type StepUpDialogProps,
  type StepUpDialogViewProps,
  type StepUpPhase,
} from './StepUpDialog';

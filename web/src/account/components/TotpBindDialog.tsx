/**
 * TOTP 绑定对话框（步骤化交互重构；docs/前端架构.md §5 行 485；
 * docs/接口文档.md §3.5 行 905-906）：两步同端点 BindTotp——打开即
 * step=challenge{空串} 取 {secret, otpauthUrl, qrcodeContent}；用户添加后
 * 输入 6 位动态码（CodeInput 复用，§2.1 codeLength 6，整段粘贴自动分格），
 * step=verify{secret, code} → {recoveryCodes}（验证一次后生效，同一响应
 * 一次性下发 10 个恢复码，行 906）。
 *
 * 交互补齐：
 * - **步骤指示**：Semi Steps 三段（添加验证器 → 验证动态码 → 保存恢复码），
 *   current 随帧推进；
 * - **可返回上一步**：扫码帧（二维码 / 密钥 / otpauth + CopyButton，复制
 *   「已复制」反馈为 CopyButton 既有能力）与输码帧拆开，输码帧带「上一步」
 *   回扫码帧（challenge 不重新发起，secret 不变）；
 * - **OTP 自动聚焦**：进入输码帧即聚焦 CodeInput 首格（经其 id prop
 *   getElementById——组件壳内 DOM 逃生口，不改 shared）；
 * - verify 成功帧直接内嵌 RecoveryCodePanel 一次性展示（§5 行 485「直接交
 *   给 RecoveryCodePanel」），用户确认已保存后经 onDone 上抛。
 *
 * 【二维码绘制（2026-11-06 引库口径落地）】challenge 下发的
 * qrcodeContent（行 922「前端绘制二维码」）经 shared/components/QrImage 自绘
 * SVG 码图（qrcode-generator@2.0.4，零传递依赖，纯 DOM 无脚本 → CSP 安全）；
 * 空串按零值兜底回退同源的 otpauthUrl（§9.18）。码图生成失败（超容量等）
 * QrImage 渲染 null，下方密钥 + otpauthUrl 文本兜底保留不删（码图失败 /
 * 手动输入场景回退，交付语义不变）。
 * 文案经 shared/i18n（account.* 域键 + common.retry 复用）。
 */
import { useEffect, useState, type ReactNode } from 'react';
import { Button, Modal, Spin, Steps } from '@douyinfe/semi-ui-19';
import { CodeInput, DEFAULT_CODE_LENGTH } from '../../shared/components/CodeInput';
import { CopyButton } from '../../shared/components/CopyButton';
import { QrImage } from '../../shared/components/QrImage';
import { useRequest } from '../../shared/hooks/useRequest';
import { t } from '../../shared/i18n';
import {
  apiErrorText,
  bindTotp,
  buildBindTotpChallengeRequest,
  buildBindTotpVerifyRequest,
} from '../api';
import { RecoveryCodePanel } from './RecoveryCodePanel';
import styles from './TotpBindDialog.module.less';

/** CodeInput 首格 id（自动聚焦锚点；label htmlFor 关联复用同一 id 口径）。 */
const CODE_INPUT_FIRST_ID = 'totp-bind-code-input';

/**
 * TOTP 绑定状态壳（ContactBindForm 同款两 useRequest 模式）：
 * 打开（visible 翻转）→ 重置本地态 + 发起 challenge；verify 成功 → 恢复码帧。
 * Modal 的 X / 遮罩关闭在恢复码帧路由到 onDone（绑定已生效，父级仍需刷新）。
 */
export function TotpBindDialog(props: {
  readonly visible: boolean;
  /** 未完成绑定时的关闭（父级仅关框）。 */
  readonly onCancel: () => void;
  /** 绑定完成（含恢复码帧的 X / 遮罩关闭）：父级关框 + 刷新 mfaPolicy / GetMfa。 */
  readonly onDone: () => void;
}): ReactNode {
  const {
    status: challengeStatus,
    data: challenge,
    error: challengeError,
    run: runChallenge,
    reset: resetChallenge,
  } = useRequest(bindTotp);
  const {
    status: verifyStatus,
    data: verifyData,
    error: verifyError,
    run: runVerify,
    reset: resetVerify,
  } = useRequest(bindTotp);
  const [code, setCode] = useState('');
  const [inputError, setInputError] = useState<'invalid_code' | undefined>(undefined);
  // 扫码帧（0）/ 输码帧（1）两段；恢复码帧由 verify 成功态驱动。
  const [formStep, setFormStep] = useState<0 | 1>(0);

  // 打开 → 重置 + 发起 challenge（行 905：入参空串）；关框无清理（下次打开重置）。
  useEffect(() => {
    if (props.visible) {
      setCode('');
      setInputError(undefined);
      setFormStep(0);
      resetChallenge();
      resetVerify();
      runChallenge(buildBindTotpChallengeRequest()).catch(() => {});
    }
  }, [props.visible, runChallenge, resetChallenge, runVerify, resetVerify]);

  const verifying = verifyStatus === 'loading';
  // verify 成功帧（§3.5 行 906）：recoveryCodes 同一响应一次性交给 RecoveryCodePanel。
  const verified = verifyStatus === 'success';

  // 自动聚焦：进入输码帧即聚焦首格（直接输入 / 整段粘贴无需先点）。
  useEffect(() => {
    if (props.visible && formStep === 1 && challenge !== undefined && !verified) {
      document.getElementById(CODE_INPUT_FIRST_ID)?.focus();
    }
  }, [props.visible, formStep, challenge, verified]);

  const submitVerify = () => {
    if (challenge === undefined) {
      return;
    }
    const built = buildBindTotpVerifyRequest(challenge.secret, code);
    if (!built.ok) {
      setInputError('invalid_code');
      return;
    }
    setInputError(undefined);
    // 失败 rethrow 已入 state（apiErrorText 出文案），吞掉防 unhandled rejection。
    runVerify(built.request).catch(() => {});
  };

  const handleCancel = () => {
    if (verified) {
      // 绑定已生效：关闭视同完成，父级刷新摘要 / 明细。
      props.onDone();
      return;
    }
    props.onCancel();
  };

  return (
    <Modal title={t('account.totpBindTitle')} visible={props.visible} onCancel={handleCancel} footer={null}>
      {/* 步骤指示：添加验证器 → 验证动态码 → 保存恢复码。 */}
      <Steps current={verified ? 2 : formStep} size="small" className={styles.steps}>
        <Steps.Step title={t('account.totpStepAdd')} />
        <Steps.Step title={t('account.totpStepVerify')} />
        <Steps.Step title={t('account.totpStepRecovery')} />
      </Steps>
      {verified ? (
        <div className={styles.body}>
          <p role="status" className={styles.doneText}>
            {t('account.totpBindSuccess')}
          </p>
          <RecoveryCodePanel codes={verifyData?.recoveryCodes ?? []} />
          <Button theme="solid" onClick={props.onDone}>
            {t('account.totpDoneAction')}
          </Button>
        </div>
      ) : challengeStatus === 'loading' ? (
        <Spin />
      ) : challenge === undefined ? (
        <div className={styles.body}>
          <p role="alert" className={styles.error}>
            {apiErrorText(challengeError)}
          </p>
          <Button onClick={() => runChallenge(buildBindTotpChallengeRequest()).catch(() => {})}>
            {t('common.retry')}
          </Button>
        </div>
      ) : formStep === 0 ? (
        <div className={styles.body}>
          {/* 行 922：qrcodeContent 码图置于挑战帧显眼位（顶部）；protojson
              省略空串 → 空值按零值兜底回退同源的 otpauthUrl（§9.18）。 */}
          <QrImage
            content={challenge.qrcodeContent || challenge.otpauthUrl}
            alt={t('account.totpQrImageAlt')}
          />
          <p className={styles.hint}>{t('account.totpScanHint')}</p>
          <p className={styles.hint}>{t('account.totpManualHint')}</p>
          <div className={styles.field}>
            <span className={styles.fieldLabel}>{t('account.totpSecretLabel')}</span>
            <span className={styles.mono}>{challenge.secret}</span>
            <CopyButton text={challenge.secret} />
          </div>
          <div className={styles.field}>
            <span className={styles.fieldLabel}>{t('account.totpOtpauthLabel')}</span>
            <span className={styles.mono}>{challenge.otpauthUrl}</span>
            <CopyButton text={challenge.otpauthUrl} />
          </div>
          <Button theme="solid" onClick={() => setFormStep(1)}>
            {t('account.totpNextAction')}
          </Button>
        </div>
      ) : (
        <form
          className={styles.body}
          onSubmit={(event) => {
            event.preventDefault();
            submitVerify();
          }}
        >
          <CodeInput
            value={code}
            onChange={setCode}
            length={DEFAULT_CODE_LENGTH}
            ariaLabel={t('account.factorTotp')}
            id={CODE_INPUT_FIRST_ID}
            disabled={verifying}
          />
          {inputError !== undefined ? (
            <p role="alert" className={styles.error}>
              {t('account.totpCodeInvalid', { count: DEFAULT_CODE_LENGTH })}
            </p>
          ) : null}
          {verifyStatus === 'error' ? (
            <p role="alert" className={styles.error}>
              {apiErrorText(verifyError)}
            </p>
          ) : null}
          <div className={styles.actions}>
            <Button type="tertiary" onClick={() => setFormStep(0)} disabled={verifying}>
              {t('account.backAction')}
            </Button>
            <Button theme="solid" htmlType="submit" loading={verifying} disabled={verifying}>
              {t('account.totpVerifyAction')}
            </Button>
          </div>
        </form>
      )}
    </Modal>
  );
}

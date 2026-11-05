/**
 * TOTP 绑定对话框（docs/前端架构.md §5 行 485；docs/接口文档.md §3.5 行 905-906）：
 * 两步同端点 BindTotp——打开即 step=challenge{空串} 取 {secret, otpauthUrl,
 * qrcodeContent}；用户在验证器应用中添加后输入 6 位动态码（CodeInput 复用，
 * §2.1 codeLength 6），step=verify{secret, code} → {recoveryCodes}（验证一次
 * 后生效，同一响应一次性下发 10 个恢复码，行 906）。
 * verify 成功帧直接内嵌 RecoveryCodePanel 一次性展示（§5 行 485「直接交给
 * RecoveryCodePanel」），用户确认已保存后经 onDone 上抛（父级刷新 mfaPolicy
 * 摘要 + GetMfa 明细并关闭）。
 *
 * 【二维码绘制裁量】challenge 下发的 qrcodeContent
 * 为 otpauth:// 文本（行 905「前端绘制二维码」）；项目内无既有文本码绘制能力
 * （shared/QRCodePanel 只渲染服务端图片 URL），自绘 QR 需完整 Reed-Solomon
 * 纠错 + 掩码评估编码器（数百行高风险算法码，超出「最简」口径）→ 取约定
 * 的兜底：展示密钥 + otpauthUrl 文本（各带复制按钮，验证器应用手动输入
 * 密钥或粘贴 otpauth 地址均可完成绑定）；qrcodeContent 与 otpauthUrl 同源
 * （二维码编码内容），后续引库 / 自绘时直接消费该字段。
 * 文案无 i18n 键：中文字面量 + 注释声明，扩键归后续 i18n 实现。
 */
import { useEffect, useState, type ReactNode } from 'react';
// 子路径 import（同 ProfilePage 口径：避免全量入口，测试链 / 产物见其注释）。
import Button from '@douyinfe/semi-ui/lib/es/button';
import Modal from '@douyinfe/semi-ui/lib/es/modal';
import Spin from '@douyinfe/semi-ui/lib/es/spin';
import { CodeInput, DEFAULT_CODE_LENGTH } from '../../shared/components/CodeInput';
import { CopyButton } from '../../shared/components/CopyButton';
import { useRequest } from '../../shared/hooks/useRequest';
import {
  apiErrorText,
  bindTotp,
  buildBindTotpChallengeRequest,
  buildBindTotpVerifyRequest,
} from '../api';
import { RecoveryCodePanel } from './RecoveryCodePanel';
import styles from './TotpBindDialog.module.less';

/** 本地校验文案（i18n 无键，中文字面量，归后续 i18n 实现）。 */
const CODE_INVALID_TEXT = `请输入 ${DEFAULT_CODE_LENGTH} 位数字动态码`;
/** 验证成功帧确认按钮（§5 行 485 一次性展示后由用户确认已保存）。 */
const DONE_TEXT = '我已保存，完成绑定';

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
  const { status: challengeStatus, data: challenge, error: challengeError, run: runChallenge, reset: resetChallenge } =
    useRequest(bindTotp);
  const { status: verifyStatus, data: verifyData, error: verifyError, run: runVerify, reset: resetVerify } =
    useRequest(bindTotp);
  const [code, setCode] = useState('');
  const [inputError, setInputError] = useState<'invalid_code' | undefined>(undefined);

  // 打开 → 重置 + 发起 challenge（行 905：入参空串）；关框无清理（下次打开重置）。
  useEffect(() => {
    if (props.visible) {
      setCode('');
      setInputError(undefined);
      resetChallenge();
      resetVerify();
      runChallenge(buildBindTotpChallengeRequest()).catch(() => {});
    }
  }, [props.visible, runChallenge, resetChallenge, runVerify, resetVerify]);

  const verifying = verifyStatus === 'loading';

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

  // verify 成功帧（§3.5 行 906）：recoveryCodes 同一响应一次性交给 RecoveryCodePanel。
  const verified = verifyStatus === 'success';

  const handleCancel = () => {
    if (verified) {
      // 绑定已生效：关闭视同完成，父级刷新摘要 / 明细。
      props.onDone();
      return;
    }
    props.onCancel();
  };

  return (
    <Modal
      title="绑定 TOTP 动态码"
      visible={props.visible}
      onCancel={handleCancel}
      footer={null}
    >
      {verified ? (
        <div className={styles.body}>
          <p role="status" className={styles.doneText}>
            TOTP 绑定成功。以下 10 个恢复码仅展示一次，请妥善保存
          </p>
          <RecoveryCodePanel codes={verifyData?.recoveryCodes ?? []} />
          <Button theme="solid" onClick={props.onDone}>
            {DONE_TEXT}
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
            重试
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
          <p className={styles.hint}>
            请使用验证器应用（如 Google Authenticator）手动输入密钥或粘贴 otpauth
            地址完成添加，然后输入当前 6 位动态码验证
          </p>
          <div className={styles.field}>
            <span className={styles.fieldLabel}>密钥</span>
            <span className={styles.mono}>{challenge.secret}</span>
            <CopyButton text={challenge.secret} />
          </div>
          <div className={styles.field}>
            <span className={styles.fieldLabel}>otpauth 地址</span>
            <span className={styles.mono}>{challenge.otpauthUrl}</span>
            <CopyButton text={challenge.otpauthUrl} />
          </div>
          <CodeInput
            value={code}
            onChange={setCode}
            length={DEFAULT_CODE_LENGTH}
            ariaLabel="TOTP 动态码"
            disabled={verifying}
          />
          {inputError !== undefined ? (
            <p role="alert" className={styles.error}>
              {CODE_INVALID_TEXT}
            </p>
          ) : null}
          {verifyStatus === 'error' ? (
            <p role="alert" className={styles.error}>
              {apiErrorText(verifyError)}
            </p>
          ) : null}
          <Button theme="solid" htmlType="submit" loading={verifying} disabled={verifying}>
            验证并完成绑定
          </Button>
        </form>
      )}
    </Modal>
  );
}

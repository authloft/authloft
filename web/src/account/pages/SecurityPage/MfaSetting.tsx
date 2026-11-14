/**
 * 双因素认证区（两步验证开关行 + TOTP 因子行）：
 * - 开关行（useMfaToggleField）：Semi Switch 由 mfaPolicy.{enabled, methods[].bound}
 *   推导可用性，onChange 调 SetMfa({enabled})，成功后重取 GetConfig + Toast；
 * - 因子行（useMfaSetting）：totp 已绑定 → 行内「已绑定」+ 解绑 / 恢复码；
 *   未绑定 → 绑定（TotpBindDialog）。解绑走二次验证
 *   （docs/接口文档.md §3.5）：StepUpDialog 取得 verificationToken 后调
 *   UnbindTotp；因子集合的启用集语义随 SetMfa 改为开关后一并下线。
 * 存量恢复码不可回显（§3.5）：弹窗只提供重新生成，成功后以新码为准。
 */
import { useCallback, useState, type ReactNode } from 'react';
import { useLocation } from '@modern-js/runtime/router';
import { useRequest } from 'ahooks';
import { Button, Modal, Popconfirm, Switch, Toast } from '@douyinfe/semi-ui';
import { CaptchaDialog } from '@/shared/captcha/CaptchaDialog';
import { useCaptchaGate } from '@/shared/captcha/useCaptchaGate';
import type { MfaPolicyMethod } from '@/gen/proto/api/account/v1/profile_pb';
import type { ListItemProps } from '@/shared/components/SettingList';
import { StepUpDialog } from '@/shared/components/StepUpDialog';
import { Modal as AppModal } from '@/shared/app-ui/Modal';
import { requestOptions } from '@/shared/hooks/requestOptions';
import { t } from '@/shared/i18n';
import {
  accountReturnTo,
  apiErrorText,
  buildRegenerateRecoveryCodesRequest,
  buildSetMfaRequest,
  buildStartVerificationRequest,
  buildSubmitVerificationRequest,
  buildUnbindTotpRequest,
  deriveMfaToggleView,
  regenerateRecoveryCodes,
  setMfa,
  startVerification,
  submitVerification,
  unbindTotp,
} from '../../api';
import { RecoveryCodePanel } from './RecoveryCodePanel';
import { TotpBindDialog } from './TotpBindDialog';
import styles from './MfaSetting.module.less';

/** 恢复码弹窗内容（父级条件渲染，打开才挂载）：存量码不可回显，仅重新生成。 */
function RecoveryCodesModalBody(): ReactNode {
  const location = useLocation();
  const returnTo = () => accountReturnTo(location.pathname, location.search);
  const {
    data: regenData,
    error: regenError,
    loading: regenBusy,
    run: runRegen,
  } = useRequest(regenerateRecoveryCodes, {
    manual: true,
    ...requestOptions({ toast: false, returnTo }),
    onSuccess: () => {
      Toast.success(t('account.recoveryRegenerateSuccess'));
    },
  });
  const regenerate = () => {
    runRegen(buildRegenerateRecoveryCodesRequest());
  };

  return (
    <>
      {regenData === undefined ? (
        <>
          <p className={styles.notice}>{t('account.recoveryNotViewable')}</p>
          <Popconfirm
            title={t('account.recoveryRegenerateConfirm')}
            onConfirm={regenerate}
          >
            <Button type="tertiary" loading={regenBusy}>
              {t('account.recoveryRegenerate')}
            </Button>
          </Popconfirm>
        </>
      ) : (
        <RecoveryCodePanel
          codes={regenData.codes}
          createdAt={regenData.createdAt}
          onRegenerate={regenerate}
          regenerateBusy={regenBusy}
        />
      )}
      {regenError !== undefined ? (
        <p role="alert" className={styles.notice}>
          {apiErrorText(regenError)}
        </p>
      ) : null}
    </>
  );
}

/**
 * 两步验证开关行（SettingList field）：checked = mfaPolicy.enabled，
 * 可用性与 help 由 deriveMfaToggleView 推导；onChange 调 SetMfa({enabled})，
 * 成功后父级重取 GetConfig 刷新 mfaPolicy + Toast。
 */
export function useMfaToggleField(props: {
  /** 用户自助开关原值（mfaPolicy.enabled）。 */
  enabled: boolean;
  /** 管理员开放的因子白名单及绑定态（mfaPolicy.methods）。 */
  methods: MfaPolicyMethod[];
  /** 切换成功：父级重取 GetConfig 刷新 mfaPolicy。 */
  onPolicyRefresh: () => void;
}): ListItemProps {
  const location = useLocation();
  const returnTo = () => accountReturnTo(location.pathname, location.search);
  const { run } = useRequest(setMfa, {
    manual: true,
    ...requestOptions({ returnTo }),
    onSuccess: () => {
      Toast.success(t('account.mfaEnabledSuccess'));
      props.onPolicyRefresh();
    },
  });
  const view = deriveMfaToggleView(props.enabled, props.methods);
  return {
    key: 'mfaToggle',
    title: t('account.mfaToggleTitle'),
    help: <span className={styles.toggleHelp}>{t(view.helpKey)}</span>,
    extra: (
      <Switch
        checked={props.enabled}
        onChange={(checked: boolean) => run(buildSetMfaRequest(checked))}
        disabled={view.disabled}
      />
    ),
  };
}

/** MFA 因子行（SettingList field）：totp 绑定态驱动 help 与动作按钮。 */
export function useMfaSetting(props: {
  /** 系统开放因子摘要（GetConfig mfaPolicy.methods）。 */
  methods: MfaPolicyMethod[];
  /** 解绑 / 绑定成功：父级重取 GetConfig 刷新 mfaPolicy。 */
  onPolicyRefresh: () => void;
}): ListItemProps {
  const [totpOpen, setTotpOpen] = useState(false);
  const [recoveryOpen, setRecoveryOpen] = useState(false);
  const [stepUpOpen, setStepUpOpen] = useState(false);
  const location = useLocation();
  const returnTo = () => accountReturnTo(location.pathname, location.search);
  const { dialogProps: captchaDialogProps, run: runCaptchaGate } =
    useCaptchaGate(AppModal);

  /** 选定因子下发挑战令牌：captcha 由 gate 吸收（取消 → undefined）。 */
  const startWithCaptcha = useCallback(
    async (method: string) => {
      if (method === '') {
        return startVerification(
          buildStartVerificationRequest('unbind_totp', 'unbind_totp'),
        );
      }
      const outcome = await runCaptchaGate({
        mode: 'reactive',
        request: (captcha) =>
          startVerification(
            buildStartVerificationRequest(
              'unbind_totp',
              'unbind_totp',
              method,
              captcha,
            ),
          ),
        // 响应无流程状态字段：captcha 结论只在 ApiError 一侧。
        readOutcome: () => ({ action: 'message' }),
      });
      if (outcome.kind === 'result') {
        return outcome.result;
      }
      if (outcome.kind === 'cancelled') {
        return undefined;
      }
      throw outcome.error;
    },
    [runCaptchaGate],
  );

  const { runAsync: runUnbind } = useRequest(unbindTotp, {
    manual: true,
    ...requestOptions({ toast: false, returnTo }),
  });

  /** 二次验证通过：携带 verificationToken 调 UnbindTotp，失败由弹窗呈现。 */
  const handleVerified = async (verificationToken: string) => {
    await runUnbind(buildUnbindTotpRequest(verificationToken));
    setStepUpOpen(false);
    Toast.success(
      t('account.mfaUnbindSuccess', { factor: t('account.factorTotp') }),
    );
    props.onPolicyRefresh();
  };

  const bound =
    props.methods.find((method) => method.factor === 'totp')?.bound ?? false;

  return {
    key: 'totp',
    title: t('account.factorTotp'),
    help: bound ? t('account.factorBoundTag') : t('account.factorUnboundTag'),
    extra: (
      <>
        {bound ? (
          <>
            <Button type="danger" onClick={() => setStepUpOpen(true)}>
              {t('account.unbindAction')}
            </Button>
            <Button type="tertiary" onClick={() => setRecoveryOpen(true)}>
              {t('account.viewRecoveryCodes')}
            </Button>
          </>
        ) : (
          <Button type="tertiary" onClick={() => setTotpOpen(true)}>
            {t('account.bindAction')}
          </Button>
        )}
        {totpOpen ? (
          <TotpBindDialog
            onCancel={() => setTotpOpen(false)}
            onDone={() => {
              setTotpOpen(false);
              Toast.success(t('account.totpBindSuccess'));
              props.onPolicyRefresh();
            }}
          />
        ) : null}
        {stepUpOpen ? (
          <StepUpDialog
            modal={AppModal}
            start={startWithCaptcha}
            submit={async (challengeToken, method, payload) => {
              const response = await submitVerification(
                buildSubmitVerificationRequest(challengeToken, method, payload),
              );
              return response.verificationToken;
            }}
            onVerified={handleVerified}
            onCancel={() => setStepUpOpen(false)}
          />
        ) : null}
        <CaptchaDialog {...captchaDialogProps} />
        {recoveryOpen ? (
          <Modal
            title={t('factors.recovery_code')}
            visible
            onCancel={() => setRecoveryOpen(false)}
            okButtonProps={{ style: { display: 'none' } }}
            cancelText={t('account.cancelAction')}
          >
            <RecoveryCodesModalBody />
          </Modal>
        ) : null}
      </>
    ),
  };
}

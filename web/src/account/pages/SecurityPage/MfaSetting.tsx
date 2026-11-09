/**
 * 双因素认证行（MFA + 恢复码合并）：totp 已绑定 → 行内「已绑定」+
 * 解绑 / 查看恢复码；未绑定 → 绑定（TotpBindDialog）。
 * 解绑无独立接口（docs/接口文档.md §3.5 行 927）：经 SetMfa 全量集合
 * 移除 totp；required=true 时 buildSetMfaRequest 本地拒绝不发包。
 * 恢复码弹窗打开才挂载（新实例无旧码 / 旧错误残留），挂载即取
 * GetRecoveryCodes；重新生成成功以新码为准（失败保留旧码）。
 */
import { useState, type ReactNode } from 'react';
import { useLocation } from '@modern-js/runtime/router';
import { useRequest } from 'ahooks';
import { Button, Modal, Popconfirm, Spin, Toast } from '@douyinfe/semi-ui';
import type { MfaPolicyMethod } from '@/gen/proto/api/account/v1/profile_pb';
import type { ListItemProps } from '@/shared/components/SettingList';
import { requestOptions } from '@/shared/hooks/requestOptions';
import { t } from '@/shared/i18n';
import {
  accountReturnTo,
  apiErrorText,
  buildRegenerateRecoveryCodesRequest,
  buildSetMfaRequest,
  getRecoveryCodes,
  regenerateRecoveryCodes,
  setMfa,
} from '../../api';
import { RecoveryCodePanel } from './RecoveryCodePanel';
import { TotpBindDialog } from './TotpBindDialog';
import styles from './MfaSetting.module.less';

/** 恢复码弹窗内容（父级条件渲染，打开才挂载）：GetRecoveryCodes + 重新生成。 */
function RecoveryCodesModalBody(): ReactNode {
  const location = useLocation();
  const returnTo = () => accountReturnTo(location.pathname, location.search);
  const {
    data: recoveryData,
    error: recoveryError,
    loading: recoveryLoading,
  } = useRequest(getRecoveryCodes, requestOptions({ toast: false, returnTo }));
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

  const codesView = regenData ?? recoveryData;
  const initialLoading =
    recoveryLoading && recoveryData === undefined && regenData === undefined;

  return (
    <>
      {initialLoading ? (
        <Spin />
      ) : codesView === undefined ? (
        <p role="alert" className={styles.notice}>
          {recoveryError !== undefined
            ? apiErrorText(recoveryError)
            : t('account.recoveryLoadFailed')}
        </p>
      ) : (
        <RecoveryCodePanel
          codes={codesView.codes}
          createdAt={codesView.createdAt}
          onRegenerate={() => {
            runRegen(buildRegenerateRecoveryCodesRequest());
          }}
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

/** MFA 行（SettingList field）：totp 绑定态驱动 help 与动作按钮。 */
export function useMfaSetting(props: {
  /** 系统开放因子摘要（GetConfig mfaPolicy.methods）。 */
  methods: MfaPolicyMethod[];
  /** 策略强制（true 时不可解绑）。 */
  required: boolean;
  /** 解绑 / 绑定成功：父级重取 GetConfig 刷新 mfaPolicy。 */
  onPolicyRefresh: () => void;
}): ListItemProps {
  const [totpOpen, setTotpOpen] = useState(false);
  const [recoveryOpen, setRecoveryOpen] = useState(false);
  const location = useLocation();
  const returnTo = () => accountReturnTo(location.pathname, location.search);

  const { loading: unbinding, run: runUnbind } = useRequest(setMfa, {
    manual: true,
    ...requestOptions({ returnTo }),
    onSuccess: () => {
      Toast.success(
        t('account.mfaUnbindSuccess', { factor: t('account.factorTotp') }),
      );
      props.onPolicyRefresh();
    },
  });

  const handleUnbind = () => {
    const built = buildSetMfaRequest(
      props.methods,
      'totp',
      false,
      props.required,
    );
    if (!built.ok) {
      Toast.error(t('account.mfaLocked'));
      return;
    }
    runUnbind(built.request);
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
            <Popconfirm
              title={t('account.mfaUnbindConfirm', {
                factor: t('account.factorTotp'),
              })}
              onConfirm={handleUnbind}
            >
              <Button type="danger" loading={unbinding}>
                {t('account.unbindAction')}
              </Button>
            </Popconfirm>
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
              Toast.success(
                t('account.mfaEnabledSuccess', {
                  factor: t('account.factorTotp'),
                }),
              );
              props.onPolicyRefresh();
            }}
          />
        ) : null}
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

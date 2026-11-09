/**
 * 通行密钥行：左侧「已绑定 X 个」，右侧「查看已绑定」（未绑定置灰）+
 * 「新增」。查看弹窗复用 WebauthnList（重命名 / 删除）；新增弹窗走
 * registerWebauthnCredential 三步编排（challenge → startRegistration →
 * verify，./api node 可测）。window.PublicKeyCredential 缺失隐藏新增入口
 * （需求 §4.1.6 行 105）；用户取消与失败分开提示。
 */
import { useState, type ReactNode } from 'react';
import { useLocation } from '@modern-js/runtime/router';
import { useRequest } from 'ahooks';
import { Button, Input, Modal, Toast } from '@douyinfe/semi-ui';
import type { ListItemProps } from '@/shared/components/SettingList';
import { requestOptions } from '@/shared/hooks/requestOptions';
import { t } from '@/shared/i18n';
import {
  accountReturnTo,
  getWebauthnCredentials,
  registerWebauthnCredential,
} from '../../api';
import { WebauthnList, webauthnAvailable } from './WebauthnList';
import styles from './WebauthnSetting.module.less';

/** 新增通行密钥弹窗（父级条件渲染，打开才挂载）：命名（可选）+ 注册编排。 */
function WebauthnAddDialog(props: {
  onCancel: () => void;
  /** 注册成功：父级关框 + 刷新凭据数。 */
  onDone: () => void;
}): ReactNode {
  const [label, setLabel] = useState('');

  const { run: handleRegister, loading: registering } = useRequest(
    () => registerWebauthnCredential(label),
    {
      manual: true,
      onSuccess: (result) => {
        if (result.ok) {
          props.onDone();
        } else if (result.cancelled) {
          Toast.warning(t('account.webauthnCancelled'));
        } else {
          Toast.error(t('account.webauthnRegisterFailed'));
        }
      },
    },
  );

  return (
    <Modal
      title={t('account.webauthnAddTitle')}
      visible
      okButtonProps={{ style: { display: 'none' } }}
      cancelText={t('account.cancelAction')}
      onCancel={props.onCancel}
    >
      <div className={styles.register}>
        <Input
          value={label}
          onChange={setLabel}
          placeholder={t('account.webauthnLabelPlaceholder')}
          disabled={registering}
        />
        <Button
          theme="solid"
          loading={registering}
          disabled={registering}
          onClick={() => void handleRegister()}
        >
          {t('account.webauthnRegisterAction')}
        </Button>
      </div>
    </Modal>
  );
}

/** 通行密钥行（SettingList field）：凭据数驱动 help 与「查看已绑定」置灰。 */
export function useWebauthnSetting(): ListItemProps {
  const available = webauthnAvailable();
  const location = useLocation();
  const { data, refresh } = useRequest(
    getWebauthnCredentials,
    requestOptions({
      toast: false,
      returnTo: () => accountReturnTo(location.pathname, location.search),
    }),
  );
  const [viewOpen, setViewOpen] = useState(false);
  const [addOpen, setAddOpen] = useState(false);
  const count = data?.items.length ?? 0;

  return {
    key: 'webauthn',
    title: t('factors.webauthn'),
    help:
      data === undefined
        ? undefined
        : count > 0
          ? t('account.webauthnBoundCount', { count })
          : t('account.factorUnboundTag'),
    extra: (
      <>
        <Button
          type="tertiary"
          disabled={count === 0}
          onClick={() => setViewOpen(true)}
        >
          {t('account.webauthnViewBound')}
        </Button>
        {available ? (
          <Button type="tertiary" onClick={() => setAddOpen(true)}>
            {t('account.addAction')}
          </Button>
        ) : null}
        {viewOpen ? (
          <Modal
            title={t('factors.webauthn')}
            visible
            onCancel={() => setViewOpen(false)}
            okButtonProps={{ style: { display: 'none' } }}
            cancelText={t('account.cancelAction')}
          >
            <WebauthnList onChanged={refresh} />
          </Modal>
        ) : null}
        {addOpen ? (
          <WebauthnAddDialog
            onCancel={() => setAddOpen(false)}
            onDone={() => {
              setAddOpen(false);
              Toast.success(t('account.webauthnRegisterSuccess'));
              refresh();
            }}
          />
        ) : null}
      </>
    ),
  };
}

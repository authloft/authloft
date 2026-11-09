/**
 * 通行密钥列表（docs/前端架构.md §5 行 487；docs/接口文档.md §3.6 行 911-931；
 * 需求 §4.1.6）：GetWebauthnCredentials 列表 {id,label,createdAt,lastUsedAt,
 * transports,aaguid}（行 914）+ 注册（resident key / 可发现凭据，需求行 106）+
 * 重命名 {id,label}（行 917）+ 删除 {id}（行 918）；写操作成功后刷新列表并经
 * onChanged 上抛——首枚凭据注册 / 末枚删除会翻转 mfaPolicy.webauthn.bound，
 * 父级（SecurityPage）重取 GetConfig 并递增 MFA 明细 detailVersion。
 *
 * 注册编排在 ./api 的 registerWebauthnCredential（node 可测）：challenge →
 * startRegistration（challengeData 整体透传 §12.9 方案 A，前端不解析 options）
 * → verify {token, credential, label}（token 前端不感知结构仅透传，行 930）。
 * window.PublicKeyCredential 缺失隐藏注册入口（需求 §4.1.6 行 105 不支持自动
 * 不展示，login 端 WebAuthnButton 同口径）；用户取消（NotAllowedError）与失败
 * 分开提示（§4.3 行 453 错误语义独立）。
 * 文案经 shared/i18n（account.* 域键）。
 */
import { useState, type ReactNode } from 'react';
import { useLocation } from '@modern-js/runtime/router';
import { useRequest } from 'ahooks';
import { Button, Empty, Input, Popconfirm, Spin, Tag } from '@douyinfe/semi-ui';
import type { WebauthnCredential } from '../../gen/proto/api/account/v1/webauthn_pb';
import { requestOptions } from '../../shared/hooks/requestOptions';
import { t } from '../../shared/i18n';
import {
  accountReturnTo,
  buildDeleteWebauthnRequest,
  buildRenameWebauthnRequest,
  deleteWebauthnCredential,
  formatUnixTime,
  getWebauthnCredentials,
  registerWebauthnCredential,
  renameWebauthnCredential,
} from '../api';
import styles from './WebauthnList.module.less';

/** window.PublicKeyCredential 缺失隐藏注册入口（需求 §4.1.6 行 105；node 无 window）。 */
function webauthnAvailable(): boolean {
  return typeof window !== 'undefined' && 'PublicKeyCredential' in window;
}

export function WebauthnList(props: {
  /** 注册 / 删除成功回调：父级刷新 mfaPolicy（webauthn.bound 可能翻转）。 */
  onChanged?: () => void;
}): ReactNode {
  const available = webauthnAvailable();
  const location = useLocation();
  const returnTo = () => accountReturnTo(location.pathname, location.search);
  // 列表自动请求（挂载即取）；错误行内呈现（toast:false 防双报）。
  const { data, error, loading, refresh } = useRequest(
    getWebauthnCredentials,
    requestOptions({ toast: false, returnTo }),
  );
  // 重命名 / 删除（手动）：错误行内呈现；成功链走 onSuccess（重取列表 +
  // 翻转上抛，删除会翻转 mfaPolicy.webauthn.bound）。
  const rename = useRequest(renameWebauthnCredential, {
    manual: true,
    ...requestOptions({ toast: false, returnTo }),
    onSuccess: () => {
      setRenamingId(undefined);
      refresh();
    },
  });
  const del = useRequest(deleteWebauthnCredential, {
    manual: true,
    ...requestOptions({ toast: false, returnTo }),
    onSuccess: () => {
      refresh();
      props.onChanged?.();
    },
  });
  const [notice, setNotice] = useState<'cancelled' | 'failed' | null>(null);
  const [registering, setRegistering] = useState(false);
  const [label, setLabel] = useState('');
  const [renamingId, setRenamingId] = useState<bigint | undefined>(undefined);
  const [renameLabel, setRenameLabel] = useState('');

  // 注册三步编排（./api）：成功 → 清 label + 刷新列表 + onChanged 上抛。
  const handleRegister = async () => {
    if (registering) {
      return;
    }
    setNotice(null);
    setRegistering(true);
    try {
      const result = await registerWebauthnCredential(label);
      if (result.ok) {
        setLabel('');
        refresh();
        props.onChanged?.();
      } else {
        setNotice(result.cancelled ? 'cancelled' : 'failed');
      }
    } finally {
      setRegistering(false);
    }
  };

  const startRename = (item: WebauthnCredential) => {
    setRenamingId(item.id);
    setRenameLabel(item.label);
  };

  const submitRename = () => {
    const trimmed = renameLabel.trim();
    if (renamingId === undefined || trimmed === '') {
      return;
    }
    rename.run(buildRenameWebauthnRequest(renamingId, trimmed));
  };

  const handleDelete = (id: bigint) => {
    del.run(buildDeleteWebauthnRequest(id));
  };

  const items = data?.items;

  return (
    <div className={styles.wrap}>
      {available ? (
        <div className={styles.register}>
          <Input
            className={styles.registerLabel}
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
      ) : null}
      {notice === 'cancelled' ? (
        <p role="alert" className={styles.notice}>
          {t('account.webauthnCancelled')}
        </p>
      ) : null}
      {notice === 'failed' ? (
        <p role="alert" className={styles.notice}>
          {t('account.webauthnRegisterFailed')}
        </p>
      ) : null}
      {loading && items === undefined ? (
        <Spin />
      ) : error !== undefined && items === undefined ? (
        <p role="alert" className={styles.error}>
          {t('account.webauthnLoadFailed')}
        </p>
      ) : items === undefined || items.length === 0 ? (
        // 空态裸文字 → Semi Empty（§9.3 映射表）。
        <Empty
          description={
            available
              ? t('account.webauthnEmpty')
              : t('account.webauthnUnsupported')
          }
        />
      ) : (
        <ul className={styles.list}>
          {items.map((item) => (
            <li key={item.id.toString()} className={styles.row}>
              {renamingId === item.id ? (
                <>
                  <div className={styles.rowMain}>
                    <Input
                      className={styles.renameInput}
                      value={renameLabel}
                      onChange={setRenameLabel}
                      disabled={rename.loading}
                    />
                  </div>
                  <div className={styles.rowActions}>
                    <Button
                      size="small"
                      loading={rename.loading}
                      disabled={rename.loading || renameLabel.trim() === ''}
                      onClick={submitRename}
                    >
                      {t('account.saveAction')}
                    </Button>
                    <Button
                      size="small"
                      type="tertiary"
                      onClick={() => setRenamingId(undefined)}
                    >
                      {t('account.cancelAction')}
                    </Button>
                  </div>
                </>
              ) : (
                <>
                  <div className={styles.rowMain}>
                    <span className={styles.label}>
                      {item.label === ''
                        ? t('account.unnamedCredential')
                        : item.label}
                    </span>
                    {item.transports.map((transport) => (
                      <Tag key={transport} size="small" color="grey">
                        {transport}
                      </Tag>
                    ))}
                    <span className={styles.times}>
                      {t('account.webauthnAddedAt', {
                        time: formatUnixTime(item.createdAt),
                      })}
                      {t('account.mfaLastUsedAt', {
                        time: formatUnixTime(item.lastUsedAt),
                      })}
                    </span>
                    {item.aaguid !== '' ? (
                      <span className={styles.aaguid}>
                        AAGUID {item.aaguid}
                      </span>
                    ) : null}
                  </div>
                  <div className={styles.rowActions}>
                    <Button size="small" onClick={() => startRename(item)}>
                      {t('account.webauthnRenameAction')}
                    </Button>
                    <Popconfirm
                      title={t('account.webauthnDeleteConfirm', {
                        name:
                          item.label === ''
                            ? t('account.unnamedCredential')
                            : item.label,
                      })}
                      onConfirm={() => handleDelete(item.id)}
                    >
                      <Button size="small" type="danger" loading={del.loading}>
                        {t('account.deleteAction')}
                      </Button>
                    </Popconfirm>
                  </div>
                </>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

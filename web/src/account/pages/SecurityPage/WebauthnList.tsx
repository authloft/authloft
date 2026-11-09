/**
 * 通行密钥列表（docs/接口文档.md §3.6 行 911-931）：GetWebauthnCredentials
 * 列表 {id,label,createdAt,lastUsedAt,transports,aaguid} + 重命名 {id,label} +
 * 删除 {id}；删除成功后刷新列表并经 onChanged 上抛（父级刷新凭据数）。
 * 注册入口归 WebauthnSetting 的「新增」弹窗，本组件只做已绑定管理。
 * 文案经 shared/i18n（account.* 域键）。
 */
import { useState, type ReactNode } from 'react';
import { useLocation } from '@modern-js/runtime/router';
import { useRequest } from 'ahooks';
import { Button, Empty, Input, Popconfirm, Spin, Tag } from '@douyinfe/semi-ui';
import type { WebauthnCredential } from '../../../gen/proto/api/account/v1/webauthn_pb';
import { requestOptions } from '../../../shared/hooks/requestOptions';
import { t } from '../../../shared/i18n';
import {
  accountReturnTo,
  buildDeleteWebauthnRequest,
  buildRenameWebauthnRequest,
  deleteWebauthnCredential,
  formatUnixTime,
  getWebauthnCredentials,
  renameWebauthnCredential,
} from '../../api';
import styles from './WebauthnList.module.less';

/** window.PublicKeyCredential 缺失隐藏注册入口（需求 §4.1.6 行 105；node 无 window）。 */
export function webauthnAvailable(): boolean {
  return typeof window !== 'undefined' && 'PublicKeyCredential' in window;
}

export function WebauthnList(props: {
  /** 删除成功回调：父级刷新凭据数。 */
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
  const [renamingId, setRenamingId] = useState<bigint | undefined>(undefined);
  const [renameLabel, setRenameLabel] = useState('');

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

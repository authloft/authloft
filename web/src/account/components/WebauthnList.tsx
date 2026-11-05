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
import { useEffect, useState, type ReactNode } from 'react';
import { Button, Input, Popconfirm, Spin, Tag } from '@douyinfe/semi-ui-19';
import type { WebauthnCredential } from '../../gen/proto/api/account/v1/webauthn_pb';
import { useRequest } from '../../shared/hooks/useRequest';
import { t } from '../../shared/i18n';
import {
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
  readonly onChanged?: () => void;
}): ReactNode {
  const available = webauthnAvailable();
  const { data, status, run } = useRequest(getWebauthnCredentials);
  const { status: renameStatus, run: runRename } = useRequest(renameWebauthnCredential);
  const { status: deleteStatus, run: runDelete } = useRequest(deleteWebauthnCredential);
  const [notice, setNotice] = useState<'cancelled' | 'failed' | null>(null);
  const [registering, setRegistering] = useState(false);
  const [label, setLabel] = useState('');
  const [renamingId, setRenamingId] = useState<bigint | undefined>(undefined);
  const [renameLabel, setRenameLabel] = useState('');

  useEffect(() => {
    run().catch(() => {});
  }, [run]);

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
        run().catch(() => {});
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
    runRename(buildRenameWebauthnRequest(renamingId, trimmed))
      .then((result) => {
        if (result !== undefined) {
          setRenamingId(undefined);
          run().catch(() => {});
        }
      })
      .catch(() => {});
  };

  const handleDelete = (id: bigint) => {
    runDelete(buildDeleteWebauthnRequest(id))
      .then((result) => {
        if (result !== undefined) {
          run().catch(() => {});
          props.onChanged?.();
        }
      })
      .catch(() => {});
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
      {status === 'loading' && items === undefined ? (
        <Spin />
      ) : status === 'error' && items === undefined ? (
        <p role="alert" className={styles.error}>
          {t('account.webauthnLoadFailed')}
        </p>
      ) : items === undefined || items.length === 0 ? (
        <p className={styles.empty}>
          {available ? t('account.webauthnEmpty') : t('account.webauthnUnsupported')}
        </p>
      ) : (
        <ul className={styles.list}>
          {items.map((item) => (
            <li key={item.id.toString()} className={styles.row}>
              {renamingId === item.id ? (
                <>
                  <Input
                    className={styles.renameInput}
                    value={renameLabel}
                    onChange={setRenameLabel}
                    disabled={renameStatus === 'loading'}
                  />
                  <Button
                    size="small"
                    loading={renameStatus === 'loading'}
                    disabled={renameStatus === 'loading' || renameLabel.trim() === ''}
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
                </>
              ) : (
                <>
                  <span className={styles.label}>
                    {item.label === '' ? t('account.unnamedCredential') : item.label}
                  </span>
                  {item.transports.map((transport) => (
                    <Tag key={transport} size="small" color="grey">
                      {transport}
                    </Tag>
                  ))}
                  <span className={styles.times}>
                    {t('account.webauthnAddedAt', { time: formatUnixTime(item.createdAt) })}
                    {t('account.mfaLastUsedAt', { time: formatUnixTime(item.lastUsedAt) })}
                  </span>
                  {item.aaguid !== '' ? (
                    <span className={styles.aaguid}>AAGUID {item.aaguid}</span>
                  ) : null}
                  <Button size="small" onClick={() => startRename(item)}>
                    {t('account.webauthnRenameAction')}
                  </Button>
                  <Popconfirm
                    title={t('account.webauthnDeleteConfirm', {
                      name: item.label === '' ? t('account.unnamedCredential') : item.label,
                    })}
                    onConfirm={() => handleDelete(item.id)}
                  >
                    <Button size="small" type="danger" loading={deleteStatus === 'loading'}>
                      {t('account.deleteAction')}
                    </Button>
                  </Popconfirm>
                </>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

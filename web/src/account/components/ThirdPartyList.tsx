/**
 * 第三方账号绑定列表（docs/前端架构.md §5 行 488；docs/接口文档.md §3.7）：
 * GetThirdpartyBindings 双列表——items 已绑定（Union 行不计入已绑定数、不能
 * 单独解绑，行 947，带「联合身份」标记展示）+ available 可绑定（过滤口径
 * 行 942，按 channel 分流绑定入口，行 943）：
 * - redirect → SsoService/Authorize{provider, scene:bind} 取 authorizeUrl 后
 *   location.replace（§3.7.1 A 行 956-960；RPC 非 302 不做 <a href> 直跳；
 *   不做 saveOidcContext——OIDC 上下文属登录场景，裁量见 ./api 注释）；
 * - qrcode → 打开 ThirdPartyBindDialog（§3.7.1 B）；
 * - api（小程序接口）通道不提供绑定入口（宿主内直接完成登录，无「已登录」
 *   前提）；未知渠道保守不渲染（hasBindEntry，同口径）。
 *
 * 解绑置灰（行 938「解绑后」口径 / 行 945 两个输入）：GetConfig.hasPassword
 * 或排除自身后非 Union 绑定数 ≥1，两者都不满足置灰（canUnbindThirdpartyRow，
 * 纯逻辑在 ./api）；服务端仍按同一口径校验兜底（invalid_request 经
 * apiErrorText 出文案）。
 * redirect 绑定的 target_taken 经回调链 ?bind= 参数由 SecurityPage 出文案；
 * 扫码绑定的 target_taken 在 ThirdPartyBindDialog 内落地。
 * 文案经 shared/i18n（account.* 域键 + common.refreshAndRetry 复用）。
 */
import { useEffect, useState, type ReactNode } from 'react';
import { Button, Empty, Popconfirm, Spin, Tag, Toast, Tooltip } from '@douyinfe/semi-ui-19';
import type { CaptchaConfig } from '../../gen/proto/api/common/v1/captcha_pb';
import type {
  ThirdpartyBinding,
  ThirdpartyOption,
} from '../../gen/proto/api/account/v1/thirdparty_pb';
import { ProviderIcon } from '../../shared/components/ProviderIcon';
import { useRequest } from '../../shared/hooks/useRequest';
import { t } from '../../shared/i18n';
import {
  apiErrorText,
  buildUnbindThirdpartyRequest,
  canUnbindThirdpartyRow,
  formatUnixTime,
  getThirdpartyBindings,
  hasBindEntry,
  sortThirdpartyOptions,
  startBindRedirect,
  unbindThirdparty,
} from '../api';
import { ThirdPartyBindDialog } from './ThirdPartyBindDialog';
import styles from './ThirdPartyList.module.less';

/** 打开的扫码绑定对话框（channel=qrcode 的 available 条目；关闭即置空）。 */
interface OpenDialog {
  readonly providerKey: string;
  readonly displayName: string;
}

/** 已绑定行（items）：Union 行带「联合身份」标记、无解绑入口；其余按置灰判定。 */
function BoundRow(props: {
  readonly item: ThirdpartyBinding;
  readonly canUnbind: boolean;
  readonly unbinding: boolean;
  readonly onUnbind: (providerKey: string, displayName: string) => void;
}): ReactNode {
  const { item } = props;
  return (
    <li className={styles.row}>
      <div className={styles.rowMain}>
        <ProviderIcon icon={item.icon} alt={item.displayName} />
        <span className={styles.label}>{item.displayName}</span>
        {/* Union 行不计入已绑定数、不能单独解绑（§3.7 行 947）——标记展示、无解绑入口。 */}
        {item.type === 'union' ? (
          <Tag size="small" color="grey">
            {t('account.unionTag')}
          </Tag>
        ) : null}
        <span className={styles.times}>
          {t('account.boundAt', { time: formatUnixTime(item.createdAt) })}
        </span>
      </div>
      <div className={styles.rowActions}>
        {item.type === 'union' ? null : props.canUnbind ? (
          <Popconfirm
            title={t('account.unbindConfirm', { name: item.displayName })}
            onConfirm={() => props.onUnbind(item.providerKey, item.displayName)}
          >
            <Button size="small" type="danger" loading={props.unbinding}>
              {t('account.unbindAction')}
            </Button>
          </Popconfirm>
        ) : (
          // A-3：置灰必须说明原因——canUnbindThirdpartyRow（api.ts）口径 =
          // 未设置密码且排除自身后无其他非 Union 绑定 → 解绑后将没有可用登录方式。
          // disabled 按钮不触发 hover，外包 span 让 Tooltip 生效。
          <Tooltip content={t('account.unbindDisabledReason')}>
            <span>
              <Button size="small" type="danger" disabled loading={props.unbinding}>
                {t('account.unbindAction')}
              </Button>
            </span>
          </Tooltip>
        )}
      </div>
    </li>
  );
}

/** 可绑定行（available）：redirect 跳转授权 / qrcode 开扫码框；api 不渲染。 */
function OptionRow(props: {
  readonly option: ThirdpartyOption;
  readonly redirecting: boolean;
  readonly onRedirect: (providerKey: string) => void;
  readonly onQrcode: (option: ThirdpartyOption) => void;
}): ReactNode {
  const { option } = props;
  return (
    <li className={styles.row}>
      <div className={styles.rowMain}>
        <ProviderIcon icon={option.icon} alt={option.displayName} />
        <span className={styles.label}>{option.displayName}</span>
      </div>
      <div className={styles.rowActions}>
        {option.channel === 'redirect' ? (
          <Button
            size="small"
            theme="solid"
            loading={props.redirecting}
            disabled={props.redirecting}
            onClick={() => props.onRedirect(option.providerKey)}
          >
            {t('account.bindAction')}
          </Button>
        ) : (
          <Button size="small" theme="solid" onClick={() => props.onQrcode(option)}>
            {t('account.bindAction')}
          </Button>
        )}
      </div>
    </li>
  );
}

/**
 * 三方绑定列表状态壳：首进拉双列表；解绑 / 扫码绑定成功后重取（redirect
 * 跳转离页、回调链整页重载，无原位刷新需求）。
 */
export function ThirdPartyList(props: {
  /** GetConfig.hasPassword（§3.7 行 945 置灰判定输入之一）。 */
  readonly hasPassword: boolean;
  /** captcha 配置（§3.2 GetConfig 注入；扫码绑定拉码必带，§2.8 行 703）。 */
  readonly captcha: CaptchaConfig;
}): ReactNode {
  const { hasPassword, captcha } = props;
  const { data, status, run } = useRequest(getThirdpartyBindings);
  const { status: unbindStatus, run: runUnbind } = useRequest(unbindThirdparty);
  const [redirecting, setRedirecting] = useState(false);
  const [redirectFailed, setRedirectFailed] = useState(false);
  const [unbindError, setUnbindError] = useState<unknown>(undefined);
  const [dialog, setDialog] = useState<OpenDialog | undefined>(undefined);

  useEffect(() => {
    run().catch(() => {});
  }, [run]);

  // redirect 渠道（§3.7.1 A）：取 authorizeUrl → location.replace 离页；
  // 失败 / 空 URL → 原地提示（startBindRedirect 纯编排，错误吞在内部）。
  const handleRedirect = async (providerKey: string) => {
    if (redirecting) {
      return;
    }
    setRedirectFailed(false);
    setRedirecting(true);
    const url = await startBindRedirect(providerKey);
    if (url === undefined) {
      setRedirectFailed(true);
      setRedirecting(false);
      return;
    }
    window.location.replace(url);
  };

  const handleUnbind = (providerKey: string, displayName: string) => {
    setUnbindError(undefined);
    runUnbind(buildUnbindThirdpartyRequest(providerKey))
      .then((result) => {
        if (result !== undefined) {
          run().catch(() => {});
          // 解绑成功反馈（P1-6 统一 Semi Toast 成功通道）。
          Toast.success(t('account.unbindSuccess', { name: displayName }));
        }
      })
      .catch((error: unknown) => {
        // 服务端置灰口径兜底（§3.7 行 945）：invalid_request 等经 apiErrorText 出文案。
        setUnbindError(error);
      });
  };

  const items = data?.items;
  const available = data?.available;

  return (
    <div className={styles.wrap}>
      {status === 'loading' && data === undefined ? (
        <Spin />
      ) : status === 'error' && data === undefined ? (
        <div className={styles.body}>
          <p role="alert" className={styles.error}>
            {t('account.thirdpartyLoadFailed')}
          </p>
        </div>
      ) : (
        <div className={styles.body}>
          {items === undefined || items.length === 0 ? (
            // 空态裸文字 → Semi Empty（§9.3 映射表）。
            <Empty description={t('account.thirdpartyEmpty')} />
          ) : (
            <ul className={styles.list}>
              {items.map((item) => (
                <BoundRow
                  key={item.providerKey}
                  item={item}
                  canUnbind={canUnbindThirdpartyRow(hasPassword, items, item)}
                  unbinding={unbindStatus === 'loading'}
                  onUnbind={handleUnbind}
                />
              ))}
            </ul>
          )}
          {unbindError !== undefined ? (
            <p role="alert" className={styles.error}>
              {apiErrorText(unbindError)}
            </p>
          ) : null}
          {redirectFailed ? (
            <p role="alert" className={styles.error}>
              {t('common.refreshAndRetry')}
            </p>
          ) : null}
          {available === undefined || available.length === 0 ? null : (
            <>
              <p className={styles.sectionLabel}>{t('account.thirdpartyAvailableTitle')}</p>
              <ul className={styles.list}>
                {/* api 通道不渲染绑定入口（行 943）；未知渠道保守不渲染（同口径）。 */}
                {sortThirdpartyOptions(available)
                  .filter((option) => hasBindEntry(option.channel))
                  .map((option) => (
                    <OptionRow
                      key={option.providerKey}
                      option={option}
                      redirecting={redirecting}
                      onRedirect={(key) => void handleRedirect(key)}
                      onQrcode={(picked) =>
                        setDialog({
                          providerKey: picked.providerKey,
                          displayName: picked.displayName,
                        })
                      }
                    />
                  ))}
              </ul>
            </>
          )}
        </div>
      )}
      <ThirdPartyBindDialog
        visible={dialog !== undefined}
        providerKey={dialog?.providerKey ?? ''}
        displayName={dialog?.displayName ?? ''}
        captcha={captcha}
        onCancel={() => setDialog(undefined)}
        onDone={() => {
          // §3.7.1 B 行 1007：成功 → 关闭面板并刷新列表。
          setDialog(undefined);
          run().catch(() => {});
        }}
      />
    </div>
  );
}

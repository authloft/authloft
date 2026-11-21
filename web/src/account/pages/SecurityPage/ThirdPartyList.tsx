/**
 * 第三方账号列表（全量行式布局，复用 SettingListSections）：
 * GetThirdpartyBindings 双列表经 mergeThirdpartyAccounts 合并为一份账号清单
 * ——每个 Provider 恒出现一行，无论是否已绑定；bound=true 出「解绑」，
 * bound=false 出「绑定」（§3.7 行 936/942）。行渲染走 SettingListSections 的
 * fields（title=图标+名称、help=绑定态、extra=动作按钮），不再自绘 <ul>。
 *
 * 绑定入口仍按 channel 分流：redirect → startBindRedirect 取 authorizeUrl
 * 后 location.replace（§3.7.1 A）；qrcode → ThirdPartyBindDialog（§3.7.1 B）；
 * api（小程序接口）与未知渠道照旧没有可用入口，但账号仍显示，绑定按钮置灰
 * 并说明原因（hasBindEntry 同口径）。
 *
 * 解绑置灰（§3.7 行 938/945）：hasPassword 或排除自身后非 Union 绑定数 ≥1
 * 才允许，Union 行不能单独解绑（行 947）——两者都出置灰按钮 + Tooltip 原因。
 * 服务端仍按同一口径兜底（invalid_request 经 apiErrorText 出文案）。
 * 文案经 shared/i18n（account.* 域键 + common.refreshAndRetry 复用）。
 */
import { useRef, useState, type ReactNode } from 'react';
import { useLocation } from '@modern-js/runtime/router';
import { useRequest } from 'ahooks';
import {
  Button,
  Empty,
  Popconfirm,
  Spin,
  Tag,
  Toast,
  Tooltip,
} from '@douyinfe/semi-ui';
import type { CaptchaConfig } from '../../../gen/proto/api/common/v1/captcha_pb';
import { ProviderIcon } from '../../../shared/components/ProviderIcon';
import {
  type ListItemProps,
  SettingListSections,
} from '../../../shared/components/SettingList';
import { requestOptions } from '../../../shared/hooks/requestOptions';
import { t } from '../../../shared/i18n';
import {
  accountReturnTo,
  apiErrorText,
  buildUnbindThirdpartyRequest,
  canUnbindThirdpartyRow,
  formatUnixTime,
  getThirdpartyBindings,
  hasBindEntry,
  isUnauthenticatedError,
  isUnionThirdpartyRow,
  mergeThirdpartyAccounts,
  startBindRedirect,
  type ThirdpartyAccountRow,
  unbindThirdparty,
} from '../../api';
import { ThirdPartyBindDialog } from './ThirdPartyBindDialog';
import styles from './ThirdPartyList.module.less';

/** 打开的扫码绑定对话框（channel=qrcode 的未绑定行；关闭即置空）。 */
interface OpenDialog {
  providerKey: string;
  displayName: string;
  /** 拉码需人机校验（§2.5 模式分派，随 provider 条目透传）。 */
  needCaptcha: boolean;
}

/** 行题：渠道图标 + 展示名（Union 行带「联合身份」标记）。 */
function AccountTitle(props: {
  row: ThirdpartyAccountRow;
  union: boolean;
}): ReactNode {
  const { row, union } = props;
  return (
    <span className={styles.accountTitle}>
      <ProviderIcon icon={row.icon} alt={row.displayName} />
      <span>{row.displayName}</span>
      {union ? (
        <Tag size="small" color="grey">
          {t('account.unionTag')}
        </Tag>
      ) : null}
    </span>
  );
}

/** disabled 按钮不触发 hover，外包 span 让 Tooltip 生效（A-3 同口径）。 */
function DisabledAction(props: {
  label: string;
  reason: string;
  danger?: boolean;
  loading?: boolean;
}): ReactNode {
  return (
    <Tooltip content={props.reason}>
      <span>
        <Button
          size="small"
          type={props.danger ? 'danger' : 'primary'}
          theme={props.danger ? undefined : 'solid'}
          disabled
          loading={props.loading}
        >
          {props.label}
        </Button>
      </span>
    </Tooltip>
  );
}

/** 已绑定行的「解绑」：Union / 置灰分别给出原因，可用则 Popconfirm 二次确认。 */
function UnbindAction(props: {
  row: ThirdpartyAccountRow;
  union: boolean;
  canUnbind: boolean;
  unbinding: boolean;
  onUnbind: (providerKey: string, displayName: string) => void;
}): ReactNode {
  const { row, union, canUnbind, unbinding } = props;
  if (union) {
    return (
      <DisabledAction
        label={t('account.unbindAction')}
        reason={t('account.unionUnbindDisabledReason')}
        danger
        loading={unbinding}
      />
    );
  }
  if (!canUnbind) {
    // canUnbindThirdpartyRow（api.ts）：未设置密码且排除自身后无其他非 Union
    // 绑定 → 解绑后将没有可用登录方式。
    return (
      <DisabledAction
        label={t('account.unbindAction')}
        reason={t('account.unbindDisabledReason')}
        danger
        loading={unbinding}
      />
    );
  }
  return (
    <Popconfirm
      title={t('account.unbindConfirm', { name: row.displayName })}
      onConfirm={() => props.onUnbind(row.providerKey, row.displayName)}
    >
      <Button type="danger" loading={unbinding}>
        {t('account.unbindAction')}
      </Button>
    </Popconfirm>
  );
}

/** 未绑定行的「绑定」：redirect 跳转授权 / qrcode 扫码 / 其余渠道置灰说明。 */
function BindAction(props: {
  row: ThirdpartyAccountRow;
  redirecting: boolean;
  onRedirect: (providerKey: string) => void;
  onQrcode: (dialog: OpenDialog) => void;
}): ReactNode {
  const { row, redirecting } = props;
  if (!hasBindEntry(row.channel)) {
    return (
      <DisabledAction
        label={t('account.bindAction')}
        reason={t('account.bindUnsupportedReason')}
      />
    );
  }
  if (row.channel === 'redirect') {
    return (
      <Button
        type="tertiary"
        loading={redirecting}
        disabled={redirecting}
        onClick={() => props.onRedirect(row.providerKey)}
      >
        {t('account.bindAction')}
      </Button>
    );
  }
  return (
    <Button
      size="small"
      theme="solid"
      onClick={() =>
        props.onQrcode({
          providerKey: row.providerKey,
          displayName: row.displayName,
          needCaptcha: row.needCaptcha === true,
        })
      }
    >
      {t('account.bindAction')}
    </Button>
  );
}

/**
 * 三方绑定列表状态壳：首进拉双列表；解绑 / 扫码绑定成功后重取（redirect
 * 跳转离页、回调链整页重载，无原位刷新需求）。
 */
export function ThirdPartyList(props: {
  /** GetConfig.hasPassword（§3.7 行 945 置灰判定输入之一）。 */
  hasPassword: boolean;
  /** captcha 配置（§3.2 GetConfig 注入；扫码绑定拉码必带，§2.8 行 703）。 */
  captcha: CaptchaConfig;
}): ReactNode {
  const { hasPassword, captcha } = props;
  const location = useLocation();
  const returnTo = () => accountReturnTo(location.pathname, location.search);
  // 双列表自动请求（挂载即取）；错误静默（错误帧呈现防双报）。
  const { data, error, loading, refresh } = useRequest(
    getThirdpartyBindings,
    requestOptions({ toast: false, returnTo }),
  );
  const [redirecting, setRedirecting] = useState(false);
  const [redirectFailed, setRedirectFailed] = useState(false);
  const [unbindError, setUnbindError] = useState<unknown>(undefined);
  const [dialog, setDialog] = useState<OpenDialog | undefined>(undefined);
  // 最近一次解绑的展示名（onSuccess 出 Toast 文案用）。
  const unbindNameRef = useRef('');
  // §5.4-#2（固定 per-call 覆盖）：解绑失败行内呈现（非 Toast）；401 仍走
  // 集中分派跳转（与页面口径一致）。成功链：重取双列表 + Toast。
  const central = requestOptions({ toast: false, returnTo });
  const unbind = useRequest(unbindThirdparty, {
    manual: true,
    ...central,
    onError: (err: Error) => {
      if (isUnauthenticatedError(err)) {
        central.onError(err);
        return;
      }
      // 服务端置灰口径兜底（§3.7 行 945）：invalid_request 等行内出文案。
      setUnbindError(err);
    },
    onSuccess: () => {
      refresh();
      Toast.success(
        t('account.unbindSuccess', { name: unbindNameRef.current }),
      );
    },
  });

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
    unbindNameRef.current = displayName;
    // 成功链在 onSuccess；错误进 per-call onError（§5.4-#2 行内呈现）。
    unbind.run(buildUnbindThirdpartyRequest(providerKey));
  };

  const items = data?.items ?? [];
  const available = data?.available ?? [];
  const rows = mergeThirdpartyAccounts(items, available);
  const fields: ListItemProps[] = rows.map((row) => {
    const union = isUnionThirdpartyRow(row);
    return {
      key: row.providerKey,
      title: <AccountTitle row={row} union={union} />,
      help: row.bound
        ? `${t('account.factorBoundTag')} · ${t('account.boundAt', {
            time: formatUnixTime(row.createdAt ?? BigInt(0)),
          })}`
        : undefined,
      extra: row.bound ? (
        <UnbindAction
          row={row}
          union={union}
          canUnbind={canUnbindThirdpartyRow(hasPassword, items, row)}
          unbinding={unbind.loading}
          onUnbind={handleUnbind}
        />
      ) : (
        <BindAction
          row={row}
          redirecting={redirecting}
          onRedirect={(key) => void handleRedirect(key)}
          onQrcode={setDialog}
        />
      ),
    };
  });

  // 首帧 / 错误帧 / 无账号帧走 section.children，其余交给 fields 行式渲染。
  const statusBody: ReactNode =
    loading && data === undefined ? (
      <Spin />
    ) : error !== undefined && data === undefined ? (
      <p role="alert" className={styles.error}>
        {t('account.thirdpartyLoadFailed')}
      </p>
    ) : fields.length === 0 ? (
      <Empty description={t('account.thirdpartyNone')} />
    ) : undefined;

  return (
    <>
      <SettingListSections
        sections={[
          {
            key: 'thirdparty',
            title: t('account.thirdpartyCardTitle'),
            ...(statusBody === undefined
              ? { fields }
              : { children: statusBody }),
          },
        ]}
      />
      {unbindError !== undefined || redirectFailed ? (
        <div className={styles.messages}>
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
        </div>
      ) : null}
      <ThirdPartyBindDialog
        visible={dialog !== undefined}
        providerKey={dialog?.providerKey ?? ''}
        displayName={dialog?.displayName ?? ''}
        needCaptcha={dialog?.needCaptcha ?? false}
        captcha={captcha}
        onCancel={() => setDialog(undefined)}
        onDone={() => {
          // §3.7.1 B 行 1007：成功 → 关闭面板并刷新列表。
          setDialog(undefined);
          refresh();
        }}
      />
    </>
  );
}

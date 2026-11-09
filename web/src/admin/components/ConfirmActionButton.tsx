/**
 * 表格行内「确认后执行」动作钮（Popconfirm + Button）：删除 / 解除限制等
 * 单发写操作的统一外壳。在途 loading、防重与失败 Toast 由组件内接管，
 * 消费方只给 action 与成功回调（成功文案 / 刷新列表归消费方）。
 *
 * 每行一个实例 → loading 天然按行隔离（页级 useRequest 只给一个全局
 * loading，表达不了行级）。防重靠触发钮 disabled：在途期间气泡无法再次
 * 打开，故 onConfirm 用 run（即发即关气泡）而非返回 Promise 让气泡自身
 * 承载 loading。
 *
 * 纯 Semi 组合无自定义样式 → 不建 .module.less（§1.7 既定口径，
 * StatusSwitch 同款）。
 */
import type { ReactNode } from 'react';
import { Button, Popconfirm, Toast } from '@douyinfe/semi-ui';
import { useRequest } from 'ahooks';
import { apiErrorText } from '../api';

export interface ConfirmActionButtonProps {
  /** 确认气泡标题。 */
  title: ReactNode;
  /** 触发钮文案。 */
  children: ReactNode;
  /** 确认后执行；reject → 组件内 Toast.error，消费方不再 catch。 */
  action: () => Promise<unknown>;
  /** 成功回调（Toast.success / 刷新列表由消费方决定）。 */
  onSuccess?: () => void;
}

/** 行内确认动作钮：loading / 防重 / 失败 Toast 内建。 */
export function ConfirmActionButton({
  title,
  children,
  action,
  onSuccess,
}: ConfirmActionButtonProps): ReactNode {
  const { run, loading } = useRequest(action, {
    manual: true,
    onSuccess: () => onSuccess?.(),
    onError: (error) => Toast.error(apiErrorText(error)),
  });

  return (
    <Popconfirm
      title={title}
      onConfirm={() => {
        run();
      }}
    >
      <Button size="small" loading={loading} disabled={loading}>
        {children}
      </Button>
    </Popconfirm>
  );
}

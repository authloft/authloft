/**
 * 行内启停开关（docs/前端架构.md §6 行 513；docs/接口文档.md §5.2 行 1173
 * SetProviderEnabled `{providerKey, isEnabled}`）——admin 端 Provider 列表
 * 「状态」列。
 *
 * 乐观更新 + 失败回滚：**复用 shared/app-ui DataTable 行内开关模式**
 * （dataTableLogic.runInlineToggle——已有 node 测试覆盖的编排：乐观打
 * 补丁、persist 失败即回滚原值），以「单行行集」形态接入：
 * - onChange：立即显示目标态（乐观）→ onToggle 持久化（in-flight loading）；
 * - 成功：保留乐观态，消费方把行数据 isEnabled 更新为 next（真值追上）后由
 *   同步 effect 清除覆盖；
 * - 失败（onToggle reject）：清除覆盖 → 显示回落消费方未变的 isEnabled
 *   （回滚）。**错误展示归消费方**（DataTable 行内开关同口径：reject 只
 *   承担「触发回滚」语义）。
 *
 * 组件壳 import Semi Switch 后模块图不可在 node 测试（工具链
 * blocker，见 AdminLayout 注释）——回滚编排已收口在 dataTableLogic（零
 * Semi、node 已测），本壳只做受控渲染接线（DataTable.tsx 同分工）。
 * 纯 Semi Switch 组合无自定义样式 → 不建 .module.less（§1.7 既定口径）。
 */
import { useEffect, useState, type ReactNode } from 'react';
import { Switch } from '@douyinfe/semi-ui-19';
import { runInlineToggle } from '../../shared/app-ui/dataTableLogic';

/** 单行行集的固定键（runInlineToggle 以 key 命中行；本组件恒单行）。 */
const SINGLE_ROW_KEY = 'row';

export interface StatusSwitchProps {
  /** 当前行启用态（真值：消费方行数据）。 */
  readonly isEnabled: boolean;
  /**
   * 持久化：成功后消费方**必须**把行数据 isEnabled 更新为 next（乐观态让
   * 位真值依赖此更新）；失败 reject 即回滚（错误展示归消费方，见文件头）。
   */
  readonly onToggle: (next: boolean) => Promise<void>;
}

/** 行内启停开关壳：乐观覆盖态显示 + in-flight loading。 */
export function StatusSwitch({ isEnabled, onToggle }: StatusSwitchProps): ReactNode {
  // 乐观覆盖：in-flight（含成功后真值未追上的一拍）期间显示目标态。
  const [override, setOverride] = useState<boolean | null>(null);
  const checked = override ?? isEnabled;

  // 消费方成功刷新行数据（isEnabled 追上 override）→ 清覆盖，显示让位真值。
  useEffect(() => {
    if (override !== null && isEnabled === override) {
      setOverride(null);
    }
  }, [isEnabled, override]);

  async function handleChange(next: boolean): Promise<void> {
    // 乐观更新先行（UI 立即反映目标态）；持久化失败即回滚——runInlineToggle
    // 编排（单行行集形态，语义与 DataTable 行内开关完全同源）。
    setOverride(next);
    const outcome = await runInlineToggle(
      [{ isEnabled }],
      () => SINGLE_ROW_KEY,
      SINGLE_ROW_KEY,
      () => ({ isEnabled: next }),
      async () => {
        await onToggle(next);
      },
    );
    if (!outcome.ok) {
      // 回滚：isEnabled prop 未被消费方改动 → 显示回落原值。
      setOverride(null);
    }
    // 成功 → 保留 override=next，待消费方行数据刷新后由上方 effect 清除。
  }

  return (
    <Switch
      checked={checked}
      loading={override !== null}
      onChange={(next) => {
        void handleChange(next);
      }}
    />
  );
}

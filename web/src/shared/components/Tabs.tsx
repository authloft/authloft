/**
 * 零依赖纯展示 tab 条（docs/前端架构.md §3.3）：受控组件，条目与高亮全部由
 * props 注入，组件不持状态、不感知业务语义。login 主因子方式列表
 * （MethodTabs）、注册 / 重置页与 StepUpDialog 的二次验证方式 tabs 共用
 * 本单份实现，禁止复制第二份。
 */
import styles from './Tabs.module.less';

interface TabsProps {
  tabList: Array<{ itemKey: string; title: string }>;
  activeKey: string;
  onChange: (itemKey: string) => void;
}

export function Tabs({ tabList, activeKey, onChange }: TabsProps) {
  return (
    <ul className={styles.list}>
      {tabList.map((entry) => (
        <li
          key={entry.itemKey}
          className={entry.itemKey === activeKey ? styles.tabActive : ''}
          aria-current={entry.itemKey === activeKey ? 'true' : undefined}
          onClick={() => onChange(entry.itemKey)}
        >
          {entry.title}
        </li>
      ))}
    </ul>
  );
}

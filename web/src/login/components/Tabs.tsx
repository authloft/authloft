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

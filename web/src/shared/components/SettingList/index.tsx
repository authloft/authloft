import { List, Typography } from '@douyinfe/semi-ui';
import { type ReactNode } from 'react';
import styles from './index.module.less';

export interface ListItemProps {
  key: string;
  title: ReactNode;
  help?: ReactNode;
  extra?: ReactNode;
}
export function SettingList(props: { fields?: Array<ListItemProps> }) {
  return (
    <List>
      {props.fields?.map((field) => (
        <List.Item
          className={styles.field}
          key={field.key}
          main={
            <div className={styles.fieldLabelRow}>
              <Typography.Text className={styles.fieldLabel}>
                {field.title}
              </Typography.Text>
              {field.help ? (
                <Typography.Text type="tertiary">{field.help}</Typography.Text>
              ) : null}
            </div>
          }
          extra={field.extra}
        />
      ))}
    </List>
  );
}

export function SettingListSections(props: {
  sections: Array<{
    title?: string;
    key: string;
    children?: ReactNode;
    fields?: Array<ListItemProps>;
  }>;
}) {
  return (
    <div className={styles.sections}>
      {props.sections.map((section) => (
        <div key={section.key} className={styles.sectionCard}>
          {section.title ? (
            <Typography.Title heading={5}>{section.title}</Typography.Title>
          ) : null}
          <div className={styles.sectionBody}>
            {section.children ? (
              section.children
            ) : (
              <SettingList fields={section.fields} />
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

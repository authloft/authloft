/**
 * SSO 客户端新建 / 编辑统一表单（docs/接口文档.md §5.5；docs/前端架构.md
 * §6）——SsoClientsPage 两个 SideSheet 共用的受控字段渲染组件：字段定义、
 * label、校验提示、白名单 / MFA 风险提示只写一份，两模式差异经 props 表达。
 *
 * - mode=create：clientId 可填（空 = 服务端生成）、无密钥项；
 * - mode=edit：clientId 只读回显（创建后不可改）+ newSecret 轮换位（留空
 *   保留原密钥）；
 * - 应用级登录配置三字段（§5.5）两模式都渲染：登录方式复选组（封闭集
 *   SSO_LOGIN_METHODS，全不选 = 跟随全局）+ OAuth Provider 多选（选项由
 *   页面经 props 注入）+ 默认回跳输入框（须命中回调白名单，匹配校验在
 *   服务端，前端提示不拦截）；非空缺省值 = 跟随全局。
 *
 * 草稿形态统一为 SsoClientFormDraft（api 层一份定义），提交逻辑（校验前置
 * 与 buildCreate/UpdateSsoClientRequest）留在页面：本组件只做受控渲染接线，
 * 不发请求。样式（§1.7）：同目录同名 module less。
 */
import type { ReactNode } from 'react';
import {
  Banner,
  CheckboxGroup,
  Input,
  Select,
  TextArea,
} from '@douyinfe/semi-ui';
import { t } from '../../shared/i18n';
import { StringListEditor } from './StringListEditor';
import {
  CLIENT_ID_MAX_LEN,
  CLIENT_NAME_MAX_LEN,
  showsDefaultRedirectHint,
  showsMfaRiskHint,
  type SsoClientFormDraft,
  type TemplateSelectOption,
} from '../api';
import styles from './SsoClientForm.module.less';

/** 统一表单 props：draft 单一形态，mode 只切换 clientId / newSecret 两个字段的表现。 */
export interface SsoClientFormProps {
  /** create = clientId 可填、无密钥项；edit = clientId 只读 + newSecret 轮换位。 */
  mode: 'create' | 'edit';
  draft: SsoClientFormDraft;
  onChange: (next: SsoClientFormDraft) => void;
  /** 提交在途时整表禁用（页面提交 loading 透传）。 */
  disabled: boolean;
  /** 登录方式复选组选项（页面由 SSO_LOGIN_METHODS + factors.* 文案构造）。 */
  loginMethodOptions: { value: string; label: string }[];
  /** OAuth Provider 多选选项（页面经 oauthProviderSelectOptions 过滤 category=oauth）。 */
  oauthProviderOptions: { label: string; value: string }[];
  /** 模板下拉选项（内置 login + 自定义 + 不指定，api.templateSelectOptions 构造）。 */
  templateOptions: TemplateSelectOption[];
}

/**
 * SSO 客户端表单（新建 / 编辑共用）：受控接线，草稿经 onChange 整体上抛。
 */
export function SsoClientForm(props: SsoClientFormProps): ReactNode {
  const { mode, draft, onChange, disabled } = props;

  /** 字段就地更新（受控整体上抛，页面 state 单一形态）。 */
  function patch(part: Partial<SsoClientFormDraft>): void {
    onChange({ ...draft, ...part });
  }

  return (
    <div className={styles.formBody}>
      <div className={styles.field}>
        <span className={styles.fieldLabel}>{t('admin.clientIdLabel')}</span>
        {mode === 'edit' ? (
          <>
            <Input
              value={draft.clientId}
              disabled
              aria-label={t('admin.clientIdLabel')}
            />
            <span className={styles.fieldHint}>
              {t('admin.clientIdImmutable')}
            </span>
          </>
        ) : (
          <Input
            value={draft.clientId}
            onChange={(value) => patch({ clientId: value })}
            maxLength={CLIENT_ID_MAX_LEN}
            placeholder={t('admin.clientIdAutoGenPlaceholder')}
            aria-label={t('admin.clientIdLabel')}
            disabled={disabled}
          />
        )}
      </div>
      <div className={styles.field}>
        <span className={styles.fieldLabel}>{t('admin.clientNameLabel')}</span>
        <Input
          value={draft.name}
          onChange={(value) => patch({ name: value })}
          maxLength={CLIENT_NAME_MAX_LEN}
          placeholder={t('admin.clientNamePlaceholder')}
          aria-label={t('admin.clientNameLabel')}
          disabled={disabled}
        />
      </div>
      {mode === 'edit' ? (
        <div className={styles.field}>
          <span className={styles.fieldLabel}>
            {t('admin.newSecretLabel')}
          </span>
          <Input
            mode="password"
            value={draft.newSecret}
            onChange={(value) => patch({ newSecret: value })}
            placeholder={t('admin.newSecretPlaceholder')}
            aria-label={t('admin.newSecretLabel')}
            autoComplete="new-password"
            disabled={disabled}
          />
          <span className={styles.fieldHint}>
            {t('admin.secretRotateHint')}
          </span>
        </div>
      ) : null}
      <div className={styles.field}>
        <span className={styles.fieldLabel}>
          {t('admin.redirectUrisLabel')}
        </span>
        <span className={styles.fieldHint}>
          {t('admin.redirectUriEntryHint')}
        </span>
        <StringListEditor
          values={draft.redirectUris}
          onChange={(next) => patch({ redirectUris: next })}
          disabled={disabled}
          ariaLabel={t('admin.redirectUriAriaLabel')}
          addText={t('admin.addRedirectUri')}
          placeholder={t('admin.redirectUriPlaceholder')}
          emptyHint={t('admin.noRedirectUrisHint')}
        />
      </div>
      <div className={styles.field}>
        <span className={styles.fieldLabel}>
          {t('admin.ssoLoginMethodsLabel')}
        </span>
        <span className={styles.fieldHint}>
          {t('admin.ssoLoginMethodsHint')}
        </span>
        <CheckboxGroup
          value={draft.loginMethods}
          onChange={(value) => patch({ loginMethods: value.map(String) })}
          options={props.loginMethodOptions}
          aria-label={t('admin.ssoLoginMethodsLabel')}
          disabled={disabled}
        />
        {showsMfaRiskHint(draft.loginMethods) ? (
          <Banner
            type="warning"
            fullMode={false}
            closeIcon={null}
            description={t('admin.ssoMfaRiskHint')}
          />
        ) : null}
      </div>
      <div className={styles.field}>
        <span className={styles.fieldLabel}>
          {t('admin.ssoOauthProvidersLabel')}
        </span>
        <span className={styles.fieldHint}>
          {t('admin.ssoOauthProvidersHint')}
        </span>
        <Select
          multiple
          value={draft.oauthProviders}
          onChange={(value) =>
            patch({ oauthProviders: Array.isArray(value) ? value.map(String) : [] })
          }
          optionList={props.oauthProviderOptions}
          placeholder={t('admin.ssoOauthProvidersPlaceholder')}
          aria-label={t('admin.ssoOauthProvidersLabel')}
          disabled={disabled}
        />
      </div>
      <div className={styles.field}>
        <span className={styles.fieldLabel}>
          {t('admin.ssoDefaultRedirectUriLabel')}
        </span>
        <Input
          value={draft.defaultRedirectUri}
          onChange={(value) => patch({ defaultRedirectUri: value })}
          placeholder={t('admin.ssoDefaultRedirectUriPlaceholder')}
          aria-label={t('admin.ssoDefaultRedirectUriLabel')}
          disabled={disabled}
        />
        {showsDefaultRedirectHint(draft.defaultRedirectUri) ? (
          <span className={styles.fieldHint}>
            {t('admin.ssoDefaultRedirectUriHint')}
          </span>
        ) : null}
      </div>
      <div className={styles.field}>
        <span className={styles.fieldLabel}>{t('admin.templateLabel')}</span>
        <span className={styles.fieldHint}>
          {t('admin.templateSelectHint')}
        </span>
        <Select
          value={draft.templateKey}
          onChange={(value) =>
            patch({ templateKey: typeof value === 'string' ? value : '' })
          }
          optionList={props.templateOptions}
          placeholder={t('admin.templateUnspecified')}
          aria-label={t('admin.templateLabel')}
          disabled={disabled}
        />
      </div>
      <div className={styles.field}>
        <span className={styles.fieldLabel}>
          {t('admin.templateVarsLabel')}
        </span>
        <span className={styles.fieldHint}>{t('admin.templateVarsHint')}</span>
        <TextArea
          value={draft.templateVars}
          onChange={(value) => patch({ templateVars: value })}
          placeholder={t('admin.templateVarsPlaceholder')}
          aria-label={t('admin.templateVarsLabel')}
          autosize={{ minRows: 3, maxRows: 10 }}
          disabled={disabled}
        />
      </div>
    </div>
  );
}

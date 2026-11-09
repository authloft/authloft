/**
 * 提供商新建 / 编辑页（docs/前端架构.md §6 行 516；docs/接口文档.md
 * §5.2 行 1164-1179 / §5.3）——/admin/providers/new 与
 * /admin/providers/{provider_key}/edit。
 *
 * 页面级职责（§6 行 516）：
 * - `type` 下拉从 Registry 的 metas 动态拉取；选定后拉 GetProviderSchema
 *   驱动 SchemaForm；编辑模式 type / provider_key 锁定；
 * - 保存前校验 provider_key 唯一性（新建模式全量列表预检，失败放行由后端
 *   already_exists 兜底）与字符集（validateSchemaValues）；
 * - `icon_url` 手填绝对 URL + ProviderIcon 实时预览（空则占位）；
 * - 短信 / 邮件类型（category sms|email）提供「发送测试」。
 *
 * 【Semi Form 化】页壳用 PageLayout；表单整体交给一个 Semi `<Form>`：
 * - 值、label 关联、必填星号、校验文案全部由 Form / Form.* 字段组件托管，
 *   页面不再自持 values / issues / testTarget / testFeedback 等受控 state；
 *   `type` 仅作为请求链驱动量（选型 → 拉 schema）保留为 state；
 * - Form 采用 Row + Col 两栏（类型选择与回调提示并排，SchemaForm 内
 *   每字段 span=12）；区块标题用 Form.Section，折叠用 Semi Collapse
 *   （见 schema/SchemaForm.tsx），不再有手写 section / details；
 * - 校验沿用 schemaLogic.validateSchemaValues 纯函数，接 Form 级
 *   `validator`（提交时一次性跑；trigger="custom" 避免失焦重复触发
 *   provider_key 唯一性预检）。校验失败由 Form 把错误注入对应字段。
 *
 * 编辑回填：GetProvider → AdminProvider（全站唯一明文凭证出口）→
 * adminProviderToValues 作为 Form.initValues；type / schema / provider
 * 变更通过 Form 的 key 重建，值态与错误态一并重置（initValues 只在
 * 挂载时生效）。提交体 buildProviderStruct（type 顶层恒带），
 * 成功后整页跳回列表。
 *
 * 401 统一跳登录（§6 行 501）；其余错误走页面错误帧（Semi Banner）/
 * 写操作失败 Toast。样式（§1.7）：同目录同名 module less。
 */
import { requestOptions } from '@/shared/hooks/requestOptions';
import { t } from '@/shared/i18n';
import { type JsonObject } from '@bufbuild/protobuf';
import { Button, SideSheet, Space } from '@douyinfe/semi-ui';
import { useLocation } from '@modern-js/runtime/router';
import { useRequest } from 'ahooks';
import { useRef, useState, type ReactNode } from 'react';
import { adminReturnTo, createProvider, updateProvider } from '../../../api';
import { FormApi, ProviderEditContent } from './content';

/** 新建 / 编辑共用：providerKey 缺省 = 新建，给定 = 编辑。 */
export function ProviderEdit(props: {
  /** 归一后 al_root（401 跳登录前缀 / 回调地址前缀）。 */
  alRoot: string;
  /** 编辑目标 provider_key；缺省 = 新建。 */
  providerKey?: string;
  onSave?: () => void;

  visible?: boolean;
  onClose?: () => void;
}): ReactNode {
  const editing = props.providerKey !== undefined;
  // 401 跳登录带 returnTo（/admin# + hash 内路径，登录后跳回本页）。
  const location = useLocation();
  const title = editing
    ? t('admin.editProviderTitle')
    : t('admin.createProviderTitle');
  // Form 托管全部字段值 / 错误；这里只留取测试目标与就地错误所需的 API。
  const formApi = useRef<FormApi | null>(null);
  const [canSave, setCanSave] = useState(false);

  const submitReq = useRequest(
    editing
      ? (values: JsonObject) => updateProvider(values)
      : (values: JsonObject) => createProvider(values),
    {
      manual: true,
      onSuccess: () => props.onSave?.(),
      ...requestOptions({
        returnTo: () => adminReturnTo(location.pathname, location.search),
      }),
    },
  );

  const submitting = submitReq.loading;

  return (
    <SideSheet
      title={title}
      visible={props.visible}
      maskClosable={false}
      onCancel={props.onClose}
      width={600}
      footer={
        <Space>
          <Button
            theme="solid"
            htmlType="submit"
            loading={submitting}
            onClick={() => formApi.current?.submitForm()}
            disabled={!canSave}
          >
            {t('admin.saveAction')}
          </Button>
        </Space>
      }
    >
      <ProviderEditContent
        alRoot={props.alRoot}
        providerKey={props.providerKey}
        onSubmit={submitReq.run}
        getFormApi={(api) => (formApi.current = api)}
      />
    </SideSheet>
  );
}

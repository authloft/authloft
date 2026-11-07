/**
 * 上传已有配置页（路径 A，docs/前端架构.md §6b / 接口文档 §13.2）：
 * 上传 config.yaml 全文；失败按 error.code 反馈（校验 / 连接 / 初始化），
 * 可修正后重试；成功（restarting:true）进入与全新安装一致的重启流程。
 * 约束（§6b）：不解析、不回显配置内容（可能含密钥）——文件只按纯文本读入
 * 编辑框，此外不渲染、不日志输出配置内容。
 * §9 第 13 条 setup 例外：Semi 化——Upload（点击 / 拖拽）
 * + TextArea 预览；admin_missing → Banner warning + Modal 确认「改走全新安装」。
 * 请求层迁移：提交改 ahooks useRequest（manual，按钮 loading 绑
 * hook loading）；错误进 onError（§5.4-#5 per-call 覆盖）——请求 / 后端
 * 错误走 Semi Toast，admin_missing 除外（§13.2 ④ 分支动作：Banner +
 * Modal 专属呈现，不是一般错误提示）。
 */
import { useEffect, useState } from 'react';
import { useRequest } from 'ahooks';
import {
  Banner,
  Button,
  Modal,
  TextArea,
  Toast,
  Typography,
  Upload,
} from '@douyinfe/semi-ui-19';
import { requestUploadConfig, setupMessage } from '../api';
import { ApiError } from '../../shared/api/errors';
import { t } from '../../shared/i18n';
import styles from './UploadConfigPage.module.less';

interface UploadConfigPageProps {
  onRestarting: () => void;
  onSwitchToInstall: () => void;
  /** Steps 推进用：提交态上抛给 SetupPage（「执行安装」步 + 锁步骤跳转）。 */
  onSubmittingChange?: (submitting: boolean) => void;
}

export default function UploadConfigPage({
  onRestarting,
  onSwitchToInstall,
  onSubmittingChange,
}: UploadConfigPageProps) {
  const [configText, setConfigText] = useState('');
  const [adminMissing, setAdminMissing] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);
  // 提交改 ahooks manual + onError 覆盖（§5.4-#5）——admin_missing
  // 是分支动作（§13.2 ④：Banner + Modal），不走集中 Toast；其余 Toast。
  // 成功经 onSuccess 进入重启流程（错误进 onError，run 不 rethrow）。
  const { run: uploadRun, loading: submitting } = useRequest(requestUploadConfig, {
    manual: true,
    onSuccess: () => {
      // §13.2：成功响应 restarting:true，进入与全新安装一致的重启流程。
      onRestarting();
    },
    onError: (error) => {
      if (error instanceof ApiError && error.code === 'admin_missing') {
        setAdminMissing(true);
      } else {
        Toast.error({
          content: setupMessage(error instanceof ApiError ? error.code : 'internal'),
        });
      }
    },
  });

  // 提交态上抛（Steps current 推进 + 锁步骤跳转），随请求状态联动。
  useEffect(() => {
    onSubmittingChange?.(submitting);
  }, [submitting, onSubmittingChange]);

  const canSubmit = configText.trim() !== '' && !submitting;

  function handleSubmit(): void {
    setAdminMissing(false);
    uploadRun(configText);
  }

  return (
    <div className={styles.stack}>
      <Typography.Title heading={3}>
        {t('setup.uploadConfigTitle')}
      </Typography.Title>
      <Typography.Paragraph type="secondary">
        {t('setup.uploadConfigIntro')}
      </Typography.Paragraph>
      <Upload
        action=""
        draggable
        accept=".yaml,.yml,text/yaml,text/plain"
        limit={1}
        dragMainText={t('setup.uploadDragMain')}
        dragSubText={t('setup.uploadDragSub')}
        customRequest={({ fileInstance, onSuccess, onError }) => {
          // 只按纯文本读入编辑框，供用户核对后提交；不解析内容（§6b）。
          // customRequest 语义仅为本地读入，不发任何网络请求。
          fileInstance
            .text()
            .then((text) => {
              setConfigText(text);
              onSuccess({});
            })
            .catch(() => {
              Toast.error({ content: t('setup.unreadableFile') });
              onError({});
            });
        }}
      />
      <TextArea
        rows={14}
        value={configText}
        placeholder={t('setup.uploadConfigPlaceholder')}
        onChange={(value) => setConfigText(value)}
      />
      {adminMissing ? (
        <>
          <Banner type="warning" description={t('setup.adminMissingHint')} />
          <Button
            block
            onClick={() => {
              setConfirmOpen(true);
            }}
          >
            {t('setup.switchToInstall')}
          </Button>
        </>
      ) : null}
      <Button
        theme="solid"
        block
        disabled={!canSubmit}
        loading={submitting}
        onClick={handleSubmit}
      >
        {submitting ? t('setup.initializing') : t('setup.startInitialize')}
      </Button>
      <Modal
        title={t('setup.adminMissingConfirmTitle')}
        visible={confirmOpen}
        okText={t('setup.switchToInstall')}
        cancelText={t('setup.cancel')}
        onOk={() => {
          setConfirmOpen(false);
          onSwitchToInstall();
        }}
        onCancel={() => {
          setConfirmOpen(false);
        }}
      >
        {t('setup.adminMissingConfirmContent')}
      </Modal>
    </div>
  );
}

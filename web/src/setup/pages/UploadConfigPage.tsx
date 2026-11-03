/**
 * 上传已有配置页（路径 A，docs/前端架构.md §6b / 接口文档 §13.2）：
 * 上传 config.yaml 全文；失败按 error.code 反馈（校验 / 连接 / 初始化），
 * 可修正后重试；成功（restarting:true）进入与全新安装一致的重启流程。
 * 约束（§6b）：不解析、不回显配置内容（可能含密钥）——文件只按纯文本读入
 * 编辑框，此外不渲染、不日志输出配置内容。
 */
import { useState, type ChangeEvent } from 'react';
import {
  requestUploadConfig,
  setupMessage,
  SetupError,
} from '../api';

interface UploadConfigPageProps {
  onRestarting: () => void;
  onSwitchToInstall: () => void;
}

export default function UploadConfigPage({
  onRestarting,
  onSwitchToInstall,
}: UploadConfigPageProps) {
  const [configText, setConfigText] = useState('');
  const [errorText, setErrorText] = useState<string | null>(null);
  const [adminMissing, setAdminMissing] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const canSubmit = configText.trim() !== '' && !submitting;

  async function handleSubmit(): Promise<void> {
    setSubmitting(true);
    setErrorText(null);
    setAdminMissing(false);
    try {
      // §13.2：成功响应 restarting:true，进入与全新安装一致的重启流程。
      await requestUploadConfig(configText);
      onRestarting();
    } catch (error) {
      if (error instanceof SetupError) {
        setErrorText(setupMessage(error.code));
        // §13.2 ④：版本已最新但管理员缺失 → 改走全新安装。
        setAdminMissing(error.code === 'admin_missing');
      } else {
        setErrorText(setupMessage('internal_error'));
      }
    } finally {
      setSubmitting(false);
    }
  }

  function handleFileChange(event: ChangeEvent<HTMLInputElement>): void {
    const file = event.target.files?.[0];
    if (!file) {
      return;
    }
    // 只按纯文本读入编辑框，供用户核对后提交；不解析内容。
    file
      .text()
      .then((text) => {
        setConfigText(text);
      })
      .catch(() => {
        setErrorText('无法读取所选文件');
      });
  }

  return (
    <>
      <h1>上传已有配置</h1>
      <p>
        粘贴或选择已有的 config.yaml 全文；系统将按序完成配置校验、数据库 /
        Redis 连接检查与初始化，成功后自动进入重启。
      </p>
      <div>
        <input
          type="file"
          accept=".yaml,.yml,text/yaml,text/plain"
          onChange={handleFileChange}
        />
      </div>
      <div>
        <textarea
          rows={14}
          cols={80}
          spellCheck={false}
          placeholder="config.yaml 全文"
          value={configText}
          onChange={(event) => setConfigText(event.target.value)}
        />
      </div>
      {errorText ? (
        <p role="alert" style={{ color: '#c0392b' }}>
          {errorText}
        </p>
      ) : null}
      {adminMissing ? (
        <p>该配置对应版本已最新但缺少管理员账号，需改走全新安装创建管理员。</p>
      ) : null}
      <div>
        <button type="button" disabled={!canSubmit} onClick={handleSubmit}>
          {submitting ? '正在初始化…' : '开始初始化'}
        </button>
        {adminMissing ? (
          <button type="button" onClick={onSwitchToInstall}>
            改走全新安装
          </button>
        ) : null}
      </div>
    </>
  );
}

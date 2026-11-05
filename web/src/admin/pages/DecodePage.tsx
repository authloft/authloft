/**
 * 解码工具页（docs/前端架构.md §6 行 525 DecodePage；docs/接口文档.md §5.6
 * 行 1289 DecodeToken）——/admin/decode。
 *
 * {token, purpose:"login"|"session"|"cookie"} → DecodeResponse.payload
 * （google.protobuf.Struct 原样透传，§5.6 行 1289「解码内容，排障用」——
 * 不为前台消费建模，前端不解析载荷、只展示 JSON）。口径（行 1289 +
 * 《后端架构》§11.6.1）：login 解 login_token、session 解 session_token、
 * cookie 解 al_login_state Cookie（三取值均按文档常驻选项；后端 cookie
 * 分支的解锁节奏不影响前端表单）。失败（篡改 / 跨 purpose / 无效）→
 * ApiError 就地展示（invalid_argument → 通用文案，不透出内部细节）；
 * 401 跳登录（提交失败内联分流，页面无自动请求）。
 *
 * 组件壳 import Semi 后不可 node 测试（既有 Blocker），可测逻辑收口
 * ./api（buildDecodeTokenRequest / decodePayloadText）。
 * 样式（§1.7）：同目录同名 module less。
 */
import { useState, type ReactNode } from 'react';
import { Button, Select, TextArea, Typography } from '@douyinfe/semi-ui-19';
import type { JsonObject } from '@bufbuild/protobuf';
import { t, type I18nKey } from '../../shared/i18n';
import {
  apiErrorText,
  buildDecodeTokenRequest,
  decodePayloadText,
  decodeToken,
  isUnauthenticatedError,
} from '../api';
import { loginUrl } from '../bootstrap';
import styles from './DecodePage.module.less';

/**
 * 解码口径下拉（§5.6 行 1289 purpose 值域 login|session|cookie，文案注解取值语义）。
 * textKey 字段化——模块级只存键，消费方渲染期 t(textKey)。
 */
const PURPOSE_OPTIONS: readonly { readonly value: string; readonly textKey: I18nKey }[] = [
  { value: 'login', textKey: 'admin.decodePurposeLogin' },
  { value: 'session', textKey: 'admin.decodePurposeSession' },
  { value: 'cookie', textKey: 'admin.decodePurposeCookie' },
];

/** 解码工具页：token + purpose 表单 → 载荷 JSON 展示。 */
export function DecodePage(props: {
  /** 归一后 al_root（401 跳登录前缀）。 */
  readonly alRoot: string;
}): ReactNode {
  const [token, setToken] = useState('');
  const [purpose, setPurpose] = useState('login');
  const [payload, setPayload] = useState<JsonObject | undefined>(undefined);
  const [decodeError, setDecodeError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  /** 提交解码（§5.6 行 1289）：失败就地提示（invalid_request 语义经 apiErrorText 通用文案）。 */
  async function submit(): Promise<void> {
    const trimmed = token.trim();
    if (trimmed === '' || submitting) {
      return;
    }
    setSubmitting(true);
    setDecodeError(null);
    setPayload(undefined);
    try {
      const res = await decodeToken(buildDecodeTokenRequest(trimmed, purpose));
      setPayload(res.payload);
    } catch (error) {
      if (isUnauthenticatedError(error)) {
        // §6 行 501：401 统一跳登录（提交请求失败内联分流；本页无自动请求）。
        window.location.replace(loginUrl(props.alRoot));
      } else {
        setDecodeError(apiErrorText(error));
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <section className={styles.page}>
      <Typography.Title heading={3}>{t('admin.navDecode')}</Typography.Title>
      <div className={styles.form}>
        <Select
          className={styles.purposeSelect}
          value={purpose}
          onChange={(value) => {
            setPurpose(typeof value === 'string' ? value : 'login');
          }}
          optionList={PURPOSE_OPTIONS.map((option) => ({
            value: option.value,
            label: t(option.textKey),
          }))}
          aria-label={t('admin.decodePurposeAriaLabel')}
        />
        <TextArea
          className={styles.tokenInput}
          value={token}
          onChange={(value) => setToken(value)}
          rows={3}
          placeholder={t('admin.decodeTokenPlaceholder')}
          aria-label={t('admin.decodeTokenAriaLabel')}
        />
        <div className={styles.formFooter}>
          <Button
            theme="solid"
            disabled={token.trim() === ''}
            loading={submitting}
            onClick={() => {
              void submit();
            }}
          >
            {t('admin.decodeAction')}
          </Button>
        </div>
      </div>
      {decodeError !== null ? (
        <p role="alert" className={styles.actionError}>
          {decodeError}
        </p>
      ) : null}
      {payload !== undefined ? (
        <div className={styles.resultBlock}>
          <p className={styles.resultHint}>{t('admin.decodeResultHint')}</p>
          <pre className={styles.result}>{decodePayloadText(payload)}</pre>
        </div>
      ) : null}
    </section>
  );
}

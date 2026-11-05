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
import {
  apiErrorText,
  buildDecodeTokenRequest,
  decodePayloadText,
  decodeToken,
  isUnauthenticatedError,
} from '../api';
import { loginUrl } from '../bootstrap';
import styles from './DecodePage.module.less';

/** 解码口径下拉（§5.6 行 1289 purpose 值域 login|session|cookie，文案注解取值语义）。 */
const PURPOSE_OPTIONS: readonly { readonly value: string; readonly label: string }[] = [
  { value: 'login', label: 'login_token（登录令牌）' },
  { value: 'session', label: 'session_token（会话令牌）' },
  { value: 'cookie', label: 'al_login_state（登录态 Cookie）' },
];

/** 结果区说明（§5.6 行 1289：解码内容仅排障用）。 */
const RESULT_HINT_TEXT =
  '解码结果为令牌内部载荷（Struct 原样透传），仅供排障参考，请勿外泄令牌与载荷内容。';

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
      <Typography.Title heading={3}>解码工具</Typography.Title>
      <div className={styles.form}>
        <Select
          className={styles.purposeSelect}
          value={purpose}
          onChange={(value) => {
            setPurpose(typeof value === 'string' ? value : 'login');
          }}
          optionList={PURPOSE_OPTIONS.map((option) => ({
            value: option.value,
            label: option.label,
          }))}
          aria-label="解码口径"
        />
        <TextArea
          className={styles.tokenInput}
          value={token}
          onChange={(value) => setToken(value)}
          rows={3}
          placeholder="粘贴待解码的令牌原文"
          aria-label="待解码令牌"
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
            解码
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
          <p className={styles.resultHint}>{RESULT_HINT_TEXT}</p>
          <pre className={styles.result}>{decodePayloadText(payload)}</pre>
        </div>
      ) : null}
    </section>
  );
}

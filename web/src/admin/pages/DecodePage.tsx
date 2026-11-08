/**
 * 解码工具页（docs/前端架构.md §6 行 525 DecodePage；docs/接口文档.md §5.6
 * 行 1289 DecodeToken）——/admin/decode。
 *
 * {token, purpose:"login"|"session"|"cookie"} → DecodeResponse.payload
 * （google.protobuf.Struct 原样透传，§5.6 行 1289「解码内容，排障用」——
 * 不为前台消费建模，前端不解析载荷、只展示 JSON）。口径（行 1289 +
 * 《后端架构》§11.6.1）：login 解 login_token、session 解 session_token、
 * cookie 解 al_login_state Cookie（三取值均按文档常驻选项；后端 cookie
 * 分支的解锁节奏不影响前端表单）。提交改 ahooks manual + 集中
 * onError——401 跳登录（带 returnTo）与其余错误 Toast 均由
 * requestOptions 分派（原内联分流删除，页面无自动请求）。
 *
 * 组件壳 import Semi 后不可 node 测试（既有 Blocker），可测逻辑收口
 * ./api（buildDecodeTokenRequest / decodePayloadText）。
 * 样式（§1.7）：同目录同名 module less。
 */
import { useState, type ReactNode } from 'react';
import { Button, Select, TextArea, Typography } from '@douyinfe/semi-ui';
import { useLocation } from '@modern-js/runtime/router';
import { useRequest } from 'ahooks';
import type { JsonObject } from '@bufbuild/protobuf';
import { t, type I18nKey } from '../../shared/i18n';
import { requestOptions } from '../../shared/hooks/requestOptions';
import {
  adminReturnTo,
  buildDecodeTokenRequest,
  decodePayloadText,
  decodeToken,
} from '../api';
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
export function DecodePage(_props: {
  /** 归一后 al_root（路由传参保留；401 跳登录已收敛集中 onError，本页不再消费）。 */
  readonly alRoot: string;
}): ReactNode {
  const [token, setToken] = useState('');
  const [purpose, setPurpose] = useState('login');
  const [payload, setPayload] = useState<JsonObject | undefined>(undefined);
  // 401 跳登录带 returnTo（/admin# + hash 内路径，登录后跳回本页）。
  const location = useLocation();
  // 提交改 ahooks manual + 集中 onError（定稿 §7）——401 由
  // requestOptions 跳登录（returnTo 取 HashRouter 内路径），其余错误
  // Toast；成功经 onSuccess 落 payload。
  const decodeReq = useRequest(
    (request: ReturnType<typeof buildDecodeTokenRequest>) => decodeToken(request),
    {
      manual: true,
      onSuccess: (res) => {
        setPayload(res.payload);
      },
      ...requestOptions({
        returnTo: () => adminReturnTo(location.pathname, location.search),
      }),
    },
  );

  /** 提交解码（§5.6 行 1289）：失败经集中 onError（401 跳登录 / 其余 Toast）。 */
  function submit(): void {
    const trimmed = token.trim();
    if (trimmed === '' || decodeReq.loading) {
      return;
    }
    setPayload(undefined);
    decodeReq.run(buildDecodeTokenRequest(trimmed, purpose));
  }

  return (
    <section className={styles.page}>
      <Typography.Title heading={3} className="page-title">{t('admin.navDecode')}</Typography.Title>
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
            loading={decodeReq.loading}
            onClick={submit}
          >
            {t('admin.decodeAction')}
          </Button>
        </div>
      </div>
      {payload !== undefined ? (
        <div className={styles.resultBlock}>
          <p className={styles.resultHint}>{t('admin.decodeResultHint')}</p>
          <pre className={styles.result}>{decodePayloadText(payload)}</pre>
        </div>
      ) : null}
    </section>
  );
}

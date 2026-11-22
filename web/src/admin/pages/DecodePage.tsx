/**
 * 解码工具页（docs/前端架构.md §6 行 525 DecodePage；docs/接口文档.md §5.6
 * 行 1289 DecodeToken）——/admin/decode。
 *
 * {token, purpose} → DecodeResponse.payload
 * （google.protobuf.Struct 原样透传，§5.6 行 1289「解码内容，排障用」——
 * 不为前台消费建模，前端不解析载荷、只展示 JSON）。口径（行 1289 +
 * 《后端架构》§11.6.1）：purpose 取 §11.6.1 AAD purpose 九值封闭集，
 * 与后端 security/purpose.go 逐字一致（前端不校验值域，非法值由后端
 * invalid_request 兜底）。提交改 ahooks manual + 集中
 * onError——401 跳登录（带 returnTo）与其余错误 Toast 均由
 * requestOptions 分派（原内联分流删除，页面无自动请求）。
 *
 * 组件壳 import Semi 后不可 node 测试（既有 Blocker），可测逻辑收口
 * ./api（buildDecodeTokenRequest / decodePayloadText）。
 * 样式（§1.7）：同目录同名 module less。
 */
import { useState, type ReactNode } from 'react';
import { Button, Select, TextArea } from '@douyinfe/semi-ui';
import { useLocation } from '@modern-js/runtime/router';
import { useRequest } from 'ahooks';
import type { JsonObject } from '@bufbuild/protobuf';
import { t, type I18nKey } from '../../shared/i18n';
import { requestOptions } from '../../shared/hooks/requestOptions';
import { PageLayout } from '../../shared/components/PageLayout';
import {
  adminReturnTo,
  buildDecodeTokenRequest,
  decodePayloadText,
  decodeToken,
} from '../api';
import styles from './DecodePage.module.less';

/**
 * 解码口径下拉（§5.6 行 1289 purpose 九值封闭集，文案注解取值语义；
 * 顺序 = 既有三值在前，新增按 purpose.go 常量序）。
 * textKey 字段化——模块级只存键，消费方渲染期 t(textKey)。
 */
const PURPOSE_OPTIONS: { value: string; textKey: I18nKey }[] = [
  { value: 'login', textKey: 'admin.decodePurposeLogin' },
  { value: 'session', textKey: 'admin.decodePurposeSession' },
  { value: 'cookie', textKey: 'admin.decodePurposeCookie' },
  { value: 'ticket', textKey: 'admin.decodePurposeTicket' },
  { value: 'verification', textKey: 'admin.decodePurposeVerification' },
  { value: 'challenge', textKey: 'admin.decodePurposeChallenge' },
  { value: 'sync_payload', textKey: 'admin.decodePurposeSyncPayload' },
  { value: 'oidc_code', textKey: 'admin.decodePurposeOidcCode' },
  { value: 'oidc_sub', textKey: 'admin.decodePurposeOidcSub' },
];

/** 解码工具页：token + purpose 表单 → 载荷 JSON 展示。 */
export function DecodePage(_props: {
  /** 归一后 al_root（路由传参保留；401 跳登录已收敛集中 onError，本页不再消费）。 */
  alRoot: string;
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
    (request: ReturnType<typeof buildDecodeTokenRequest>) =>
      decodeToken(request),
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
    <PageLayout title={t('admin.navDecode')}>
      <div className={styles.content}>
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
      </div>
    </PageLayout>
  );
}

/**
 * 文本内容二维码自绘组件（docs/接口文档.md §3.5 行 922「前端绘制
 * 二维码」）：选型 qrcode-generator@2.0.4（零传递依赖 + 自带 TS 类型，
 * pnpm add 实证仅 +1 包）产出模块矩阵，本组件自渲染 SVG——纯 DOM 绘制，
 * 无 canvas / dataURL / 脚本字符串，页面 CSP（§9.22 无 unsafe-eval）不受
 * 影响。生成失败（空串 / 超容量）渲染 null，码图缺席时调用方文本兜底
 * （如 TotpBindDialog 的密钥 / otpauth 文本）仍可完成添加。
 * 零 Semi 依赖（跨 entry 通用组件，§9.13），node 环境可 renderToStaticMarkup
 * 直测（同 QRCodePanel 的纯函数 + View 测试口径，前端架构 §8.2）。
 */
import type { ReactNode } from 'react';
// esModuleInterop（@modern-js/tsconfig/base）下 export = 工厂的默认导入。
import qrcode from 'qrcode-generator';
import styles from './QrImage.module.less';

/** 静默区模块数（ISO/IEC 18004：码图四周须留 ≥4 模块空白，扫读依赖）。 */
const QUIET_ZONE = 4;

/** 默认渲染尺寸 px（验证器扫码的常规展示大小）。 */
const DEFAULT_SIZE = 180;

/** 码图 SVG 组装结果：modules = 单边模块数，path = 暗模块单路径。 */
export interface QrSvgBuild {
  readonly modules: number;
  readonly path: string;
}

/**
 * 文本内容 → QR 模块矩阵的单 path SVG 几何（纯函数，node 可测）：
 * 每行暗模块 run-length 合并（`M{x} {y}h{n}v1h-{n}z`），避免逐模块矩形
 * 膨胀产物；纠错级 M（验证器扫码通用档）。失败（空串 / make 抛错——
 * 容量上限 40-M 约 2331 字节）返回 undefined，调用方按文本兜底回退。
 */
export function buildQrSvg(content: string): QrSvgBuild | undefined {
  if (content === '') {
    return undefined;
  }
  try {
    const qr = qrcode(0, 'M');
    qr.addData(content);
    qr.make();
    const modules = qr.getModuleCount();
    let path = '';
    for (let row = 0; row < modules; row += 1) {
      let runStart = -1;
      for (let col = 0; col <= modules; col += 1) {
        const dark = col < modules && qr.isDark(row, col);
        if (dark && runStart < 0) {
          runStart = col;
        } else if (!dark && runStart >= 0) {
          path += `M${runStart} ${row}h${col - runStart}v1h-${col - runStart}z`;
          runStart = -1;
        }
      }
    }
    return { modules, path };
  } catch {
    return undefined;
  }
}

/**
 * 二维码图（渲染兜底：生成失败 → null，不阻塞调用方布局）。黑白对比为
 * 扫码硬件的识别需求而非主题样式，固定 fill（深浅色主题下均可扫读）；
 * viewBox 含静默区，码图自含白底、独立可扫。
 */
export function QrImage(props: {
  /** 编码内容（BindTotp challenge 的 qrcodeContent；§9.18 零值兜底由调用方完成）。 */
  readonly content: string;
  /** 无障碍名（role="img" 的 aria-label），调用方传 i18n 键值。 */
  readonly alt: string;
  /** 渲染尺寸 px（缺省 180）。 */
  readonly size?: number;
}): ReactNode {
  const build = buildQrSvg(props.content);
  if (build === undefined || build.path === '') {
    return null;
  }
  const side = props.size ?? DEFAULT_SIZE;
  const span = build.modules + QUIET_ZONE * 2;
  return (
    <svg
      className={styles.qr}
      role="img"
      aria-label={props.alt}
      width={side}
      height={side}
      viewBox={`${-QUIET_ZONE} ${-QUIET_ZONE} ${span} ${span}`}
      shapeRendering="crispEdges"
    >
      <rect x={-QUIET_ZONE} y={-QUIET_ZONE} width={span} height={span} fill="#fff" />
      <path d={build.path} fill="#000" />
    </svg>
  );
}

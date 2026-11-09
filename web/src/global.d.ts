/**
 * 全局 TS 模块声明（docs/前端架构.md §1.7 样式方案）。
 * Modern.js 官方口径：样式模块的类型声明由项目自建（app-tools 内置类型
 * 不含 *.less）；本文件是样式收口的共同基建。
 * 最小集：CSS Modules（*.module.less）+ 全局样式副作用 import（*.less）。
 */
declare module '*.module.less' {
  const classes: { [key: string]: string };
  export default classes;
}

declare module '*.less' {
  /** 全局样式副作用 import（shared/styles 的 tokens/reset），无运行期导出值。 */
  const content: void;
  export default content;
}

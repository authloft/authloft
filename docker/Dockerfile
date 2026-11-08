# Authloft 默认镜像（debian 运行时，glibc）：复用 CI 前序已构建的 web/dist，镜像内只做壳层同步与 go 编译
# （docs/后端架构.md §23.1）
# 构建上下文为「最小上下文目录」（只含 server/、web/dist、web/scripts/sync-templates.mjs，
# 以及平铺到上下文根的当前变体 Dockerfile）：
#   本地：docker build -f .docker-build/Dockerfile .docker-build
#   CI：docker/build-push-action 的 context=.docker-build、file=.docker-build/Dockerfile
# 该目录由 build-manual.yml 的 docker-publish job 组装（web/dist 来自 web-dist artifact），
# 上下文已只含必需输入，天然排除 node_modules / 本地残留，不再需要 .dockerignore。
# 本地构建需先 pnpm --dir web build 产出 web/dist，再按同一布局组装 .docker-build/。

# ---- web 阶段：承接已构建的 web/dist，并向 server 阶段提供 node 运行时 ----
FROM node:24 AS web
WORKDIR /build/web
# web/dist 由前序 web-build job 产出并经 download-artifact 落位；镜像内不再安装依赖 / 不跑 pnpm build
COPY web/dist ./dist

# ---- server 阶段：golang（版本随 server/go.mod），CGO_ENABLED=0 静态编译单二进制 ----
FROM golang:1.26 AS server
WORKDIR /build
# sync-templates.mjs 仅用 node 内置模块（零依赖），从 web 阶段借 node 运行时（同源 bookworm 基础）
COPY --from=web /usr/local/bin/node /usr/local/bin/node
COPY server/go.mod server/go.sum server/
RUN cd server && go mod download
COPY server/ server/
COPY --from=web /build/web/dist web/dist
COPY web/scripts/sync-templates.mjs web/scripts/sync-templates.mjs
# 壳层模板与静态资产落位（§3.13），供 server/assets embed 进二进制
RUN node web/scripts/sync-templates.mjs
RUN cd server && CGO_ENABLED=0 GOAMD64=v1 go build -ldflags "-s -w" -o /out/authloft .

# ---- 运行时阶段：仅二进制 + ca-certificates/tzdata + 非 root 用户 ----
FROM debian:stable-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r authloft && useradd -r -g authloft authloft \
    && mkdir -p /conf && chown authloft:authloft /conf
COPY --from=server /out/authloft /usr/local/bin/authloft
USER authloft
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/authloft", "--config", "/conf/authloft.yml"]

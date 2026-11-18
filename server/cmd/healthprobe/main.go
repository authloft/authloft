// Command healthprobe 容器 HEALTHCHECK 探针（docs/后端架构.md §23.1）：
// GET /health，2xx 视为就绪退出 0，其余（连接失败 / 非 2xx / 超时）退出 1。
// 运行时镜像不装 curl / wget（debian-slim 两者皆无，不引入新包），debian 与
// alpine 共用同一静态探针二进制。
//
// 探针目标可用 AUTHLOFT_HEALTHCHECK_URL 覆盖，默认本机 8080 端口 /health，
// 与 EXPOSE / server.listen 缺省（":8080"）一致；若改监听地址需同步覆盖该
// 变量。HTTP 超时须大于 /health 内部逐依赖探活上限（internal/app probeTimeout
// 2s），取 5s 留出余量；HEALTHCHECK 指令的 --timeout 再大于此值。
package main

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

const (
	// defaultHealthURL 容器内缺省探针目标（本机回环，EXPOSE 8080）。
	defaultHealthURL = "http://127.0.0.1:8080/health"
	// envHealthURL 监听地址变更时的覆盖入口（Dockerfile 不写死端口假设之外的值）。
	envHealthURL = "AUTHLOFT_HEALTHCHECK_URL"
	// clientTimeout 探针 HTTP 客户端总超时，须大于 /health 内部探活上限。
	clientTimeout = 5 * time.Second
)

func main() {
	target := os.Getenv(envHealthURL)
	if target == "" {
		target = defaultHealthURL
	}
	if code := probe(target, &http.Client{Timeout: clientTimeout}); code != 0 {
		os.Exit(code)
	}
}

// probe GET 目标并按状态码给退出值：2xx → 0，其余 → 1；原因写 stderr 供
// docker inspect 排障，不带响应体（响应体无敏感面，但探针输出保持最小）。
func probe(target string, client *http.Client) int {
	resp, err := client.Get(target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthprobe:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "healthprobe: %s -> %d\n", target, resp.StatusCode)
		return 1
	}
	return 0
}

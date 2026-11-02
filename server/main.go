package main

func main() {
	// TODO(config): rootOrigin 与小程序 appid Referer 白名单待 config 系统接入后注入；
	// 空值下非免检查写请求保守 403（见 middleware/origin.go）。
	r, _ := newRouter("", nil)
	// TODO(config): 监听地址暂用 gin 默认 :8080（脚手架遗留）。
	_ = r.Run()
}

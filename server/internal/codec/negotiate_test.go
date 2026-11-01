package codec

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNegotiate(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		accept string
		want   Format
	}{
		{name: "缺失 Accept 回落 JSON", path: "/api/account/profile", want: FormatJSON},
		{name: "Accept 为空串回落 JSON", path: "/api/account/profile", accept: "", want: FormatJSON},
		{name: "通配符 */* 回落 JSON", path: "/api/account/profile", accept: "*/*", want: FormatJSON},
		{name: "仅 application/json", path: "/api/account/profile", accept: "application/json", want: FormatJSON},
		{name: "json 带 charset", path: "/api/account/profile", accept: "application/json; charset=utf-8", want: FormatJSON},
		{name: "仅 octet-stream 无 json", path: "/api/account/profile", accept: "application/octet-stream", want: FormatProto},
		{name: "octet 与 json 均缺省 q 相等", path: "/api/account/profile", accept: "application/octet-stream, application/json", want: FormatProto},
		{name: "octet q 等于 json q", path: "/api/account/profile", accept: "application/octet-stream;q=0.5, application/json;q=0.5", want: FormatProto},
		{name: "octet q 大于 json q", path: "/api/account/profile", accept: "application/octet-stream;q=1, application/json;q=0.8", want: FormatProto},
		{name: "octet q 小于 json q", path: "/api/account/profile", accept: "application/octet-stream;q=0.4, application/json;q=0.5", want: FormatJSON},
		{name: "octet q=0 视为不可接受", path: "/api/account/profile", accept: "application/octet-stream;q=0", want: FormatJSON},
		{name: "json q=0 仅 octet 可用", path: "/api/account/profile", accept: "application/octet-stream;q=1, application/json;q=0", want: FormatProto},
		{name: "媒体类型大小写不敏感", path: "/api/account/profile", accept: "Application/Octet-Stream", want: FormatProto},
		{name: "无法识别类型回落 JSON", path: "/api/account/profile", accept: "text/html", want: FormatJSON},
		{name: "多值取最高 q", path: "/api/account/profile", accept: "application/octet-stream;q=0.2, application/octet-stream;q=0.9, application/json;q=0.5", want: FormatProto},
		{name: "白名单 /api/oidc/** 恒 JSON", path: "/api/oidc/token", accept: "application/octet-stream", want: FormatJSON},
		{name: "白名单 /api/oidc 精确路径恒 JSON", path: "/api/oidc", accept: "application/octet-stream", want: FormatJSON},
		{name: "白名单 /api/gateway/** 恒 JSON", path: "/api/gateway/decode", accept: "application/octet-stream", want: FormatJSON},
		{name: "白名单前缀不误伤相似路径", path: "/api/oidcfoo/x", accept: "application/octet-stream", want: FormatProto},
		{name: "非白名单路径按 Accept 协商", path: "/api/account/profile", accept: "application/octet-stream", want: FormatProto},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, tt.path, nil)
			if tt.accept != "" {
				r.Header.Set("Accept", tt.accept)
			}
			if got := Negotiate(r); got != tt.want {
				t.Errorf("Negotiate(%q, Accept=%q) = %v, want %v", tt.path, tt.accept, got, tt.want)
			}
		})
	}
}

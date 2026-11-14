// sealer_test.go TicketResultSealer 的加密往返用例（随 sealer 迁入本包）：
// protojson 整值加密往返 + 跨密钥拒绝 + 未知版本按失败处理。
package ticket

import (
	"testing"

	"authloft/gen/go/token"
)

// TestTicketResultSealerRoundtrip protojson 整值加密往返 + 跨密钥拒绝 +
// 未知版本按失败处理（§11.6.5 行 1347 / 1351）。
func TestTicketResultSealerRoundtrip(t *testing.T) {
	codec := tpCodec(t, 0x50)
	sealer := NewTicketResultSealer(codec)
	res := &token.TicketResult{
		V: 1, Scene: "login", Status: "success", ProviderKey: "scan", Channel: "qrcode",
		LoginResult: &token.LoginResult{Uid: 9},
	}
	sealed, err := sealer.Seal(res)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := sealer.Open(sealed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got.GetV() != 1 || got.GetScene() != "login" || got.GetStatus() != "success" ||
		got.GetLoginResult().GetUid() != 9 || got.GetChannel() != "qrcode" {
		t.Fatalf("roundtrip = %+v", got)
	}
	// 跨密钥不可解。
	if _, err := NewTicketResultSealer(tpCodec(t, 0x51)).Open(sealed); err == nil {
		t.Fatalf("跨密钥不应解 开")
	}
	// 未知版本按失败处理（§11.6.5 行 1351）。
	bad, err := sealer.Seal(&token.TicketResult{V: 99, Status: "success"})
	if err != nil {
		t.Fatalf("Seal v99: %v", err)
	}
	if _, err := sealer.Open(bad); err == nil {
		t.Fatalf("未知版本应按失败处理")
	}
}

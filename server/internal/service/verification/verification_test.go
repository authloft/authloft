package verification

import "testing"

func TestBizPurposeClosedSet(t *testing.T) {
	all := []BizPurpose{
		BizPurposeLogin, BizPurposeMFA, BizPurposeBindContact,
		BizPurposeChangePassword, BizPurposeUnbindTOTP,
		BizPurposeUnbindThirdParty, BizPurposeAdminSensitive,
		BizPurposeWebAuthnEnroll,
	}
	seen := map[BizPurpose]bool{}
	for _, bp := range all {
		if !bp.Valid() {
			t.Fatalf("%q should be valid", bp)
		}
		if seen[bp] {
			t.Fatalf("duplicate %q", bp)
		}
		seen[bp] = true
	}
	if len(seen) != 8 {
		t.Fatalf("closed set size = %d, want 8", len(seen))
	}
	for _, bp := range []BizPurpose{"", "register", "reset", "LOGIN"} {
		if bp.Valid() {
			t.Fatalf("%q must not be valid", bp)
		}
	}
}

func TestSubjectKindAndSubject(t *testing.T) {
	if !SubjectKindTID.Valid() || !SubjectKindUID.Valid() {
		t.Fatal("tid/uid must be valid")
	}
	if SubjectKind("sid").Valid() || SubjectKind("").Valid() {
		t.Fatal("unknown subject_kind must be invalid")
	}
	if !(Subject{Kind: SubjectKindUID, ID: "42"}).Valid() {
		t.Fatal("uid/42 must be valid")
	}
	for _, s := range []Subject{{}, {Kind: SubjectKindUID}, {ID: "42"}, {Kind: SubjectKind("x"), ID: "42"}} {
		if s.Valid() {
			t.Fatalf("%+v must be invalid", s)
		}
	}
}

func TestOwner(t *testing.T) {
	if got := Owner(BizPurposeMFA, "tid-1", "nonce-1"); got != "mfa:tid-1:nonce-1" {
		t.Fatalf("Owner = %q", got)
	}
}

func TestPolicyFactors(t *testing.T) {
	p := DefaultPolicy()
	stepUp := []string{"otp_sms", "otp_email", "webauthn", "totp", "recovery_code"}
	for _, bp := range []BizPurpose{
		BizPurposeLogin, BizPurposeMFA, BizPurposeBindContact,
		BizPurposeChangePassword, BizPurposeUnbindTOTP,
		BizPurposeUnbindThirdParty, BizPurposeAdminSensitive,
	} {
		got := p.Factors(bp)
		if len(got) != len(stepUp) {
			t.Fatalf("Factors(%q) = %v", bp, got)
		}
		for i := range stepUp {
			if got[i] != stepUp[i] {
				t.Fatalf("Factors(%q)[%d] = %q, want %q", bp, i, got[i], stepUp[i])
			}
		}
	}
	if got := p.Factors(BizPurposeWebAuthnEnroll); len(got) != 1 || got[0] != "webauthn" {
		t.Fatalf("enroll factors = %v", got)
	}
	if got := p.Factors(BizPurpose("unknown")); got != nil {
		t.Fatalf("unknown purpose factors = %v, want nil (fail-closed)", got)
	}
	// 返回副本：改写不得污染策略表。
	got := p.Factors(BizPurposeMFA)
	got[0] = "tampered"
	if p.Factors(BizPurposeMFA)[0] == "tampered" {
		t.Fatal("Factors must return a copy")
	}
}

func TestPolicyAllows(t *testing.T) {
	p := DefaultPolicy()
	for _, m := range []string{"otp_sms", "otp_email", "webauthn", "totp", "recovery_code"} {
		if !p.Allows(BizPurposeMFA, m) {
			t.Fatalf("mfa must allow %q", m)
		}
	}
	for _, m := range []string{"password", "thirdparty", "device", ""} {
		if p.Allows(BizPurposeMFA, m) {
			t.Fatalf("mfa must not allow %q", m)
		}
	}
	if !p.Allows(BizPurposeWebAuthnEnroll, "webauthn") || p.Allows(BizPurposeWebAuthnEnroll, "totp") {
		t.Fatal("enroll allows only webauthn")
	}
	if p.Allows(BizPurpose("unknown"), "totp") {
		t.Fatal("unknown purpose must allow nothing")
	}
}

func TestPolicyHighRisk(t *testing.T) {
	p := DefaultPolicy()
	for _, bp := range []BizPurpose{BizPurposeChangePassword, BizPurposeAdminSensitive} {
		if !p.HighRisk(bp) {
			t.Fatalf("%q must be high risk", bp)
		}
	}
	for _, bp := range []BizPurpose{
		BizPurposeLogin, BizPurposeMFA, BizPurposeBindContact,
		BizPurposeUnbindTOTP, BizPurposeUnbindThirdParty,
		BizPurposeWebAuthnEnroll, BizPurpose("unknown"),
	} {
		if p.HighRisk(bp) {
			t.Fatalf("%q must not be high risk", bp)
		}
	}
}

package robase

import (
	"errors"
	"testing"
)

const testSecret = "whsec_test"

func TestVerifyWebhookSignature(t *testing.T) {
	body := []byte(`{"event":"otp.sent","timestamp":"2026-07-22T10:00:00Z","data":{}}`)
	sig := SignWebhookPayload(body, testSecret)

	if err := VerifyWebhookSignature(body, sig, testSecret); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	if err := VerifyWebhookSignature(body, sig, "wrong-secret"); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("wrong secret accepted: %v", err)
	}
	if err := VerifyWebhookSignature(append(body, ' '), sig, testSecret); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("tampered body accepted: %v", err)
	}
	if err := VerifyWebhookSignature(body, "", testSecret); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("empty signature accepted: %v", err)
	}
}

// The signature must match the Go server's core.SignWebhookPayload exactly:
// lowercase hex HMAC-SHA256 over the raw body.
func TestSignatureMatchesServerFixture(t *testing.T) {
	got := SignWebhookPayload([]byte("hello"), "secret")
	want := "88aab3ede8d3adf94d26ab90d3bafd4a2083070c3bcce9c014ee04a443847c0b"
	if got != want {
		t.Errorf("SignWebhookPayload = %q, want %q", got, want)
	}
}

func TestParseWebhookOTPEvent(t *testing.T) {
	body := []byte(`{
		"event":"otp.verified",
		"timestamp":"2026-07-22T10:00:00Z",
		"data":{"id":"otp_1","phone_number":"+2348012345678","country_code":"NG","status":"verified","provider":"beem","credit_cost":1}
	}`)
	sig := SignWebhookPayload(body, testSecret)

	payload, err := ParseWebhook(body, sig, testSecret)
	if err != nil {
		t.Fatalf("ParseWebhook: %v", err)
	}
	if payload.Event != EventOTPVerified {
		t.Errorf("Event = %q", payload.Event)
	}
	data, err := payload.OTPData()
	if err != nil {
		t.Fatalf("OTPData: %v", err)
	}
	if data.ID != "otp_1" || data.Provider != "beem" {
		t.Errorf("unexpected data: %+v", data)
	}
}

func TestParseWebhookSMSEvent(t *testing.T) {
	body := []byte(`{
		"event":"sms.delivered",
		"timestamp":"2026-07-22T10:00:00Z",
		"data":{"id":"msg_1","phone_number":"+2348012345678","country_code":"NG","message":"hi","status":"delivered","provider":"termii","credit_cost":1}
	}`)
	payload, err := ParseWebhook(body, SignWebhookPayload(body, testSecret), testSecret)
	if err != nil {
		t.Fatalf("ParseWebhook: %v", err)
	}
	data, err := payload.SMSData()
	if err != nil {
		t.Fatalf("SMSData: %v", err)
	}
	if data.Status != "delivered" {
		t.Errorf("Status = %q", data.Status)
	}
}

func TestParseWebhookCreditEvent(t *testing.T) {
	body := []byte(`{
		"event":"credit_balance.low",
		"timestamp":"2026-07-22T10:00:00Z",
		"data":{"workspace_id":"ws_1","balance":42,"threshold":100}
	}`)
	payload, err := ParseWebhook(body, SignWebhookPayload(body, testSecret), testSecret)
	if err != nil {
		t.Fatalf("ParseWebhook: %v", err)
	}
	data, err := payload.CreditData()
	if err != nil {
		t.Fatalf("CreditData: %v", err)
	}
	if data.Balance != 42 || data.Threshold == nil || *data.Threshold != 100 {
		t.Errorf("unexpected data: %+v", data)
	}
}

func TestParseWebhookRejectsBadSignature(t *testing.T) {
	body := []byte(`{"event":"otp.sent","timestamp":"2026-07-22T10:00:00Z","data":{}}`)
	if _, err := ParseWebhook(body, "deadbeef", testSecret); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("err = %v, want ErrInvalidSignature", err)
	}
}

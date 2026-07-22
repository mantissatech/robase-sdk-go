package robase

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestOTPSendDecodesResponse(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v1/otp/send" {
			t.Errorf("got %s %s", r.Method, r.URL.Path)
		}
		w.Write([]byte(`{
			"id":"7f3a1c9e-0000-4000-8000-000000000001",
			"phone_number":"+2348012345678",
			"country_code":"NG",
			"credit_cost":1,
			"status":"pending",
			"code_length":6,
			"expires_at":"2026-07-22T10:10:00Z",
			"created_at":"2026-07-22T10:00:00Z"
		}`))
	}))

	got, err := c.OTP.Send(context.Background(), SendOTPParams{PhoneNumber: "+2348012345678"})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got.ID != "7f3a1c9e-0000-4000-8000-000000000001" {
		t.Errorf("ID = %q", got.ID)
	}
	if got.CountryCode != "NG" || got.CreditCost != 1 || got.Status != StatusPending {
		t.Errorf("unexpected response: %+v", got)
	}
	if !got.ExpiresAt.Equal(time.Date(2026, 7, 22, 10, 10, 0, 0, time.UTC)) {
		t.Errorf("ExpiresAt = %v", got.ExpiresAt)
	}
}

func TestOTPSendRequiresPhoneNumber(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request should not have been sent")
	}))
	if _, err := c.OTP.Send(context.Background(), SendOTPParams{}); err == nil {
		t.Fatal("expected a client-side validation error")
	}
}

func TestOTPVerifyValid(t *testing.T) {
	var body map[string]any
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&body)
		w.Write([]byte(`{"valid":true,"status":"verified","attempts_used":1}`))
	}))

	got, err := c.OTP.Verify(context.Background(), VerifyOTPParams{OTPID: "otp_1", Code: "123456"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	// The API names this field otp_id, not id.
	if body["otp_id"] != "otp_1" {
		t.Errorf("request body = %v, want otp_id", body)
	}
	if !got.Valid || got.Status != StatusVerified || got.AttemptsUsed != 1 {
		t.Errorf("unexpected response: %+v", got)
	}
	if got.AttemptsRemaining != nil {
		t.Errorf("AttemptsRemaining = %v, want nil on success", *got.AttemptsRemaining)
	}
}

func TestOTPVerifyWrongCodeIsNotAnError(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"valid":false,"status":"sent","attempts_used":2,"attempts_remaining":3}`))
	}))

	got, err := c.OTP.Verify(context.Background(), VerifyOTPParams{OTPID: "otp_1", Code: "000000"})
	if err != nil {
		t.Fatalf("a wrong code must not surface as an error, got %v", err)
	}
	if got.Valid {
		t.Error("Valid = true, want false")
	}
	if got.AttemptsRemaining == nil || *got.AttemptsRemaining != 3 {
		t.Errorf("AttemptsRemaining = %v, want 3", got.AttemptsRemaining)
	}
}

func TestOTPVerifyTerminalStatesAreErrors(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`{"error":{"type":"max_attempts_exceeded","message":"maximum verification attempts exceeded"}}`))
	}))

	_, err := c.OTP.Verify(context.Background(), VerifyOTPParams{OTPID: "otp_1", Code: "000000"})
	if !errors.Is(err, ErrMaxAttempts) {
		t.Fatalf("err = %v, want max_attempts_exceeded", err)
	}
}

func TestOTPVerifyRequiresFields(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request should not have been sent")
	}))
	if _, err := c.OTP.Verify(context.Background(), VerifyOTPParams{Code: "1"}); err == nil {
		t.Error("expected error for missing OTPID")
	}
	if _, err := c.OTP.Verify(context.Background(), VerifyOTPParams{OTPID: "otp_1"}); err == nil {
		t.Error("expected error for missing Code")
	}
}

func TestOTPGet(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/otp/otp_1" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Write([]byte(`{
			"id":"otp_1",
			"workspace_id":"ws_1",
			"phone_number":"+2348012345678",
			"country_code":"NG",
			"credit_cost":1,
			"provider":"beem",
			"status":"sent",
			"code_length":6,
			"ttl_seconds":600,
			"attempt_count":0,
			"max_attempts":5,
			"sent_at":"2026-07-22T10:00:05Z",
			"expired_at":"2026-07-22T10:10:00Z",
			"created_at":"2026-07-22T10:00:00Z"
		}`))
	}))

	got, err := c.OTP.Get(context.Background(), "otp_1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != StatusSent || got.Provider != "beem" || got.MaxAttempts != 5 {
		t.Errorf("unexpected record: %+v", got)
	}
	if got.SentAt == nil {
		t.Fatal("SentAt = nil")
	}
	if got.DeliveredAt != nil {
		t.Errorf("DeliveredAt = %v, want nil", got.DeliveredAt)
	}
}

func TestOTPGetNotFound(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":{"type":"otp_not_found","message":"OTP not found"}}`))
	}))
	if _, err := c.OTP.Get(context.Background(), "missing"); !errors.Is(err, ErrOTPNotFound) {
		t.Fatalf("err = %v, want otp_not_found", err)
	}
}

package robase

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// newTestClient wires a client to a test server with retries disabled by
// default so a test only sees the requests it makes.
func newTestClient(t *testing.T, h http.Handler, opts ...Option) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	all := append([]Option{WithBaseURL(srv.URL), WithMaxRetries(0)}, opts...)
	c, err := New("robe_test_key", all...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestNewRejectsBadKeys(t *testing.T) {
	if _, err := New(""); err == nil {
		t.Fatal("expected error for empty key")
	}
	if _, err := New("sk_live_nope"); err == nil {
		t.Fatal("expected error for key without robe_ prefix")
	}
}

func TestRequestHeaders(t *testing.T) {
	var got http.Header
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.Write([]byte(`{"id":"otp_1"}`))
	}))

	if _, err := c.OTP.Send(context.Background(), SendOTPParams{PhoneNumber: "+2348012345678"}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if want := "Bearer robe_test_key"; got.Get("Authorization") != want {
		t.Errorf("Authorization = %q, want %q", got.Get("Authorization"), want)
	}
	if got.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q", got.Get("Content-Type"))
	}
	if got.Get("User-Agent") != "robase-go/"+Version {
		t.Errorf("User-Agent = %q", got.Get("User-Agent"))
	}
	// POSTs must always carry a key so retries can't double-charge.
	if got.Get("Idempotency-Key") == "" {
		t.Error("expected an auto-generated Idempotency-Key on POST")
	}
}

func TestWithIdempotencyKeyOverridesGenerated(t *testing.T) {
	var got string
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Idempotency-Key")
		w.Write([]byte(`{}`))
	}))

	_, err := c.SMS.Send(context.Background(),
		SendSMSParams{PhoneNumber: "+2348012345678", Message: "hi"},
		WithIdempotencyKey("order-42"))
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got != "order-42" {
		t.Errorf("Idempotency-Key = %q, want order-42", got)
	}
}

func TestGetSendsNoIdempotencyKey(t *testing.T) {
	var got string
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Idempotency-Key")
		w.Write([]byte(`{"id":"otp_1"}`))
	}))
	if _, err := c.OTP.Get(context.Background(), "otp_1"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "" {
		t.Errorf("Idempotency-Key = %q, want empty on GET", got)
	}
}

func TestErrorEnvelopeMapsToSentinel(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		body     string
		sentinel error
	}{
		{"validation", 400, `{"error":{"type":"validation_error","message":"phone_number is required"}}`, ErrValidation},
		{"unauthorized", 401, `{"error":{"type":"unauthorized","message":"invalid API key"}}`, ErrUnauthorized},
		{"credits", 402, `{"error":{"type":"insufficient_credits","message":"insufficient credit balance"}}`, ErrInsufficientCredits},
		{"not found", 404, `{"error":{"type":"otp_not_found","message":"OTP not found"}}`, ErrOTPNotFound},
		{"expired", 409, `{"error":{"type":"otp_expired","message":"OTP has expired"}}`, ErrOTPExpired},
		{"rate limited", 429, `{"error":{"type":"rate_limited","message":"too many send attempts"}}`, ErrRateLimited},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				w.Write([]byte(tc.body))
			}))

			_, err := c.OTP.Send(context.Background(), SendOTPParams{PhoneNumber: "+2348012345678"})
			if !errors.Is(err, tc.sentinel) {
				t.Fatalf("err = %v, want match for %v", err, tc.sentinel)
			}
			var apiErr *Error
			if !errors.As(err, &apiErr) {
				t.Fatalf("err is not *Error: %T", err)
			}
			if apiErr.StatusCode != tc.status {
				t.Errorf("StatusCode = %d, want %d", apiErr.StatusCode, tc.status)
			}
			if apiErr.Message == "" {
				t.Error("Message is empty")
			}
		})
	}
}

func TestSpamErrorCarriesDetail(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"spam_detected","detail":{"score":0.94,"category":"phishing","reason":"credential harvesting"}}`))
	}))

	_, err := c.SMS.Send(context.Background(), SendSMSParams{PhoneNumber: "+2348012345678", Message: "click here"})
	if !errors.Is(err, ErrSpamDetected) {
		t.Fatalf("err = %v, want spam_detected", err)
	}
	var apiErr *Error
	errors.As(err, &apiErr)
	if apiErr.Detail["category"] != "phishing" {
		t.Errorf("Detail[category] = %v, want phishing", apiErr.Detail["category"])
	}
}

func TestNonJSONErrorBodyStillClassified(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("<html>gateway down</html>"))
	}))

	_, err := c.OTP.Get(context.Background(), "otp_1")
	if !errors.Is(err, ErrInternal) {
		t.Fatalf("err = %v, want internal_error", err)
	}
}

func TestRetriesOn429ThenSucceeds(t *testing.T) {
	var calls int32
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":{"type":"rate_limited","message":"slow down"}}`))
			return
		}
		w.Write([]byte(`{"id":"otp_1","status":"pending"}`))
	}), WithMaxRetries(2))

	sent, err := c.OTP.Send(context.Background(), SendOTPParams{PhoneNumber: "+2348012345678"})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if sent.ID != "otp_1" {
		t.Errorf("ID = %q", sent.ID)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("calls = %d, want 2", got)
	}
}

func TestRetriesReuseTheSameIdempotencyKey(t *testing.T) {
	var keys []string
	var calls int32
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keys = append(keys, r.Header.Get("Idempotency-Key"))
		if atomic.AddInt32(&calls, 1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write([]byte(`{"id":"otp_1"}`))
	}), WithMaxRetries(1))

	if _, err := c.OTP.Send(context.Background(), SendOTPParams{PhoneNumber: "+2348012345678"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(keys) != 2 || keys[0] != keys[1] || keys[0] == "" {
		t.Fatalf("keys = %v, want two identical non-empty keys", keys)
	}
}

func TestDoesNotRetryClientErrors(t *testing.T) {
	var calls int32
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":{"type":"invalid_phone","message":"bad number"}}`))
	}), WithMaxRetries(3))

	_, err := c.OTP.Send(context.Background(), SendOTPParams{PhoneNumber: "+234"})
	if !errors.Is(err, ErrInvalidPhone) {
		t.Fatalf("err = %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("calls = %d, want 1 — 4xx must not be retried", got)
	}
}

func TestRetryAfterIsSurfaced(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"error":{"type":"rate_limited","message":"slow down"}}`))
	}))

	_, err := c.OTP.Send(context.Background(), SendOTPParams{PhoneNumber: "+2348012345678"})
	var apiErr *Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("err is not *Error: %v", err)
	}
	if apiErr.RetryAfter != 30*time.Second {
		t.Errorf("RetryAfter = %v, want 30s", apiErr.RetryAfter)
	}
}

func TestContextCancellationIsNotRetried(t *testing.T) {
	var calls int32
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		<-r.Context().Done()
	}), WithMaxRetries(3))

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if _, err := c.OTP.Get(ctx, "otp_1"); err == nil {
		t.Fatal("expected an error")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("calls = %d, want 1", got)
	}
}

func TestBaseURLOverride(t *testing.T) {
	var path string
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		w.Write([]byte(`{}`))
	}))
	if _, err := c.SMS.Get(context.Background(), "msg_1"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if path != "/v1/sms/msg_1" {
		t.Errorf("path = %q", path)
	}
}

func TestRequestBodyEncoding(t *testing.T) {
	var body map[string]any
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&body)
		w.Write([]byte(`{}`))
	}))

	_, err := c.OTP.Send(context.Background(), SendOTPParams{
		PhoneNumber: "+2348012345678",
		CodeLength:  4,
		TTLSeconds:  300,
		Code:        "9081",
		Metadata:    map[string]any{"user_id": "u_1"},
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	if body["phone_number"] != "+2348012345678" {
		t.Errorf("phone_number = %v", body["phone_number"])
	}
	if body["code_length"] != float64(4) {
		t.Errorf("code_length = %v", body["code_length"])
	}
	if body["ttl_seconds"] != float64(300) {
		t.Errorf("ttl_seconds = %v", body["ttl_seconds"])
	}
	if body["code"] != "9081" {
		t.Errorf("code = %v", body["code"])
	}
	md, _ := body["metadata"].(map[string]any)
	if md["user_id"] != "u_1" {
		t.Errorf("metadata = %v", body["metadata"])
	}
}

func TestOmittedOptionalsAreNotSent(t *testing.T) {
	var body map[string]any
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&body)
		w.Write([]byte(`{}`))
	}))

	if _, err := c.OTP.Send(context.Background(), SendOTPParams{PhoneNumber: "+2348012345678"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	// Sending code_length:0 would be rejected as out of range; the server's
	// defaults only apply when the field is absent.
	if _, ok := body["code_length"]; ok {
		t.Error("code_length should be omitted when unset")
	}
	if _, ok := body["ttl_seconds"]; ok {
		t.Error("ttl_seconds should be omitted when unset")
	}
	if _, ok := body["code"]; ok {
		t.Error("code should be omitted when unset")
	}
}

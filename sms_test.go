package robase

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestSMSSendDecodesResponse(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v1/sms/send" {
			t.Errorf("got %s %s", r.Method, r.URL.Path)
		}
		w.Write([]byte(`{
			"id":"msg_1",
			"phone_number":"+2348012345678",
			"country_code":"NG",
			"credit_cost":1,
			"status":"pending",
			"created_at":"2026-07-22T10:00:00Z"
		}`))
	}))

	got, err := c.SMS.Send(context.Background(), SendSMSParams{
		PhoneNumber: "+2348012345678",
		Message:     "Your order #12345 has shipped.",
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got.ID != "msg_1" || got.Status != MessageStatusPending || got.CreditCost != 1 {
		t.Errorf("unexpected response: %+v", got)
	}
}

func TestSMSSendValidatesLocally(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request should not have been sent")
	}))

	if _, err := c.SMS.Send(context.Background(), SendSMSParams{Message: "hi"}); err == nil {
		t.Error("expected error for missing PhoneNumber")
	}
	if _, err := c.SMS.Send(context.Background(), SendSMSParams{PhoneNumber: "+2348012345678"}); err == nil {
		t.Error("expected error for missing Message")
	}
	long := strings.Repeat("a", MaxMessageLength+1)
	if _, err := c.SMS.Send(context.Background(), SendSMSParams{PhoneNumber: "+2348012345678", Message: long}); err == nil {
		t.Error("expected error for over-long Message")
	}
}

func TestSMSGet(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"id":"msg_1",
			"phone_number":"+2348012345678",
			"country_code":"NG",
			"credit_cost":1,
			"status":"delivered",
			"message":"Your order #12345 has shipped.",
			"metadata":{"order_id":"12345"},
			"created_at":"2026-07-22T10:00:00Z"
		}`))
	}))

	got, err := c.SMS.Get(context.Background(), "msg_1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != MessageStatusDelivered {
		t.Errorf("Status = %q", got.Status)
	}
	if got.Metadata["order_id"] != "12345" {
		t.Errorf("Metadata = %v", got.Metadata)
	}
}

func TestSMSGetNotFound(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":{"type":"sms_not_found","message":"SMS message not found"}}`))
	}))
	if _, err := c.SMS.Get(context.Background(), "missing"); !errors.Is(err, ErrSMSNotFound) {
		t.Fatalf("err = %v, want sms_not_found", err)
	}
}

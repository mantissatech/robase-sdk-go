package robase

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Webhook headers set on every delivery.
const (
	SignatureHeader = "X-Robase-Signature"
	EventHeader     = "X-Robase-Event"
)

// WebhookEvent identifies what happened.
type WebhookEvent string

const (
	EventOTPSent      WebhookEvent = "otp.sent"
	EventOTPDelivered WebhookEvent = "otp.delivered"
	EventOTPVerified  WebhookEvent = "otp.verified"
	EventOTPExpired   WebhookEvent = "otp.expired"
	EventOTPFailed    WebhookEvent = "otp.failed"

	EventSMSSent      WebhookEvent = "sms.sent"
	EventSMSDelivered WebhookEvent = "sms.delivered"
	EventSMSFailed    WebhookEvent = "sms.failed"

	EventCreditLow       WebhookEvent = "credit_balance.low"
	EventCreditExhausted WebhookEvent = "credit_balance.exhausted"
	EventCreditToppedUp  WebhookEvent = "credit_balance.topped_up"
)

// WebhookPayload is the body Robase POSTs to your endpoint.
type WebhookPayload struct {
	Event     WebhookEvent    `json:"event"`
	Timestamp time.Time       `json:"timestamp"`
	Data      json.RawMessage `json:"data"`
}

// OTPWebhookData is the Data field for otp.* events.
type OTPWebhookData struct {
	ID          string `json:"id"`
	PhoneNumber string `json:"phone_number"`
	CountryCode string `json:"country_code"`
	Status      string `json:"status"`
	Provider    string `json:"provider"`
	CreditCost  int    `json:"credit_cost"`
}

// SMSWebhookData is the Data field for sms.* events.
type SMSWebhookData struct {
	ID          string `json:"id"`
	PhoneNumber string `json:"phone_number"`
	CountryCode string `json:"country_code"`
	Message     string `json:"message"`
	Status      string `json:"status"`
	Provider    string `json:"provider"`
	CreditCost  int    `json:"credit_cost"`
}

// CreditWebhookData is the Data field for credit_balance.* events.
type CreditWebhookData struct {
	WorkspaceID string `json:"workspace_id"`
	Balance     int    `json:"balance"`
	Threshold   *int   `json:"threshold,omitempty"`
}

// OTPData decodes Data as an otp.* event payload.
func (p *WebhookPayload) OTPData() (*OTPWebhookData, error) {
	var d OTPWebhookData
	if err := json.Unmarshal(p.Data, &d); err != nil {
		return nil, fmt.Errorf("robase: decode otp webhook data: %w", err)
	}
	return &d, nil
}

// SMSData decodes Data as an sms.* event payload.
func (p *WebhookPayload) SMSData() (*SMSWebhookData, error) {
	var d SMSWebhookData
	if err := json.Unmarshal(p.Data, &d); err != nil {
		return nil, fmt.Errorf("robase: decode sms webhook data: %w", err)
	}
	return &d, nil
}

// CreditData decodes Data as a credit_balance.* event payload.
func (p *WebhookPayload) CreditData() (*CreditWebhookData, error) {
	var d CreditWebhookData
	if err := json.Unmarshal(p.Data, &d); err != nil {
		return nil, fmt.Errorf("robase: decode credit webhook data: %w", err)
	}
	return &d, nil
}

// SignWebhookPayload computes the hex-encoded HMAC-SHA256 of body under secret.
// This is what Robase sends in X-Robase-Signature; exported mainly for tests
// and for building fixtures.
func SignWebhookPayload(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyWebhookSignature reports whether signature authenticates body under
// secret, comparing in constant time. It returns ErrInvalidSignature on
// mismatch. Pass the exact bytes received — re-encoding the JSON changes the
// signature.
func VerifyWebhookSignature(body []byte, signature, secret string) error {
	expected := SignWebhookPayload(body, secret)
	if !hmac.Equal([]byte(expected), []byte(signature)) {
		return ErrInvalidSignature
	}
	return nil
}

// ParseWebhook verifies the signature and decodes the payload in one step.
// Use it directly in your HTTP handler:
//
//	body, _ := io.ReadAll(r.Body)
//	payload, err := robase.ParseWebhook(body, r.Header.Get(robase.SignatureHeader), secret)
func ParseWebhook(body []byte, signature, secret string) (*WebhookPayload, error) {
	if err := VerifyWebhookSignature(body, signature, secret); err != nil {
		return nil, err
	}
	var p WebhookPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("robase: decode webhook payload: %w", err)
	}
	return &p, nil
}

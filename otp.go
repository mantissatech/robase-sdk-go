package robase

import (
	"context"
	"errors"
	"net/url"
	"time"
)

// Status is the lifecycle state of an OTP.
type Status string

const (
	StatusPending  Status = "pending"
	StatusSent     Status = "sent"
	StatusVerified Status = "verified"
	StatusExpired  Status = "expired"
	StatusFailed   Status = "failed"
)

// OTPService groups the /v1/otp endpoints. Access it via Client.OTP.
type OTPService struct {
	client *Client
}

// SendOTPParams is the request body for OTP.Send.
type SendOTPParams struct {
	// PhoneNumber is the destination in E.164 format, e.g. "+2348012345678". Required.
	PhoneNumber string `json:"phone_number"`
	// CodeLength is the number of digits in the generated code, 4–8. Defaults to 6.
	CodeLength int `json:"code_length,omitempty"`
	// TTLSeconds is how long the code stays valid, up to 3600. Defaults to 600.
	TTLSeconds int `json:"ttl_seconds,omitempty"`
	// Code is an optional 4 to 8 digit code. Leave it empty and Robase generates one.
	// An empty value is omitted, so callers that do not set Code are unchanged.
	Code string `json:"code,omitempty"`
	// Metadata is arbitrary data stored with the OTP and echoed back by Get.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// SendOTPResponse is returned by OTP.Send.
type SendOTPResponse struct {
	// ID identifies the OTP. Pass it to Verify and Get.
	ID string `json:"id"`
	// PhoneNumber is the destination the code was sent to.
	PhoneNumber string `json:"phone_number"`
	// CountryCode is the ISO 3166-1 alpha-2 code derived from the number.
	CountryCode string `json:"country_code"`
	// CreditCost is the number of credits the send consumed.
	CreditCost int `json:"credit_cost"`
	// Status is "pending" on accept; delivery happens asynchronously.
	Status Status `json:"status"`
	// CodeLength is the number of digits in the generated code.
	CodeLength int `json:"code_length"`
	// ExpiresAt is when the code stops being verifiable.
	ExpiresAt time.Time `json:"expires_at"`
	// CreatedAt is when the OTP was created.
	CreatedAt time.Time `json:"created_at"`
}

// VerifyOTPParams is the request body for OTP.Verify.
type VerifyOTPParams struct {
	// OTPID is the id returned by Send. Required.
	OTPID string `json:"otp_id"`
	// Code is the code the user entered. Required.
	Code string `json:"code"`
}

// VerifyOTPResponse is returned by OTP.Verify.
//
// A wrong-but-still-usable code is not an error: the call succeeds with
// Valid false and AttemptsRemaining set. Terminal states — expired, already
// verified, attempts exhausted — come back as *Error instead.
type VerifyOTPResponse struct {
	// Valid reports whether the submitted code matched.
	Valid bool `json:"valid"`
	// Status is the OTP's state after this attempt.
	Status Status `json:"status"`
	// AttemptsUsed counts verification attempts made so far, including this one.
	AttemptsUsed int `json:"attempts_used"`
	// AttemptsRemaining is how many attempts are left. Only sent when Valid is false.
	AttemptsRemaining *int `json:"attempts_remaining,omitempty"`
}

// OTP is the full record returned by OTP.Get. The code itself is never returned.
type OTP struct {
	ID            string         `json:"id"`
	WorkspaceID   string         `json:"workspace_id"`
	PhoneNumber   string         `json:"phone_number"`
	CountryCode   string         `json:"country_code"`
	CreditCost    int            `json:"credit_cost"`
	Provider      string         `json:"provider,omitempty"`
	ProviderMsgID string         `json:"provider_msg_id,omitempty"`
	Status        Status         `json:"status"`
	CodeLength    int            `json:"code_length"`
	TTLSeconds    int            `json:"ttl_seconds"`
	AttemptCount  int            `json:"attempt_count"`
	MaxAttempts   int            `json:"max_attempts"`
	SentAt        *time.Time     `json:"sent_at,omitempty"`
	DeliveredAt   *time.Time     `json:"delivered_at,omitempty"`
	VerifiedAt    *time.Time     `json:"verified_at,omitempty"`
	ExpiredAt     time.Time      `json:"expired_at"`
	Metadata      map[string]any `json:"metadata,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
}

// Send generates a code and delivers it by SMS. The credit charge is applied
// before this returns; delivery itself is asynchronous, so a "pending" status
// is the normal success case.
func (s *OTPService) Send(ctx context.Context, params SendOTPParams, opts ...RequestOption) (*SendOTPResponse, error) {
	if params.PhoneNumber == "" {
		return nil, errors.New("robase: PhoneNumber is required")
	}
	var out SendOTPResponse
	if err := s.client.do(ctx, "POST", "/v1/otp/send", params, &out, opts...); err != nil {
		return nil, err
	}
	return &out, nil
}

// Verify checks a code against a previously sent OTP using a constant-time
// comparison. See VerifyOTPResponse for how wrong codes differ from errors.
func (s *OTPService) Verify(ctx context.Context, params VerifyOTPParams, opts ...RequestOption) (*VerifyOTPResponse, error) {
	if params.OTPID == "" {
		return nil, errors.New("robase: OTPID is required")
	}
	if params.Code == "" {
		return nil, errors.New("robase: Code is required")
	}
	var out VerifyOTPResponse
	if err := s.client.do(ctx, "POST", "/v1/otp/verify", params, &out, opts...); err != nil {
		return nil, err
	}
	return &out, nil
}

// Get retrieves the current state of an OTP.
func (s *OTPService) Get(ctx context.Context, id string, opts ...RequestOption) (*OTP, error) {
	if id == "" {
		return nil, errors.New("robase: id is required")
	}
	var out OTP
	if err := s.client.do(ctx, "GET", "/v1/otp/"+url.PathEscape(id), nil, &out, opts...); err != nil {
		return nil, err
	}
	return &out, nil
}

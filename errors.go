package robase

import (
	"errors"
	"fmt"
	"time"
)

// Error is returned for every non-2xx API response. The API reports failures as
// {"error":{"type":"...","message":"..."}}, and Type is the stable machine-readable
// half of that pair — match on it with errors.Is and the sentinels below rather
// than on Message, which is prose and may change.
type Error struct {
	// StatusCode is the HTTP status of the response.
	StatusCode int
	// Type is the API's error identifier, e.g. "insufficient_credits".
	Type string
	// Message is the human-readable description.
	Message string
	// RetryAfter is the Retry-After header, when the server sent one.
	RetryAfter time.Duration
	// Detail carries any extra fields the endpoint attached to the error.
	// The anti-spam block on POST /v1/sms/send populates it with score,
	// category and reason.
	Detail map[string]any
	// Body is the raw response body, useful when the payload wasn't the
	// standard error envelope.
	Body []byte
}

func (e *Error) Error() string {
	if e.Type == "" {
		return fmt.Sprintf("robase: HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("robase: %s (%s, HTTP %d)", e.Message, e.Type, e.StatusCode)
}

// Is lets callers write errors.Is(err, robase.ErrRateLimited). Sentinels carry
// only a Type, so comparison is on Type alone.
func (e *Error) Is(target error) bool {
	var t *Error
	if !errors.As(target, &t) {
		return false
	}
	return t.Type != "" && t.Type == e.Type
}

// Sentinel errors for every error type the API emits. Use them with errors.Is:
//
//	if errors.Is(err, robase.ErrInsufficientCredits) { ... }
var (
	// ErrUnauthorized — the API key is missing, malformed, or unknown (401).
	ErrUnauthorized = &Error{Type: "unauthorized"}
	// ErrValidation — the request body failed validation (400).
	ErrValidation = &Error{Type: "validation_error"}
	// ErrInvalidPhone — phone_number was not valid E.164 (400).
	ErrInvalidPhone = &Error{Type: "invalid_phone"}
	// ErrCountryNotSupported — no SMS route exists for the destination (400).
	ErrCountryNotSupported = &Error{Type: "country_not_supported"}
	// ErrInsufficientCredits — the workspace balance is below the send cost (402).
	ErrInsufficientCredits = &Error{Type: "insufficient_credits"}
	// ErrSpamDetected — anti-spam blocked the message (403). See Error.Detail.
	ErrSpamDetected = &Error{Type: "spam_detected"}
	// ErrOTPNotFound — no OTP with that id (404).
	ErrOTPNotFound = &Error{Type: "otp_not_found"}
	// ErrSMSNotFound — no SMS message with that id (404).
	ErrSMSNotFound = &Error{Type: "sms_not_found"}
	// ErrOTPExpired — the OTP's TTL elapsed before verification (409).
	ErrOTPExpired = &Error{Type: "otp_expired"}
	// ErrOTPAlreadyVerified — the OTP was already consumed (409).
	ErrOTPAlreadyVerified = &Error{Type: "otp_already_verified"}
	// ErrMaxAttempts — too many wrong codes were submitted (409).
	ErrMaxAttempts = &Error{Type: "max_attempts_exceeded"}
	// ErrRateLimited — a per-phone or per-key rate limit tripped (429).
	ErrRateLimited = &Error{Type: "rate_limited"}
	// ErrInternal — the API failed unexpectedly (5xx).
	ErrInternal = &Error{Type: "internal_error"}
)

// ErrInvalidSignature is returned by VerifyWebhookSignature and ParseWebhook when
// the X-Robase-Signature header does not match the payload.
var ErrInvalidSignature = errors.New("robase: invalid webhook signature")

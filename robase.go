// Package robase is the official Go client for the Robase SMS OTP API.
//
//	client, err := robase.New("robe_...")
//	if err != nil {
//		return err
//	}
//	sent, err := client.OTP.Send(ctx, robase.SendOTPParams{PhoneNumber: "+2348012345678"})
//
// Every API failure is returned as *Error; match on it with errors.Is and the
// sentinels in errors.go.
package robase

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Version is the SDK version, reported in the User-Agent.
const Version = "1.0.0"

// DefaultBaseURL is the production API endpoint.
const DefaultBaseURL = "https://api.robase.dev"

const (
	defaultTimeout    = 30 * time.Second
	defaultMaxRetries = 2
	maxRetryBackoff   = 8 * time.Second
)

// Client is a Robase API client. It is safe for concurrent use.
type Client struct {
	// OTP groups the /v1/otp endpoints.
	OTP *OTPService
	// SMS groups the /v1/sms endpoints.
	SMS *SMSService

	apiKey     string
	baseURL    string
	httpClient *http.Client
	maxRetries int
	userAgent  string
}

// Option customises a Client. Pass options to New.
type Option func(*Client)

// WithBaseURL points the client at a different API host — useful for local
// development against http://localhost:8080.
func WithBaseURL(raw string) Option {
	return func(c *Client) { c.baseURL = strings.TrimRight(raw, "/") }
}

// WithHTTPClient supplies the *http.Client used for every request. Set this to
// control proxies, TLS, or connection pooling. It overrides WithTimeout.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.httpClient = hc }
}

// WithTimeout sets the per-request timeout on the default HTTP client.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.httpClient.Timeout = d }
}

// WithMaxRetries caps how many times a failed request is retried. Retries apply
// to network errors, 429s and 5xxs; POSTs carry an Idempotency-Key so a retry
// cannot double-charge. Pass 0 to disable.
func WithMaxRetries(n int) Option {
	return func(c *Client) {
		if n >= 0 {
			c.maxRetries = n
		}
	}
}

// WithUserAgent overrides the User-Agent header.
func WithUserAgent(ua string) Option {
	return func(c *Client) { c.userAgent = ua }
}

// New builds a client for the given API key. Keys are issued in the dashboard
// and start with "robe_".
func New(apiKey string, opts ...Option) (*Client, error) {
	if apiKey == "" {
		return nil, errors.New("robase: api key is required")
	}
	if !strings.HasPrefix(apiKey, "robe_") {
		return nil, errors.New(`robase: api key must start with "robe_"`)
	}

	c := &Client{
		apiKey:     apiKey,
		baseURL:    DefaultBaseURL,
		httpClient: &http.Client{Timeout: defaultTimeout},
		maxRetries: defaultMaxRetries,
		userAgent:  "robase-go/" + Version,
	}
	for _, opt := range opts {
		opt(c)
	}
	if _, err := url.Parse(c.baseURL); err != nil {
		return nil, fmt.Errorf("robase: invalid base url: %w", err)
	}

	c.OTP = &OTPService{client: c}
	c.SMS = &SMSService{client: c}
	return c, nil
}

// RequestOption tweaks a single API call.
type RequestOption func(*requestConfig)

type requestConfig struct {
	idempotencyKey string
	headers        map[string]string
}

// WithIdempotencyKey pins the Idempotency-Key for one request. Replaying the
// same key within 24 hours returns the original response instead of sending a
// second message. Send calls generate a random key when none is given, so this
// is only needed when you want to reuse a key across processes or retries of
// your own.
func WithIdempotencyKey(key string) RequestOption {
	return func(rc *requestConfig) { rc.idempotencyKey = key }
}

// WithHeader attaches an extra header to one request.
func WithHeader(name, value string) RequestOption {
	return func(rc *requestConfig) {
		if rc.headers == nil {
			rc.headers = map[string]string{}
		}
		rc.headers[name] = value
	}
}

// do executes an API call, decoding a successful body into out. body may be nil
// for GETs. It retries transient failures up to the configured limit.
func (c *Client) do(ctx context.Context, method, path string, body, out any, opts ...RequestOption) error {
	cfg := &requestConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			return fmt.Errorf("robase: encode request: %w", err)
		}
	}

	// A POST that times out mid-flight may still have been charged. Giving every
	// POST an idempotency key makes the retry below safe: the server replays the
	// original response rather than sending a second message.
	if method == http.MethodPost && cfg.idempotencyKey == "" {
		cfg.idempotencyKey = newUUID()
	}

	var lastErr error
	for attempt := 0; ; attempt++ {
		var reader io.Reader
		if payload != nil {
			reader = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
		if err != nil {
			return fmt.Errorf("robase: build request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", c.userAgent)
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if cfg.idempotencyKey != "" {
			req.Header.Set("Idempotency-Key", cfg.idempotencyKey)
		}
		for name, value := range cfg.headers {
			req.Header.Set(name, value)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			// Context cancellation is the caller's decision, not a transient fault.
			if ctx.Err() != nil {
				return err
			}
			lastErr = fmt.Errorf("robase: request failed: %w", err)
			if attempt >= c.maxRetries {
				return lastErr
			}
			if waitErr := sleep(ctx, backoff(attempt, 0)); waitErr != nil {
				return waitErr
			}
			continue
		}

		respBody, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			lastErr = fmt.Errorf("robase: read response: %w", readErr)
			if attempt >= c.maxRetries {
				return lastErr
			}
			if waitErr := sleep(ctx, backoff(attempt, 0)); waitErr != nil {
				return waitErr
			}
			continue
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if out == nil || len(respBody) == 0 {
				return nil
			}
			if err := json.Unmarshal(respBody, out); err != nil {
				return fmt.Errorf("robase: decode response: %w", err)
			}
			return nil
		}

		apiErr := parseError(resp, respBody)
		if attempt < c.maxRetries && retryable(resp.StatusCode) {
			lastErr = apiErr
			if waitErr := sleep(ctx, backoff(attempt, apiErr.RetryAfter)); waitErr != nil {
				return waitErr
			}
			continue
		}
		return apiErr
	}
}

func retryable(status int) bool {
	return status == http.StatusTooManyRequests || status >= 500
}

// backoff returns the delay before the next attempt: the server's Retry-After
// when it sent one, otherwise exponential growth with full jitter.
func backoff(attempt int, retryAfter time.Duration) time.Duration {
	if retryAfter > 0 {
		if retryAfter > maxRetryBackoff {
			return maxRetryBackoff
		}
		return retryAfter
	}
	d := time.Duration(1<<attempt) * 500 * time.Millisecond
	if d > maxRetryBackoff {
		d = maxRetryBackoff
	}
	// Full jitter spreads out retries from callers that failed simultaneously.
	n, err := rand.Int(rand.Reader, big.NewInt(int64(d)))
	if err != nil {
		return d
	}
	return time.Duration(n.Int64())
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

type errorEnvelope struct {
	Error json.RawMessage `json:"error"`
	// The anti-spam block sits alongside "error" rather than inside it.
	Detail map[string]any `json:"detail,omitempty"`
}

type errorDetail struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

func parseError(resp *http.Response, body []byte) *Error {
	apiErr := &Error{StatusCode: resp.StatusCode, Body: body}

	if raw := resp.Header.Get("Retry-After"); raw != "" {
		if secs, err := strconv.Atoi(raw); err == nil && secs >= 0 {
			apiErr.RetryAfter = time.Duration(secs) * time.Second
		}
	}

	var env errorEnvelope
	if err := json.Unmarshal(body, &env); err != nil || len(env.Error) == 0 {
		apiErr.Type = fallbackType(resp.StatusCode)
		apiErr.Message = strings.TrimSpace(string(body))
		if apiErr.Message == "" {
			apiErr.Message = http.StatusText(resp.StatusCode)
		}
		return apiErr
	}
	apiErr.Detail = env.Detail

	// "error" is an object on most endpoints but a bare string on the
	// anti-spam block, which puts its context in a sibling "detail" field.
	var detail errorDetail
	if err := json.Unmarshal(env.Error, &detail); err == nil && detail.Type != "" {
		apiErr.Type = detail.Type
		apiErr.Message = detail.Message
		return apiErr
	}
	var asString string
	if err := json.Unmarshal(env.Error, &asString); err == nil && asString != "" {
		apiErr.Type = asString
		apiErr.Message = asString
		return apiErr
	}

	apiErr.Type = fallbackType(resp.StatusCode)
	apiErr.Message = http.StatusText(resp.StatusCode)
	return apiErr
}

func fallbackType(status int) string {
	switch {
	case status == http.StatusUnauthorized:
		return "unauthorized"
	case status == http.StatusPaymentRequired:
		return "insufficient_credits"
	case status == http.StatusTooManyRequests:
		return "rate_limited"
	case status >= 500:
		return "internal_error"
	default:
		return "api_error"
	}
}

// newUUID returns a random RFC 4122 v4 UUID.
func newUUID() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// crypto/rand failing is unrecoverable; a timestamp key is still unique
		// enough to keep the idempotency guarantee useful.
		return fmt.Sprintf("robase-%d", time.Now().UnixNano())
	}
	buf[6] = (buf[6] & 0x0f) | 0x40
	buf[8] = (buf[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:])
}

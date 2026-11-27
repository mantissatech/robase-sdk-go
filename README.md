# Robase Go SDK

Official Go client for the [Robase](https://robase.dev) SMS OTP and transactional SMS API.

No third-party dependencies — standard library only.

## Install

```bash
go get github.com/mantissatech/robase-sdk-go
```

```go
import robase "github.com/mantissatech/robase-sdk-go"
```

## Quick start

```go
client, err := robase.New(os.Getenv("ROBASE_API_KEY"))
if err != nil {
    log.Fatal(err)
}

sent, err := client.OTP.Send(ctx, robase.SendOTPParams{
    PhoneNumber: "+2348012345678",
})
if err != nil {
    log.Fatal(err)
}
fmt.Println(sent.ID, sent.ExpiresAt)

// ...after the user types in the code they received:
result, err := client.OTP.Verify(ctx, robase.VerifyOTPParams{
    OTPID: sent.ID,
    Code:  "123456",
})
if err != nil {
    log.Fatal(err)
}
if result.Valid {
    fmt.Println("verified")
}
```

## Client options

```go
client, err := robase.New(apiKey,
    robase.WithBaseURL("http://localhost:8080"), // default: https://api.robase.dev
    robase.WithTimeout(10*time.Second),          // default: 30s
    robase.WithMaxRetries(3),                    // default: 2
    robase.WithHTTPClient(myClient),             // full control over transport
    robase.WithUserAgent("acme-billing/2.1"),
)
```

`Client` is safe for concurrent use — build one and share it.

## API

### OTP

| Method | Endpoint |
|---|---|
| `client.OTP.Send(ctx, params, opts...)` | `POST /v1/otp/send` |
| `client.OTP.Verify(ctx, params, opts...)` | `POST /v1/otp/verify` |
| `client.OTP.Get(ctx, id, opts...)` | `GET /v1/otp/{id}` |

```go
sent, err := client.OTP.Send(ctx, robase.SendOTPParams{
    PhoneNumber: "+2348012345678", // required, E.164
    Code:        "908172",          // optional, 4 to 8 digits; omit to generate
    CodeLength:  6,                // optional, 4–8, defaults to 6
    TTLSeconds:  600,              // optional, ≤3600, defaults to 600
    Metadata:    map[string]any{"user_id": "u_123"},
})
```

A wrong-but-not-yet-exhausted code is **not** an error — `Verify` returns
successfully with `Valid: false` and `AttemptsRemaining` set:

```go
result, err := client.OTP.Verify(ctx, robase.VerifyOTPParams{OTPID: id, Code: code})
switch {
case err == nil && result.Valid:
    // success
case err == nil:
    fmt.Printf("wrong code, %d attempts left\n", *result.AttemptsRemaining)
case errors.Is(err, robase.ErrOTPExpired):
    // the code timed out — send a new one
case errors.Is(err, robase.ErrMaxAttempts):
    // too many wrong guesses; this OTP is dead
default:
    return err
}
```

### SMS

| Method | Endpoint |
|---|---|
| `client.SMS.Send(ctx, params, opts...)` | `POST /v1/sms/send` |
| `client.SMS.Get(ctx, id, opts...)` | `GET /v1/sms/{id}` |

```go
msg, err := client.SMS.Send(ctx, robase.SendSMSParams{
    PhoneNumber: "+2348012345678",
    Message:     "Your order #12345 has shipped.", // ≤918 characters
    Metadata:    map[string]any{"order_id": "12345"},
})
```

`Send` returns as soon as the message is queued and charged — `msg.Status` is
always `pending`. Subscribe to the `sms.delivered` / `sms.failed` webhooks, or
poll `SMS.Get`, to learn the outcome.

## Errors

Every non-2xx response comes back as `*robase.Error`. Match on the sentinels
rather than on message text:

```go
if errors.Is(err, robase.ErrInsufficientCredits) {
    // top up and retry
}

var apiErr *robase.Error
if errors.As(err, &apiErr) {
    log.Printf("%s: %s (HTTP %d)", apiErr.Type, apiErr.Message, apiErr.StatusCode)
}
```

| Sentinel | HTTP | Meaning |
|---|---|---|
| `ErrValidation` | 400 | Request body failed validation |
| `ErrInvalidPhone` | 400 | `phone_number` isn't valid E.164 |
| `ErrCountryNotSupported` | 400 | No route to that destination |
| `ErrUnauthorized` | 401 | Missing or unknown API key |
| `ErrInsufficientCredits` | 402 | Balance below the send cost |
| `ErrSpamDetected` | 403 | Anti-spam blocked the message |
| `ErrOTPNotFound` / `ErrSMSNotFound` | 404 | No such record |
| `ErrOTPExpired` | 409 | OTP TTL elapsed |
| `ErrOTPAlreadyVerified` | 409 | OTP already consumed |
| `ErrMaxAttempts` | 409 | Too many wrong codes |
| `ErrRateLimited` | 429 | Rate limit tripped; see `Error.RetryAfter` |
| `ErrInternal` | 5xx | Server-side failure |

When anti-spam blocks a message, `Error.Detail` carries `score`, `category` and
`reason`.

## Retries and idempotency

Network errors, `429`s and `5xx`s are retried with exponential backoff and full
jitter, honouring `Retry-After` when the server sends it. Every `POST` carries an
auto-generated `Idempotency-Key`, and a retry reuses the same key — so a retried
send replays the original response instead of charging you twice.

To reuse a key across processes (say, keyed on your own order ID), pass it
explicitly:

```go
client.SMS.Send(ctx, params, robase.WithIdempotencyKey("order-"+orderID))
```

Keys are honoured for 24 hours.

## Webhooks

Robase signs every delivery with `X-Robase-Signature` — a hex HMAC-SHA256 of the
raw body under your webhook secret.

```go
func handler(w http.ResponseWriter, r *http.Request) {
    body, err := io.ReadAll(r.Body)
    if err != nil {
        http.Error(w, "bad request", http.StatusBadRequest)
        return
    }

    payload, err := robase.ParseWebhook(body, r.Header.Get(robase.SignatureHeader), secret)
    if err != nil {
        http.Error(w, "bad signature", http.StatusUnauthorized)
        return
    }

    switch payload.Event {
    case robase.EventOTPVerified:
        data, _ := payload.OTPData()
        log.Println("verified", data.ID)
    case robase.EventSMSDelivered:
        data, _ := payload.SMSData()
        log.Println("delivered", data.ID)
    case robase.EventCreditLow:
        data, _ := payload.CreditData()
        log.Println("balance low", data.Balance)
    }

    w.WriteHeader(http.StatusOK)
}
```

Verify against the **raw** bytes — re-encoding the JSON changes the signature.

Events: `otp.sent`, `otp.delivered`, `otp.verified`, `otp.expired`, `otp.failed`,
`sms.sent`, `sms.delivered`, `sms.failed`, `credit_balance.low`,
`credit_balance.exhausted`, `credit_balance.topped_up`.

## Development

```bash
go test ./...
go vet ./...
```

## License

MIT

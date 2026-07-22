package robase

import (
	"context"
	"errors"
	"net/url"
	"time"
)

// MessageStatus is the delivery state of a transactional SMS.
type MessageStatus string

const (
	MessageStatusPending   MessageStatus = "pending"
	MessageStatusSent      MessageStatus = "sent"
	MessageStatusDelivered MessageStatus = "delivered"
	MessageStatusFailed    MessageStatus = "failed"
)

// MaxMessageLength is the longest message body the API accepts.
const MaxMessageLength = 918

// SMSService groups the /v1/sms endpoints. Access it via Client.SMS.
type SMSService struct {
	client *Client
}

// SendSMSParams is the request body for SMS.Send.
type SendSMSParams struct {
	// PhoneNumber is the destination in E.164 format. Required.
	PhoneNumber string `json:"phone_number"`
	// Message is the body, at most MaxMessageLength characters. Required.
	Message string `json:"message"`
	// Metadata is arbitrary data stored with the message and echoed back by Get.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// SendSMSResponse is returned by SMS.Send.
type SendSMSResponse struct {
	// ID identifies the message. Pass it to Get.
	ID string `json:"id"`
	// PhoneNumber is the destination.
	PhoneNumber string `json:"phone_number"`
	// CountryCode is the ISO 3166-1 alpha-2 code derived from the number.
	CountryCode string `json:"country_code"`
	// CreditCost is the number of credits the send consumed.
	CreditCost int `json:"credit_cost"`
	// Status is always "pending" here; it transitions asynchronously.
	Status MessageStatus `json:"status"`
	// CreatedAt is when the message was accepted.
	CreatedAt time.Time `json:"created_at"`
}

// Message is the full record returned by SMS.Get.
type Message struct {
	ID          string         `json:"id"`
	PhoneNumber string         `json:"phone_number"`
	CountryCode string         `json:"country_code"`
	Message     string         `json:"message"`
	CreditCost  int            `json:"credit_cost"`
	Status      MessageStatus  `json:"status"`
	Metadata    map[string]any `json:"metadata,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
}

// Send queues a transactional SMS. It uses the same routing, billing and
// provider failover as OTPs. Delivery is asynchronous — subscribe to the
// sms.delivered and sms.failed webhooks to learn the outcome.
//
// If anti-spam is enabled for the workspace and blocks the message, the returned
// error matches ErrSpamDetected and its Detail holds the score, category and reason.
func (s *SMSService) Send(ctx context.Context, params SendSMSParams, opts ...RequestOption) (*SendSMSResponse, error) {
	if params.PhoneNumber == "" {
		return nil, errors.New("robase: PhoneNumber is required")
	}
	if params.Message == "" {
		return nil, errors.New("robase: Message is required")
	}
	if len(params.Message) > MaxMessageLength {
		return nil, errors.New("robase: Message must be at most 918 characters")
	}
	var out SendSMSResponse
	if err := s.client.do(ctx, "POST", "/v1/sms/send", params, &out, opts...); err != nil {
		return nil, err
	}
	return &out, nil
}

// Get retrieves the current state of a transactional SMS.
func (s *SMSService) Get(ctx context.Context, id string, opts ...RequestOption) (*Message, error) {
	if id == "" {
		return nil, errors.New("robase: id is required")
	}
	var out Message
	if err := s.client.do(ctx, "GET", "/v1/sms/"+url.PathEscape(id), nil, &out, opts...); err != nil {
		return nil, err
	}
	return &out, nil
}

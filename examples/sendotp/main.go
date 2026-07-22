// Command sendotp sends an OTP and then verifies a code read from stdin.
//
//	ROBASE_API_KEY=robe_... go run ./examples/sendotp +2348012345678
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	robase "github.com/mantissatech/robase-sdk-go"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: sendotp <phone-number-in-e164>")
	}
	phone := os.Args[1]

	apiKey := os.Getenv("ROBASE_API_KEY")
	if apiKey == "" {
		log.Fatal("ROBASE_API_KEY is not set")
	}

	client, err := robase.New(apiKey)
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	sent, err := client.OTP.Send(ctx, robase.SendOTPParams{
		PhoneNumber: phone,
		CodeLength:  6,
		TTLSeconds:  300,
	})
	if err != nil {
		switch {
		case errors.Is(err, robase.ErrInsufficientCredits):
			log.Fatal("out of credits — top up at https://robase.dev")
		case errors.Is(err, robase.ErrInvalidPhone):
			log.Fatalf("%q is not a valid E.164 number", phone)
		default:
			log.Fatal(err)
		}
	}

	fmt.Printf("sent %s to %s (%d credit(s)), expires %s\n",
		sent.ID, sent.PhoneNumber, sent.CreditCost, sent.ExpiresAt.Format(time.Kitchen))

	fmt.Print("enter the code: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		log.Fatal(err)
	}

	result, err := client.OTP.Verify(ctx, robase.VerifyOTPParams{
		OTPID: sent.ID,
		Code:  strings.TrimSpace(line),
	})
	switch {
	case errors.Is(err, robase.ErrOTPExpired):
		log.Fatal("that code expired — send a new one")
	case errors.Is(err, robase.ErrMaxAttempts):
		log.Fatal("too many attempts")
	case err != nil:
		log.Fatal(err)
	case result.Valid:
		fmt.Println("verified ✓")
	default:
		fmt.Printf("wrong code — %d attempt(s) left\n", *result.AttemptsRemaining)
	}
}

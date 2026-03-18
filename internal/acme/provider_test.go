package acme

import (
	"testing"
	"time"
)

func TestProvider_Present_SendsChallenge(t *testing.T) {
	p := NewProvider(2*time.Hour, 2*time.Minute)

	// Call Present directly (bypassing lego) to test channel mechanics.
	// We use a known domain/keyAuth pair. The actual FQDN and value
	// depend on dns01.GetChallengeInfo, but we can verify the channel receives data.
	go func() {
		err := p.Present("example.com", "token123", "keyAuth123")
		if err != nil {
			t.Errorf("Present returned error: %v", err)
		}
	}()

	select {
	case data := <-p.Challenge():
		if data.FQDN == "" {
			t.Error("FQDN should not be empty")
		}
		if data.Value == "" {
			t.Error("Value should not be empty")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for challenge data")
	}
}

func TestProvider_Timeout_ReturnsConfiguredValues(t *testing.T) {
	timeout := 3 * time.Hour
	interval := 5 * time.Minute
	p := NewProvider(timeout, interval)

	gotTimeout, gotInterval := p.Timeout()
	if gotTimeout != timeout {
		t.Errorf("timeout = %v, want %v", gotTimeout, timeout)
	}
	if gotInterval != interval {
		t.Errorf("interval = %v, want %v", gotInterval, interval)
	}
}

func TestProvider_CleanUp_NoOp(t *testing.T) {
	p := NewProvider(2*time.Hour, 2*time.Minute)
	if err := p.CleanUp("example.com", "token", "keyAuth"); err != nil {
		t.Errorf("CleanUp returned error: %v", err)
	}
}

func TestProvider_Challenge_Buffered(t *testing.T) {
	p := NewProvider(2*time.Hour, 2*time.Minute)

	// Sending to the channel should not block (buffered size 1).
	p.challenges <- ChallengeData{FQDN: "test", Value: "test"}

	select {
	case <-p.Challenge():
		// OK
	default:
		t.Error("channel should have data")
	}
}

package acme

import (
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
)

// ChallengeData holds the DNS-01 challenge info sent back through the channel.
type ChallengeData struct {
	FQDN  string
	Value string
}

// Provider implements challenge.Provider for DNS-01.
// Each cert request gets its own Provider instance.
type Provider struct {
	challenges chan ChallengeData
	timeout    time.Duration
	interval   time.Duration
}

// NewProvider creates a provider with a buffered channel of size 1.
func NewProvider(timeout, interval time.Duration) *Provider {
	return &Provider{
		challenges: make(chan ChallengeData, 1),
		timeout:    timeout,
		interval:   interval,
	}
}

// Present is called by lego when it has a DNS-01 challenge.
// Instead of creating a DNS record, we send the challenge data
// back through the channel so the HTTP handler can return it.
func (p *Provider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	p.challenges <- ChallengeData{
		FQDN:  info.EffectiveFQDN,
		Value: info.Value,
	}
	return nil
}

// CleanUp is a no-op — the caller manages their own DNS records.
func (p *Provider) CleanUp(domain, token, keyAuth string) error {
	return nil
}

// Timeout returns the propagation timeout and polling interval.
func (p *Provider) Timeout() (time.Duration, time.Duration) {
	return p.timeout, p.interval
}

// Challenge returns the channel that the HTTP handler reads from.
func (p *Provider) Challenge() <-chan ChallengeData {
	return p.challenges
}

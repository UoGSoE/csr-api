package acme

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"

	"github.com/billyraycyrus/csr-api/internal/store"
)

// CertObtainer abstracts cert obtainment for testability.
type CertObtainer interface {
	ObtainCert(ctx context.Context, csrPEM []byte, hostname string) (*ChallengeData, error)
}

type Client struct {
	legoClient *lego.Client
	certsDir   string
	store      *store.Store
	timeout    time.Duration
	interval   time.Duration
	dnsServers []string
	logger     *slog.Logger
}

type ClientConfig struct {
	AcmeDirectory string
	Account       *Account
	CertsDir      string
	Store         *store.Store
	DNSServers    []string
	PollTimeout   time.Duration
	PollInterval  time.Duration
	Logger        *slog.Logger
}

func NewClient(cfg ClientConfig) (*Client, error) {
	legoCfg := lego.NewConfig(cfg.Account)
	legoCfg.CADirURL = cfg.AcmeDirectory

	legoClient, err := lego.NewClient(legoCfg)
	if err != nil {
		return nil, fmt.Errorf("create lego client: %w", err)
	}

	if cfg.Account.Registration == nil {
		reg, err := legoClient.Registration.Register(registration.RegisterOptions{
			TermsOfServiceAgreed: true,
		})
		if err != nil {
			return nil, fmt.Errorf("register account: %w", err)
		}
		cfg.Account.Registration = reg
	}

	return &Client{
		legoClient: legoClient,
		certsDir:   cfg.CertsDir,
		store:      cfg.Store,
		timeout:    cfg.PollTimeout,
		interval:   cfg.PollInterval,
		dnsServers: cfg.DNSServers,
		logger:     cfg.Logger,
	}, nil
}

func (c *Client) ObtainCert(ctx context.Context, csrPEM []byte, hostname string) (*ChallengeData, error) {
	csr, err := parseCSR(csrPEM)
	if err != nil {
		return nil, fmt.Errorf("invalid CSR: %w", err)
	}

	provider := NewProvider(c.timeout, c.interval)

	var opts []dns01.ChallengeOption
	if len(c.dnsServers) > 0 {
		opts = append(opts, dns01.AddRecursiveNameservers(c.dnsServers))
	}
	if err := c.legoClient.Challenge.SetDNS01Provider(provider, opts...); err != nil {
		return nil, fmt.Errorf("set DNS provider: %w", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	id, err := c.store.InsertCertRequest(&store.CertRequest{
		Hostname:  hostname,
		CSRPEM:    string(csrPEM),
		TXTFQDN:   "",
		TXTValue:  "",
		Status:    "pending_dns",
		CreatedAt: now,
	})
	if err != nil {
		return nil, fmt.Errorf("insert cert request: %w", err)
	}

	// Start the ACME flow in a background goroutine.
	// lego will call provider.Present() which sends challenge data on the channel.
	go func() {
		resource, err := c.legoClient.Certificate.ObtainForCSR(certificate.ObtainForCSRRequest{
			CSR: csr,
		})
		if err != nil {
			errMsg := err.Error()
			c.store.UpdateStatus(id, "failed", &errMsg)
			c.logger.Error("obtain cert failed", "hostname", hostname, "err", err)
			return
		}

		certPath := filepath.Join(c.certsDir, hostname+".pem")
		if err := os.WriteFile(certPath, resource.Certificate, 0o644); err != nil {
			errMsg := err.Error()
			c.store.UpdateStatus(id, "failed", &errMsg)
			c.logger.Error("write cert failed", "hostname", hostname, "err", err)
			return
		}

		c.store.MarkCompleted(id)
		c.logger.Info("cert issued", "hostname", hostname, "path", certPath)
	}()

	// Wait for the challenge data from Present().
	select {
	case data := <-provider.Challenge():
		c.store.UpdateChallengeData(id, data.FQDN, data.Value)
		return &data, nil
	case <-time.After(30 * time.Second):
		errMsg := "timed out waiting for ACME challenge"
		c.store.UpdateStatus(id, "failed", &errMsg)
		return nil, fmt.Errorf(errMsg)
	case <-ctx.Done():
		errMsg := "request cancelled"
		c.store.UpdateStatus(id, "failed", &errMsg)
		return nil, ctx.Err()
	}
}

func parseCSR(csrPEM []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	if csr.Subject.CommonName == "" && len(csr.DNSNames) == 0 {
		return nil, fmt.Errorf("CSR has no CN and no SANs")
	}
	return csr, nil
}

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/billyraycyrus/csr-api/internal/auth"
	"github.com/billyraycyrus/csr-api/internal/server"
	"github.com/billyraycyrus/csr-api/internal/store"
)

type CLI struct {
	Serve       ServeCmd       `cmd:"" help:"Start the API server."`
	CreateToken CreateTokenCmd `cmd:"" help:"Generate a new bearer token."`
	RevokeToken RevokeTokenCmd `cmd:"" help:"Revoke a bearer token by prefix."`
	ListTokens  ListTokensCmd  `cmd:"" help:"List all tokens."`

	DBPath string `help:"SQLite database path." default:"data/certs.db" env:"CSR_API_DB_PATH"`
}

type ListTokensCmd struct{}

type ServeCmd struct {
	Addr    string `help:"Listen address." default:":8443" env:"CSR_API_ADDR"`
	CSRsDir string `help:"Directory for submitted CSRs." default:"data/csrs" env:"CSR_API_CSRS_DIR"`
}

type CreateTokenCmd struct {
	ForWhom string `arg:"" help:"Description of who this token is for."`
}

type RevokeTokenCmd struct {
	TokenPrefix string `arg:"" help:"First 8 chars of the token to revoke."`
}

var version = "dev"

func main() {
	var cli CLI
	ctx := kong.Parse(&cli,
		kong.Name("csr-api"),
		kong.Description("Self-service CSR submission API."),
		kong.Vars{"version": version},
	)
	err := ctx.Run(&cli)
	ctx.FatalIfErrorf(err)
}

func (cmd *ServeCmd) Run(cli *CLI) error {
	logger := slog.Default()

	os.MkdirAll(cmd.CSRsDir, 0o755)
	os.MkdirAll(filepath.Dir(cli.DBPath), 0o755)

	st, err := store.New(cli.DBPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	srv := server.New(server.Config{
		Store:   st,
		Logger:  logger,
		CSRsDir: cmd.CSRsDir,
	})

	httpServer := &http.Server{
		Addr:    cmd.Addr,
		Handler: srv,
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)

	go func() {
		logger.Info("starting server", "addr", cmd.Addr)
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			logger.Error("server error", "err", err)
		}
	}()

	<-done
	logger.Info("shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return httpServer.Shutdown(shutdownCtx)
}

func (cmd *CreateTokenCmd) Run(cli *CLI) error {
	os.MkdirAll(filepath.Dir(cli.DBPath), 0o755)

	st, err := store.New(cli.DBPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	rawToken, err := auth.GenerateToken()
	if err != nil {
		return fmt.Errorf("generate token: %w", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	err = st.InsertToken(&store.AuthToken{
		TokenHash:   auth.HashToken(rawToken),
		TokenPrefix: auth.TokenPrefix(rawToken),
		ForWhom:     cmd.ForWhom,
		CreatedAt:   now,
	})
	if err != nil {
		return fmt.Errorf("store token: %w", err)
	}

	fmt.Printf("Token:  %s\n", rawToken)
	fmt.Printf("Prefix: %s\n", auth.TokenPrefix(rawToken))
	fmt.Printf("For:    %s\n", cmd.ForWhom)
	return nil
}

func (cmd *RevokeTokenCmd) Run(cli *CLI) error {
	st, err := store.New(cli.DBPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	found, err := st.RevokeTokenByPrefix(cmd.TokenPrefix)
	if err != nil {
		return fmt.Errorf("revoke token: %w", err)
	}
	if !found {
		fmt.Println("No token found with that prefix.")
		return nil
	}
	fmt.Println("Token revoked.")
	return nil
}

func (cmd *ListTokensCmd) Run(cli *CLI) error {
	st, err := store.New(cli.DBPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	tokens, err := st.ListTokens()
	if err != nil {
		return fmt.Errorf("list tokens: %w", err)
	}

	if len(tokens) == 0 {
		fmt.Println("No tokens found.")
		return nil
	}

	fmt.Println("prefix,for_whom,created_at,last_used,revoked")
	for _, t := range tokens {
		lastUsed := ""
		if t.LastUsed != nil {
			lastUsed = *t.LastUsed
		}
		revoked := "no"
		if t.Revoked {
			revoked = "yes"
		}
		fmt.Printf("%s,%s,%s,%s,%s\n", t.TokenPrefix, t.ForWhom, t.CreatedAt, lastUsed, revoked)
	}
	return nil
}

package cmd

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/majd/ipatool/v2/pkg/appstore"
	"github.com/majd/ipatool/v2/pkg/server"
	"github.com/spf13/cobra"
)

func serveCmd() *cobra.Command {
	var listen, base, dir, keyFile, emailFile, passwordFile string
	var ttl time.Duration
	var maxBytes, maxStorage int64
	cmd := &cobra.Command{Use: "serve", Short: "Serve profile-scoped IPA download links over HTTP", RunE: func(cmd *cobra.Command, args []string) error {
		if accountProfile != "cn" && accountProfile != "us" {
			return errors.New("serve requires --profile cn or --profile us")
		}
		host, _, err := net.SplitHostPort(listen)
		if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
			return errors.New("serve must listen on a loopback IP address")
		}
		secret, err := server.ReadCredential(keyFile)
		if err != nil {
			return err
		}
		artifacts, err := server.NewArtifactStore(dir, base, accountProfile, []byte(secret), ttl, maxBytes, maxStorage)
		if err != nil {
			return err
		}
		var creds server.CredentialsProvider
		if emailFile != "" || passwordFile != "" {
			if _, err := server.ReadLoginCredentials(emailFile, passwordFile); err != nil {
				return err
			}
			creds = func() (server.LoginCredentials, error) { return server.ReadLoginCredentials(emailFile, passwordFile) }
		}
		preparer, ok := dependencies.AppStore.(appstore.DownloadPreparer)
		if !ok {
			return errors.New("App Store download preparation is unavailable")
		}
		resolver, err := server.NewResolver(dependencies.AppStore, preparer, artifacts, creds, accountProfile, maxBytes)
		if err != nil {
			return err
		}
		handler := server.NewHandler(resolver, artifacts, func(code string) { log.Printf("request failed profile=%s code=%s", accountProfile, code) })
		srv := &http.Server{Addr: listen, Handler: handler, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 16 * time.Minute, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		go func() {
			<-ctx.Done()
			shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = srv.Shutdown(shutdown)
		}()
		log.Printf("listening profile=%s address=%s", accountProfile, listen)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve: %w", err)
		}
		return nil
	}}
	cmd.Flags().StringVar(&listen, "listen", "127.0.0.1:8080", "HTTP listen address")
	cmd.Flags().StringVar(&base, "public-base-url", "", "public HTTPS origin used in signed IPA links")
	cmd.Flags().StringVar(&dir, "artifact-dir", "", "absolute directory for private IPA artifacts")
	cmd.Flags().StringVar(&keyFile, "artifact-signing-key-file", "", "protected file containing the artifact signing key")
	cmd.Flags().DurationVar(&ttl, "artifact-ttl", time.Hour, "lifetime of signed IPA links")
	cmd.Flags().Int64Var(&maxBytes, "artifact-max-bytes", 1<<30, "maximum IPA artifact size")
	cmd.Flags().Int64Var(&maxStorage, "artifact-max-storage-bytes", 2<<30, "maximum total IPA storage")
	cmd.Flags().StringVar(&emailFile, "apple-email-credential-file", "", "protected file containing the fallback Apple ID")
	cmd.Flags().StringVar(&passwordFile, "apple-password-credential-file", "", "protected file containing the fallback Apple password")
	return cmd
}

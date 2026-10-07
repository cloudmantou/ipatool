package server

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/majd/ipatool/v2/pkg/appstore"
)

type ServiceError struct {
	Code, Message string
	Status        int
	RetryAfter    time.Duration
	Cause         error
}

func (e *ServiceError) Error() string { return e.Message }
func (e *ServiceError) Unwrap() error { return e.Cause }
func serviceError(code, message string, status int, cause error) error {
	return &ServiceError{Code: code, Message: message, Status: status, Cause: cause}
}

type Backend interface {
	AccountInfo() (appstore.AccountInfoOutput, error)
	Login(appstore.LoginInput) (appstore.LoginOutput, error)
	Lookup(appstore.LookupInput) (appstore.LookupOutput, error)
	Purchase(appstore.PurchaseInput) error
	Download(appstore.DownloadInput) (appstore.DownloadOutput, error)
	ReplicateSinf(appstore.ReplicateSinfInput) error
}
type Resolver struct {
	Store              Backend
	Preparer           appstore.DownloadPreparer
	Artifacts          *ArtifactStore
	Credentials        CredentialsProvider
	ExpectedStorefront string
	MaxBytes           int64
	gate               chan struct{}
	failureUntil       time.Time
	failureCount       int
	now                func() time.Time
}

func NewResolver(store Backend, preparer appstore.DownloadPreparer, artifacts *ArtifactStore, creds CredentialsProvider, region string, maxBytes int64) (*Resolver, error) {
	sf := map[string]string{"cn": "143465", "us": "143441"}[region]
	if sf == "" || maxBytes <= 0 || store == nil || preparer == nil || artifacts == nil {
		return nil, errors.New("invalid regional service configuration")
	}
	return &Resolver{Store: store, Preparer: preparer, Artifacts: artifacts, Credentials: creds, ExpectedStorefront: sf, MaxBytes: maxBytes, gate: make(chan struct{}, 1), now: time.Now}, nil
}
func (r *Resolver) acquire(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case r.gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (r *Resolver) validateAccount(acc appstore.Account) error {
	sf, _, _ := strings.Cut(acc.StoreFront, "-")
	if sf != r.ExpectedStorefront {
		return serviceError("storefront_mismatch", "account does not belong to the configured storefront", 503, nil)
	}
	if acc.PasswordToken == "" || acc.DirectoryServicesID == "" {
		return serviceError("authentication_unavailable", "account credentials are incomplete", 503, nil)
	}
	return nil
}
func (r *Resolver) refresh(old appstore.Account) (appstore.Account, error) {
	if remaining := r.failureUntil.Sub(r.now()); remaining > 0 {
		return appstore.Account{}, &ServiceError{Code: "authentication_unavailable", Message: "account authentication is temporarily unavailable", Status: 503, RetryAfter: remaining}
	}
	creds := LoginCredentials{Email: old.Email, Password: old.Password}
	if r.Credentials != nil {
		c, err := r.Credentials()
		if err != nil {
			return appstore.Account{}, serviceError("credentials_unavailable", "protected Apple credentials are unavailable", 503, err)
		}
		creds = c
	}
	if creds.Email == "" || creds.Password == "" {
		return appstore.Account{}, serviceError("credentials_unavailable", "Apple credentials are unavailable", 503, nil)
	}
	out, err := r.Store.Login(appstore.LoginInput{Email: creds.Email, Password: creds.Password})
	if err != nil {
		r.failureCount++
		delay := 30 * time.Second * time.Duration(1<<min(r.failureCount-1, 5))
		if delay > 10*time.Minute {
			delay = 10 * time.Minute
		}
		r.failureUntil = r.now().Add(delay)
		code, message := "authentication_unavailable", "account authentication is temporarily unavailable"
		if errors.Is(err, appstore.ErrAuthCodeRequired) {
			code = "auth_code_required"
			message = "account requires a two-factor verification code"
		}
		return appstore.Account{}, &ServiceError{Code: code, Message: message, Status: 503, RetryAfter: delay, Cause: err}
	}
	if err := r.validateAccount(out.Account); err != nil {
		return appstore.Account{}, err
	}
	r.failureUntil = time.Time{}
	r.failureCount = 0
	return out.Account, nil
}
func (r *Resolver) account() (appstore.Account, error) {
	out, err := r.Store.AccountInfo()
	if err != nil {
		return r.refresh(appstore.Account{})
	}
	if err := r.validateAccount(out.Account); err != nil {
		return appstore.Account{}, err
	}
	return out.Account, nil
}
func (r *Resolver) prepare(ctx context.Context, appID, version string) (appstore.PrepareDownloadOutput, appstore.Account, appstore.App, bool, error) {
	acc, err := r.account()
	if err != nil {
		return appstore.PrepareDownloadOutput{}, acc, appstore.App{}, false, err
	}
	id, _ := strconv.ParseInt(appID, 10, 64)
	app := appstore.App{ID: id}
	purchased, refreshed := false, false
	for attempt := 0; attempt < 4; attempt++ {
		if err := ctx.Err(); err != nil {
			return appstore.PrepareDownloadOutput{}, acc, app, purchased, err
		}
		out, err := r.Preparer.PrepareDownload(appstore.PrepareDownloadInput{Context: ctx, Account: acc, App: app, ExternalVersionID: version, Platform: appstore.PlatformIPhone, MaxBytes: r.MaxBytes})
		if err == nil {
			return out, acc, app, purchased, nil
		}
		if errors.Is(err, appstore.ErrPasswordTokenExpired) && !refreshed {
			acc, err = r.refresh(acc)
			if err != nil {
				return out, acc, app, purchased, err
			}
			refreshed = true
			continue
		}
		if errors.Is(err, appstore.ErrLicenseRequired) && !purchased {
			lookup, lookupErr := r.Store.Lookup(appstore.LookupInput{Account: acc, AppID: id, Platform: appstore.PlatformIPhone})
			if lookupErr != nil {
				return out, acc, app, purchased, serviceError("purchase_unavailable", "automatic purchase is unavailable", 422, lookupErr)
			}
			app = lookup.App
			if app.ID != id || app.Price != 0 {
				return out, acc, app, purchased, serviceError("purchase_unavailable", "only free apps can be acquired automatically", 422, nil)
			}
			err = r.Store.Purchase(appstore.PurchaseInput{Account: acc, App: app, Platform: appstore.PlatformIPhone})
			if errors.Is(err, appstore.ErrPasswordTokenExpired) && !refreshed {
				acc, err = r.refresh(acc)
				if err != nil {
					return out, acc, app, purchased, err
				}
				refreshed = true
				continue
			}
			if err != nil && !errors.Is(err, appstore.ErrLicenseAlreadyExists) {
				return out, acc, app, purchased, serviceError("purchase_unavailable", "automatic purchase is unavailable", 422, err)
			}
			purchased = true
			continue
		}
		return out, acc, app, purchased, serviceError("download_unavailable", "Apple download preparation failed", 502, err)
	}
	return appstore.PrepareDownloadOutput{}, acc, app, purchased, serviceError("download_unavailable", "download recovery attempts exhausted", 502, nil)
}
func (r *Resolver) Prepare(ctx context.Context, appID, version string) (appstore.PrepareDownloadOutput, bool, error) {
	if err := r.acquire(ctx); err != nil {
		return appstore.PrepareDownloadOutput{}, false, err
	}
	defer func() { <-r.gate }()
	out, _, _, purchased, err := r.prepare(ctx, appID, version)
	return out, purchased, err
}
func (r *Resolver) Download(ctx context.Context, appID, version string) (string, bool, error) {
	if err := r.acquire(ctx); err != nil {
		return "", false, err
	}
	defer func() { <-r.gate }()
	_, acc, app, purchased, err := r.prepare(ctx, appID, version)
	if err != nil {
		return "", purchased, err
	}
	link, err := r.Artifacts.Build(func(dst string) error {
		out, err := r.Store.Download(appstore.DownloadInput{Context: ctx, Account: acc, App: app, OutputPath: dst, ExternalVersionID: version, Platform: appstore.PlatformIPhone, MaxBytes: r.MaxBytes})
		if err != nil {
			return err
		}
		if len(out.Sinfs) > 0 {
			if err := r.Store.ReplicateSinf(appstore.ReplicateSinfInput{Sinfs: out.Sinfs, PackagePath: out.DestinationPath}); err != nil {
				return fmt.Errorf("package sinf: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return "", purchased, serviceError("download_unavailable", "IPA packaging failed", 502, err)
	}
	return link, purchased, nil
}

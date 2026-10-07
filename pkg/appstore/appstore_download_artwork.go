package appstore

import (
	"context"
	"errors"
	"fmt"
	apphttp "github.com/majd/ipatool/v2/pkg/http"
	"io"
	"net/http"
)

func (t *appstore) downloadArtwork(ctx context.Context, url string) ([]byte, error) {
	return t.downloadArtworkWithClient(ctx, url, t.httpClient)
}

func (t *appstore) downloadArtworkWithClient(ctx context.Context, url string, client apphttp.Client[interface{}]) ([]byte, error) {
	if url == "" {
		return nil, nil
	}

	if ctx == nil {
		ctx = context.Background()
	}

	req, err := client.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	res, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected artwork response status: %d", res.StatusCode)
	}

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read artwork: %w", err)
	}

	if len(data) == 0 {
		return nil, errors.New("artwork response is empty")
	}

	return data, nil
}

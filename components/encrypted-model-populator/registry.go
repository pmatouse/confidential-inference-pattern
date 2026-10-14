// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type Registry struct {
	Client    *http.Client
	Origin    string
	TokenFile string
}

func NewRegistry(origin, caFile, tokenFile string) (*Registry, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("registry origin must be an explicit HTTPS origin")
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("registry CA bundle is empty")
	}
	// Redirects are unnecessary for the internal registry. Refuse all of them,
	// including same-origin redirects, rather than forwarding registry credentials.
	client := &http.Client{Timeout: 20 * time.Minute, Transport: &http.Transport{
		TLSClientConfig:       &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		ResponseHeaderTimeout: 30 * time.Second,
	}, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return fmt.Errorf("registry redirects forbidden") }}
	return &Registry{client, origin, tokenFile}, nil
}

func (r *Registry) Get(ctx context.Context, path string) (io.ReadCloser, error) {
	token, err := os.ReadFile(r.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("registry credential unavailable")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", r.Origin+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Accept", manifestType)
	res, err := r.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("registry request failed: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		res.Body.Close()
		return nil, fmt.Errorf("registry returned HTTP %d", res.StatusCode)
	}
	return res.Body, nil
}

func shaDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (r *Registry) Manifest(ctx context.Context, s Source) (Descriptor, error) {
	body, err := r.Get(ctx, "/v2/"+s.Repository+"/manifests/"+s.ManifestDigest)
	if err != nil {
		return Descriptor{}, err
	}
	defer body.Close()
	raw, err := io.ReadAll(io.LimitReader(body, (1<<20)+1))
	if err != nil {
		return Descriptor{}, err
	}
	if len(raw) > 1<<20 || shaDigest(raw) != s.ManifestDigest {
		return Descriptor{}, fmt.Errorf("manifest size or digest mismatch")
	}
	var m Manifest
	if err := decodeStrict(raw, &m); err != nil {
		return Descriptor{}, fmt.Errorf("invalid model manifest: %w", err)
	}
	if m.SchemaVersion != 2 || m.MediaType != manifestType || m.Config.MediaType != configType || !digestPattern.MatchString(m.Config.Digest) || m.Config.Size < 1 || m.Config.Size > 1<<20 || len(m.Layers) != 1 {
		return Descriptor{}, fmt.Errorf("unsupported model artifact layout")
	}
	layer := m.Layers[0]
	if layer.MediaType != layerType || !digestPattern.MatchString(layer.Digest) || layer.Size < 1 || layer.Size > s.DiskBytes+(16<<20) {
		return Descriptor{}, fmt.Errorf("invalid ciphertext layer")
	}
	return layer, nil
}

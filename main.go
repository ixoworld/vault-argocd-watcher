// vault-argocd-watcher polls Vault KV v2 secret metadata for version changes and
// triggers a hard refresh on the corresponding ArgoCD Application so that
// ArgoCD Vault Plugin (AVP) re-fetches the updated secret on the next render.
//
// Auth flow:
//   - Authenticates to Vault using the pod's Kubernetes service account token
//   - Polls GET /<mount>/metadata/<app> for each watched app on a configurable interval
//   - On version increment, patches the ArgoCD Application annotation using
//     the in-cluster Kubernetes API (no ArgoCD token needed)
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

// ── Config ────────────────────────────────────────────────────────────────────

type config struct {
	vaultAddr     string
	vaultRole     string
	vaultMount    string
	k8sAPIServer  string
	k8sTokenPath  string
	k8sCACertPath string
	argoNamespace string
	watchedApps   []string
	pollInterval  time.Duration
}

func loadConfig() config {
	appsRaw := mustEnv("WATCHED_APPS")
	apps := []string{}
	for _, a := range strings.Split(appsRaw, ",") {
		if s := strings.TrimSpace(a); s != "" {
			apps = append(apps, s)
		}
	}
	pollInterval := 30 * time.Second
	if s := os.Getenv("POLL_INTERVAL"); s != "" {
		if d, err := time.ParseDuration(s); err == nil && d >= 5*time.Second {
			pollInterval = d
		}
	}
	return config{
		vaultAddr:     getEnv("VAULT_ADDR", "http://vault-active.vault.svc.cluster.local:8200"),
		vaultRole:     getEnv("VAULT_ROLE", "vault-watcher"),
		vaultMount:    getEnv("VAULT_MOUNT", "ixo_core"),
		k8sAPIServer:  getEnv("K8S_API_SERVER", "https://kubernetes.default.svc"),
		k8sTokenPath:  getEnv("K8S_TOKEN_PATH", "/var/run/secrets/kubernetes.io/serviceaccount/token"),
		k8sCACertPath: getEnv("K8S_CA_CERT_PATH", "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"),
		argoNamespace: getEnv("ARGO_NAMESPACE", "app-argocd"),
		watchedApps:   apps,
		pollInterval:  pollInterval,
	}
}

// ── Vault auth ────────────────────────────────────────────────────────────────

type vaultAuthResp struct {
	Auth struct {
		ClientToken   string `json:"client_token"`
		LeaseDuration int    `json:"lease_duration"`
	} `json:"auth"`
}

func vaultLogin(cfg config) (token string, leaseSecs int, err error) {
	jwt, err := os.ReadFile(cfg.k8sTokenPath)
	if err != nil {
		return "", 0, fmt.Errorf("read k8s token: %w", err)
	}

	body, _ := json.Marshal(map[string]string{
		"jwt":  strings.TrimSpace(string(jwt)),
		"role": cfg.vaultRole,
	})

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, cfg.vaultAddr+"/v1/auth/kubernetes/login", bytes.NewReader(body))
	if err != nil {
		return "", 0, fmt.Errorf("vault login new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("vault login request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return "", 0, fmt.Errorf("vault login failed (%d): %s", resp.StatusCode, data)
	}

	var ar vaultAuthResp
	if err := json.NewDecoder(resp.Body).Decode(&ar); err != nil {
		return "", 0, fmt.Errorf("decode vault auth response: %w", err)
	}
	return ar.Auth.ClientToken, ar.Auth.LeaseDuration, nil
}

func vaultRenewSelf(cfg config, token string) error {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, cfg.vaultAddr+"/v1/auth/token/renew-self", nil)
	if err != nil {
		return fmt.Errorf("renew-self new request: %w", err)
	}
	req.Header.Set("X-Vault-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("renew-self returned %d", resp.StatusCode)
	}
	return nil
}

func scheduleTokenRenewal(cfg config, token string, leaseSecs int) {
	if leaseSecs <= 0 {
		return
	}
	// Renew at 75% of lease duration to stay well within the TTL.
	interval := time.Duration(float64(leaseSecs)*0.75) * time.Second
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			if err := vaultRenewSelf(cfg, token); err != nil {
				slog.Warn("token renewal failed", "error", err)
			} else {
				slog.Info("vault token renewed", "next_in", interval)
			}
		}
	}()
}

// ── Vault KV v2 metadata polling ──────────────────────────────────────────────

type kvMetadataResp struct {
	Data struct {
		CurrentVersion int `json:"current_version"`
	} `json:"data"`
}

func fetchSecretVersion(cfg config, token, appName string) (int, error) {
	u := fmt.Sprintf("%s/v1/%s/metadata/%s", cfg.vaultAddr, cfg.vaultMount, appName)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("X-Vault-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("metadata %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var m kvMetadataResp
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return 0, fmt.Errorf("decode metadata: %w", err)
	}
	return m.Data.CurrentVersion, nil
}

// pollLoop seeds initial versions then polls on cfg.pollInterval, calling
// hardRefresh for any app whose secret version has incremented.
// Returns when all apps fail in a single cycle (likely token expiry), so the
// caller can re-authenticate and restart.
func pollLoop(cfg config, token string) error {
	// Seed initial versions to avoid spurious refreshes on startup.
	versions := make(map[string]int, len(cfg.watchedApps))
	for _, app := range cfg.watchedApps {
		v, err := fetchSecretVersion(cfg, token, app)
		if err != nil {
			slog.Warn("could not seed version", "app", app, "error", err)
			continue
		}
		versions[app] = v
	}
	slog.Info("polling vault kv metadata", "apps", len(cfg.watchedApps), "interval", cfg.pollInterval)

	ticker := time.NewTicker(cfg.pollInterval)
	defer ticker.Stop()

	for range ticker.C {
		failures := 0
		for _, app := range cfg.watchedApps {
			v, err := fetchSecretVersion(cfg, token, app)
			if err != nil {
				slog.Warn("fetch version failed", "app", app, "error", err)
				failures++
				continue
			}
			prev, seeded := versions[app]
			if !seeded {
				versions[app] = v
				continue
			}
			if v == prev {
				continue
			}
			slog.Info("secret version changed", "app", app, "old_version", prev, "new_version", v)
			if err := hardRefresh(cfg, app); err != nil {
				slog.Error("hard refresh failed", "app", app, "error", err)
			} else {
				versions[app] = v
			}
		}
		if failures == len(cfg.watchedApps) && len(cfg.watchedApps) > 0 {
			return fmt.Errorf("all apps unreachable, re-authenticating")
		}
	}
	return nil
}

// ── ArgoCD hard refresh via K8s annotation patch ──────────────────────────────

// hardRefresh patches the ArgoCD Application with the hard-refresh annotation.
// ArgoCD detects this annotation, re-renders the app (re-running AVP against
// Vault), then removes the annotation automatically.
func hardRefresh(cfg config, appName string) error {
	token, err := os.ReadFile(cfg.k8sTokenPath)
	if err != nil {
		return fmt.Errorf("read k8s token: %w", err)
	}

	caCert, err := os.ReadFile(cfg.k8sCACertPath)
	if err != nil {
		return fmt.Errorf("read k8s ca cert: %w", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCert)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
		Timeout: 10 * time.Second,
	}

	patchURL := fmt.Sprintf(
		"%s/apis/argoproj.io/v1alpha1/namespaces/%s/applications/%s",
		cfg.k8sAPIServer, cfg.argoNamespace, appName,
	)
	patch := `{"metadata":{"annotations":{"argocd.argoproj.io/refresh":"hard"}}}`

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPatch, patchURL, strings.NewReader(patch))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Content-Type", "application/merge-patch+json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("k8s patch request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("k8s patch returned %d: %s", resp.StatusCode, body)
	}

	slog.Info("hard refresh annotation set", "app", appName)
	return nil
}

// ── Main run loop ─────────────────────────────────────────────────────────────

func run() {
	cfg := loadConfig()
	slog.Info("starting vault-argocd-watcher",
		"vault_addr", cfg.vaultAddr,
		"vault_mount", cfg.vaultMount,
		"vault_role", cfg.vaultRole,
		"argocd_namespace", cfg.argoNamespace,
		"watched_apps", len(cfg.watchedApps),
		"poll_interval", cfg.pollInterval,
	)

	const retryBackoff = 10 * time.Second
	for {
		token, lease, err := vaultLogin(cfg)
		if err != nil {
			slog.Error("vault login failed", "error", err, "retry_in", retryBackoff)
			time.Sleep(retryBackoff)
			continue
		}
		slog.Info("authenticated to vault", "lease_seconds", lease)
		scheduleTokenRenewal(cfg, token, lease)

		if err := pollLoop(cfg, token); err != nil {
			slog.Warn("poll loop stopped", "error", err, "retry_in", retryBackoff)
			time.Sleep(retryBackoff)
		}
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		slog.Error("required env var not set", "key", key)
		os.Exit(1)
	}
	return v
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	run()
}

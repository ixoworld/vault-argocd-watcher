// vault-argocd-watcher watches Vault KV v2 write events via WebSocket and
// triggers a hard refresh on the corresponding ArgoCD Application so that
// ArgoCD Vault Plugin (AVP) re-fetches the updated secret on the next render.
//
// Auth flow:
//   - Authenticates to Vault using the pod's Kubernetes service account token
//   - Connects to Vault's event WebSocket endpoint (Vault OSS 1.16+)
//   - On secret write event, patches the ArgoCD Application annotation using
//     the in-cluster Kubernetes API (no ArgoCD token needed)
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
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
}

func loadConfig() config {
	appsRaw := mustEnv("WATCHED_APPS")
	apps := []string{}
	for _, a := range strings.Split(appsRaw, ",") {
		if s := strings.TrimSpace(a); s != "" {
			apps = append(apps, s)
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

	resp, err := http.Post(cfg.vaultAddr+"/v1/auth/kubernetes/login", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", 0, fmt.Errorf("vault login request: %w", err)
	}
	defer resp.Body.Close()

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
	req, _ := http.NewRequest(http.MethodPost, cfg.vaultAddr+"/v1/auth/token/renew-self", nil)
	req.Header.Set("X-Vault-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
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
				slog.Warn("token renewal failed — will re-authenticate on reconnect", "error", err)
			} else {
				slog.Info("vault token renewed", "next_in", interval)
			}
		}
	}()
}

// ── Vault event WebSocket ─────────────────────────────────────────────────────

// vaultEvent is the CloudEvents envelope Vault emits for KV v2 changes.
type vaultEvent struct {
	Type string `json:"type"`
	Data struct {
		Event struct {
			Metadata struct {
				Path       string `json:"path"`
				MountPoint string `json:"mount_point"`
			} `json:"metadata"`
		} `json:"event"`
	} `json:"data"`
}

// secretPath returns the normalised logical path from the event.
func (e vaultEvent) secretPath() string {
	return strings.TrimPrefix(e.Data.Event.Metadata.Path, "/")
}

// watchEvents opens a WebSocket to Vault's event stream and calls hardRefresh
// for every write event whose path matches an entry in appMapping.
// Returns when the connection drops so the caller can reconnect.
func watchEvents(cfg config, token string, appMapping map[string]string) error {
	u, err := url.Parse(cfg.vaultAddr)
	if err != nil {
		return fmt.Errorf("parse vault addr: %w", err)
	}
	switch u.Scheme {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	}
	// Subscribe to KV v2 data-write and data-patch events.
	u.Path = "/v1/sys/events/subscribe/kv-v2/data-write,kv-v2/data-patch"
	u.RawQuery = "json=true"

	header := http.Header{"X-Vault-Token": {token}}
	conn, _, err := websocket.DefaultDialer.Dial(u.String(), header)
	if err != nil {
		return fmt.Errorf("websocket dial: %w", err)
	}
	defer conn.Close()
	slog.Info("connected to vault event stream", "url", u.String())

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return fmt.Errorf("websocket read: %w", err)
		}

		var ev vaultEvent
		if err := json.Unmarshal(msg, &ev); err != nil {
			slog.Warn("failed to parse event", "error", err)
			continue
		}

		path := ev.secretPath()
		if path == "" {
			continue
		}
		slog.Debug("event received", "type", ev.Type, "path", path)

		appName, ok := appMapping[path]
		if !ok {
			continue
		}
		slog.Info("matched app, requesting hard refresh", "app", appName)
		if err := hardRefresh(cfg, appName); err != nil {
			slog.Error("hard refresh failed", "app", appName, "error", err)
		}
	}
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

	req, err := http.NewRequest(http.MethodPatch, patchURL, strings.NewReader(patch))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Content-Type", "application/merge-patch+json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("k8s patch request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("k8s patch returned %d: %s", resp.StatusCode, body)
	}

	slog.Info("hard refresh annotation set", "app", appName)
	return nil
}

// ── Main run loop ─────────────────────────────────────────────────────────────

func run() error {
	cfg := loadConfig()
	slog.Info("starting vault-argocd-watcher",
		"vault_addr", cfg.vaultAddr,
		"vault_mount", cfg.vaultMount,
		"vault_role", cfg.vaultRole,
		"argocd_namespace", cfg.argoNamespace,
		"watched_apps", len(cfg.watchedApps),
	)

	// Build path → app name mapping: ixo_core/data/{app-name} → {app-name}
	appMapping := make(map[string]string, len(cfg.watchedApps))
	for _, name := range cfg.watchedApps {
		appMapping[cfg.vaultMount+"/data/"+name] = name
	}

	// Initial Vault authentication.
	token, lease, err := vaultLogin(cfg)
	if err != nil {
		return fmt.Errorf("initial vault login: %w", err)
	}
	slog.Info("authenticated to vault", "lease_seconds", lease)
	scheduleTokenRenewal(cfg, token, lease)

	// Reconnect loop with exponential backoff.
	const (
		minBackoff = 5 * time.Second
		maxBackoff = 2 * time.Minute
	)
	backoff := minBackoff

	for {
		if err := watchEvents(cfg, token, appMapping); err != nil {
			slog.Warn("websocket disconnected, reconnecting", "error", err, "backoff", backoff)
			time.Sleep(backoff)
			if backoff < maxBackoff {
				backoff *= 2
			}

			// Re-authenticate in case the token expired while disconnected.
			token, lease, err = vaultLogin(cfg)
			if err != nil {
				slog.Error("re-authentication failed", "error", err)
				continue
			}
			slog.Info("re-authenticated to vault", "lease_seconds", lease)
			scheduleTokenRenewal(cfg, token, lease)
			backoff = minBackoff
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
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

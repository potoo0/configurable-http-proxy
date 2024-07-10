package lib

import (
	"context"
	"github.com/stretchr/testify/assert"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestErrorHandler(t *testing.T) {
	server := httptest.NewServer(http.StripPrefix("/status", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		statusRaw, _ := strings.CutPrefix(r.URL.Path, "/")
		status, err := strconv.Atoi(statusRaw)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		http.Error(w, "errorTarget,"+statusRaw, status)
	})))

	status := 400
	p, err := NewConfigurableProxy(new(Config))
	assert.NoError(t, err)
	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost:8080/get", nil)
	if err != nil {
		t.Fatalf("http.NewRequestWithContext error: %v", err)
	}

	t.Run("ErrorTarget", func(t *testing.T) {
		p.errorTarget = server.URL + "/status"
		resp := httptest.NewRecorder()
		p.handleProxyError(status, "http", resp, req, nil)
		assert.Equal(t, status, resp.Code)
		assert.Equal(t, "errorTarget,"+strconv.Itoa(status)+"\n", resp.Body.String())
	})
	t.Run("no-ErrorTarget", func(t *testing.T) {
		p.errorTarget = ""
		resp := httptest.NewRecorder()
		p.handleProxyError(status, "http", resp, req, nil)
		assert.Equal(t, status, resp.Code)
		assert.Contains(t, resp.Body.String(), "<p>configurable-http-proxy</p>")
	})
	t.Run("ErrorPath", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "configproxy-errorpath-")
		if err != nil {
			t.Fatal(err.Error())
		}
		defer os.Remove(tempDir)
		p.errorPath = tempDir

		msg := "errorPath"
		err = os.WriteFile(filepath.Join(tempDir, strconv.Itoa(status)+".html"), []byte(msg), 0644)
		if err != nil {
			t.Fatal(err.Error())
		}

		resp := httptest.NewRecorder()
		p.handleProxyError(status, "http", resp, req, nil)
		assert.Equal(t, status, resp.Code)
		assert.Equal(t, msg, resp.Body.String())
	})
}

func TestNewConfigurableProxy(t *testing.T) {
	cfg := SslConfig{
		Key:        LocalhostKey,
		Passphrase: "1234",
		Cert:       LocalhostCert,
		Ca:         RootCert,
	}

	// build target server
	targetServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//t.Logf("http request uri: %s", r.RequestURI)
		w.WriteHeader(http.StatusOK)
	}))
	tlsConfig, err := cfg.TlsConfig(true)
	assert.Nil(t, err)
	targetServer.TLS = tlsConfig
	targetServer.StartTLS()
	defer targetServer.Close()

	config := &Config{
		DefaultTarget: targetServer.URL,
		ClientSsl:     &cfg,
	}
	p, err := NewConfigurableProxy(config)
	assert.NoError(t, err)
	proxyServer := httptest.NewServer(p.ProxyServer.Handler())
	resp, err := proxyServer.Client().Get(proxyServer.URL + "/")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
}

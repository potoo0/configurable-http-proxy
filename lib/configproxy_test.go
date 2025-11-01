package lib

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigurableProxy_ErrorHandler(t *testing.T) {
	server := httptest.NewServer(http.StripPrefix("/status", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		statusRaw, _ := strings.CutPrefix(r.URL.Path, "/")
		status, err := strconv.Atoi(statusRaw)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		http.Error(w, "errorTarget,"+statusRaw, status)
	})))
	defer server.Close()

	status := 400
	p, err := NewConfigurableProxy(new(Config))
	require.NoError(t, err)
	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost:8080/get", nil)
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
		err = os.WriteFile(filepath.Join(tempDir, strconv.Itoa(status)+".html"), []byte(msg), 0o644)
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
	targetServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// t.Logf("http request uri: %s", r.RequestURI)
		w.WriteHeader(http.StatusOK)
	}))
	tlsConfig, err := cfg.TLSConfig(true)
	require.NoError(t, err)
	targetServer.TLS = tlsConfig
	targetServer.StartTLS()
	defer targetServer.Close()

	config := &Config{
		DefaultTarget: targetServer.URL,
		ClientSsl:     &cfg,
	}
	p, err := NewConfigurableProxy(config)
	require.NoError(t, err)
	proxyServer := httptest.NewServer(p.ProxyServer.Handler())
	defer proxyServer.Close()

	resp, err := proxyServer.Client().Get(proxyServer.URL + "/")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
}

func TestConfigurableProxy_MetricsServe(t *testing.T) {
	p, err := NewConfigurableProxy(&Config{
		EnableMetrics: true,
	})
	require.NoError(t, err)
	server := httptest.NewServer(p.MetricsServer)
	defer server.Close()
	resp, err := server.Client().Get(server.URL + "/metrics")
	require.NoError(t, err)
	defer resp.Body.Close()
	written, _ := io.Copy(io.Discard, resp.Body)
	assert.NotEqual(t, 0, written)
}

func TestConfigurableProxy_route(t *testing.T) {
	p, err := NewConfigurableProxy(new(Config))
	require.NoError(t, err)

	t.Run("add-get-remove", func(t *testing.T) {
		// add
		routeDataOld := map[string]any{"target": "old"}
		p.addRoute("/path", copyMap(routeDataOld))

		// get
		route, exists := p.getRoute("/path")
		assert.True(t, exists)
		assert.True(t, equalOnLeft(routeDataOld, route))

		// remove
		removed := p.removeRoute("/path")
		assert.True(t, removed)
		removed = p.removeRoute("/path")
		assert.False(t, removed)

		// get
		_, exists = p.getRoute("/path")
		assert.False(t, exists)
	})
	t.Run("get-routes-all", func(t *testing.T) {
		routeDataOld := map[string]any{"target": "old"}
		p.addRoute("/path1", copyMap(routeDataOld))
		p.addRoute("/path2", copyMap(routeDataOld))
		defer p.removeRoute("/path1")
		defer p.removeRoute("/path2")

		routes := p.getRoutes(0)
		assert.Len(t, routes, 2)
	})
	t.Run("get-routes-by_inactiveSince", func(t *testing.T) {
		routeData1 := map[string]any{"target": "t1"}
		p.addRoute("/path1", copyMap(routeData1))
		time.Sleep(1005 * time.Millisecond)
		inactiveSince := time.Now().Unix()
		routeData2 := map[string]any{"target": "t2"}
		p.addRoute("/path2", copyMap(routeData2))
		defer p.removeRoute("/path1")
		defer p.removeRoute("/path2")

		routes := p.getRoutes(inactiveSince)
		assert.Len(t, routes, 1)
		assert.True(t, equalOnLeft(routeData1, routes["/path1"]))
	})
}

func copyMap(src map[string]any) map[string]any {
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func equalOnLeft(left, right map[string]any) bool {
	for k, v := range left {
		if rv, exists := right[k]; !exists || rv != v {
			return false
		}
	}
	return true
}

package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strconv"
	"testing"
)

func muteLog() {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	slog.SetDefault(log)
}

func TestProxy_rewrite(t *testing.T) {
	muteLog()
	prefix := "/prefix"
	serverUrlRaw := "http://localhost:8080"
	serverUrl := mustParse(t, serverUrlRaw)
	target := mustParse(t, "https://httpbin.org/get")

	ctx := context.WithValue(context.Background(), ctxTargetKey{}, target)
	req, err := http.NewRequestWithContext(ctx, "GET", serverUrlRaw+prefix, nil)
	if err != nil {
		t.Fatalf("http.NewRequestWithContext error: %v", err)
	}
	req.RemoteAddr = "127.0.0.1:55555"

	t.Run("PrependPath-false", func(t *testing.T) {
		proxyServer := &Server{}
		pr := &httputil.ProxyRequest{In: req, Out: req.Clone(ctx)}
		proxyServer.rewrite(pr)
		targetNew := cloneURL(target)
		targetNew.Path = ""
		targetNew.RawPath = ""
		assert.Equal(t, targetNew.String()+prefix, pr.Out.URL.String())
	})
	t.Run("PrependPath-true", func(t *testing.T) {
		proxyServer := &Server{PrependPath: true}
		pr := &httputil.ProxyRequest{In: req, Out: req.Clone(ctx)}
		proxyServer.rewrite(pr)
		assert.Equal(t, target.String()+prefix, pr.Out.URL.String())
	})
	t.Run("ChangeOrigin-false", func(t *testing.T) {
		proxyServer := &Server{}
		pr := &httputil.ProxyRequest{In: req, Out: req.Clone(ctx)}
		proxyServer.rewrite(pr)
		assert.Equal(t, serverUrl.Host, pr.Out.Header.Get("Host"))
	})
	t.Run("ChangeOrigin-true", func(t *testing.T) {
		proxyServer := &Server{ChangeOrigin: true}
		pr := &httputil.ProxyRequest{In: req, Out: req.Clone(ctx)}
		proxyServer.rewrite(pr)
		assert.Equal(t, target.Host, pr.Out.Header.Get("Host"))
	})
	t.Run("Xfwd-false", func(t *testing.T) {
		proxyServer := &Server{}
		pr := &httputil.ProxyRequest{In: req, Out: req.Clone(ctx)}
		proxyServer.rewrite(pr)
		assert.Empty(t, pr.Out.Header.Get("X-Forwarded-For"))
	})
	t.Run("Xfwd-true", func(t *testing.T) {
		proxyServer := &Server{Xfwd: true}
		pr := &httputil.ProxyRequest{In: req, Out: req.Clone(ctx)}
		proxyServer.rewrite(pr)
		assert.Equal(t, "127.0.0.1", pr.Out.Header.Get("X-Forwarded-For"))
		assert.Equal(t, serverUrl.Host, pr.Out.Header.Get("X-Forwarded-Host"))
		assert.Equal(t, serverUrl.Scheme, pr.Out.Header.Get("X-Forwarded-Proto"))
	})
}

func TestProxy_redirect_reg(t *testing.T) {
	cases := []struct {
		statusCode int
		redirect   bool
	}{
		{200, false},
		{201, true},
		{301, true},
		{301278, false},
		{1301, false},
		{302, true},
		{306, false},
		{307, true},
		{308, true},
	}
	for _, c := range cases {
		assert.Equal(t, c.redirect, redirectRegex.MatchString(strconv.Itoa(c.statusCode)),
			fmt.Sprintf("statusCode=%d", c.statusCode))
	}
}

func TestProxy_redirect(t *testing.T) {
	muteLog()
	redirectTo := "https://httpbin.org/get"
	reqUrlRaw := "https://httpbin.org/redirect-to?url=" + redirectTo

	serverUrl := mustParse(t, reqUrlRaw)
	ctx := context.Background()
	ctx = context.WithValue(ctx, ctxPrefixKey{}, serverUrl.Path)

	reqHeader := http.Header{}
	reqHeader.Set("Host", serverUrl.Host)
	req, err := http.NewRequestWithContext(ctx, "GET", reqUrlRaw, nil)
	if err != nil {
		t.Fatalf("http.NewRequestWithContext error: %v", err)
	}
	req.Header = reqHeader

	proxyServer := &Server{AutoRewrite: true}

	t.Run("status-200", func(t *testing.T) {
		respHeader := http.Header{}
		respHeader.Set("Location", redirectTo)
		resp := &http.Response{Request: req, Header: respHeader, StatusCode: 200}
		if err := proxyServer.modifyResponse(resp); err != nil {
			t.Fatalf("modifyResponse error: %v", err)
		}
		assert.Equal(t, redirectTo, resp.Header.Get("Location"))
	})
	t.Run("status-301", func(t *testing.T) {
		redirectToHost := "localhost:8080"
		reqHeader.Set("Host", redirectToHost)
		u := mustParse(t, redirectTo)
		u.Host = redirectToHost

		respHeader := http.Header{}
		respHeader.Set("Location", redirectTo)
		resp := &http.Response{Request: req, Header: respHeader, StatusCode: 301}
		if err := proxyServer.modifyResponse(resp); err != nil {
			t.Fatalf("modifyResponse error: %v", err)
		}
		assert.Equal(t, u.String(), resp.Header.Get("Location"))
	})
	t.Run("ProtocolRewrite", func(t *testing.T) {
		protocolRewrite := "http"
		proxyServer.ProtocolRewrite = protocolRewrite

		redirectToHost := "localhost:8080"
		reqHeader.Set("Host", redirectToHost)
		u := mustParse(t, redirectTo)
		u.Scheme = protocolRewrite
		u.Host = redirectToHost

		respHeader := http.Header{}
		respHeader.Set("Location", redirectTo)
		resp := &http.Response{Request: req, Header: respHeader, StatusCode: 301}
		if err := proxyServer.modifyResponse(resp); err != nil {
			t.Fatalf("modifyResponse error: %v", err)
		}
		assert.Equal(t, u.String(), resp.Header.Get("Location"))
	})

}

func TestProxyServer(t *testing.T) {
	muteLog()
	// value type any for assert.Equal
	queryParams := map[string]any{"q1": "v1"}
	routes := map[string]string{}
	proxyServer := &Server{
		TargetForReq: func(host, path string) (target Target, exists bool) {
			var urlRaw string
			if urlRaw, exists = routes[path]; exists {
				target.Target = urlRaw
				target.Prefix = path
			}
			return target, exists
		},
	}
	server := httptest.NewServer(proxyServer.Handler())
	defer server.Close()

	requestAndAssert := func(t *testing.T, path string) {
		res, err := server.Client().Get(server.URL + path)
		if !assert.Nil(t, err) {
			return
		}
		defer res.Body.Close()

		assert.Equal(t, 200, res.StatusCode)
		bodyBytes, err := io.ReadAll(res.Body)
		if !assert.Nil(t, err) {
			return
		}
		//t.Logf("GET StatusCode=%d, body=%s", res.StatusCode, string(bodyBytes))

		bodyMap := map[string]any{}
		err = json.Unmarshal(bodyBytes, &bodyMap)
		if !assert.Nil(t, err) {
			return
		}
		assert.Equal(t, queryParams, bodyMap["args"])
	}

	t.Run("IncludePrefix-true", func(t *testing.T) {
		proxyServer.IncludePrefix = true
		routes["/get"] = "https://httpbin.org?" + toQueryRaw(queryParams)
		requestAndAssert(t, "/get")
	})

	t.Run("IncludePrefix-false", func(t *testing.T) {
		proxyServer.IncludePrefix = false
		proxyServer.PrependPath = true
		routes["/get"] = "https://httpbin.org/get?" + toQueryRaw(queryParams)
		requestAndAssert(t, "/get")
	})
}

func mustParse(t *testing.T, raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse serverUrl error: %v", err)
		return nil
	}
	return u
}

func toQueryRaw(m map[string]any) string {
	values := url.Values{}
	for k, v := range m {
		values.Set(k, v.(string))
	}
	return values.Encode()
}

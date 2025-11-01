package lib

import (
	"io"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)
	server := httptest.NewServer(promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))
	defer server.Close()

	expected := make(map[string][]string)

	m.apiRoute.WithLabelValues("200", "POST").Inc()
	m.apiRoute.WithLabelValues("404", "GET").Inc()
	expected["apiRoute"] = []string{
		`api_route{code="200",method="POST"}`,
		`api_route{code="404",method="GET"}`,
	}

	m.findTarget.Observe(100)
	m.findTarget.Observe(200)
	expected["findTarget"] = []string{
		`find_target_for_req_sum 300`,
	}

	m.lastActivityUpdating.Observe(300)
	m.lastActivityUpdating.Observe(400)
	expected["lastActivityUpdating"] = []string{
		`last_activity_updating_sum 700`,
	}

	m.proxyRequests.WithLabelValues("http").Inc()
	m.proxyRequests.WithLabelValues("http").Inc()
	m.proxyRequests.WithLabelValues("ws").Inc()
	expected["proxyRequests"] = []string{
		`proxy_requests{kind="http"} 2`,
		`proxy_requests{kind="ws"} 1`,
	}

	m.proxyResponses.WithLabelValues("200").Inc()
	m.proxyResponses.WithLabelValues("404").Inc()
	expected["proxyResponses"] = []string{
		`proxy_responses{code="200"} 1`,
		`proxy_responses{code="404"} 1`,
	}

	resp, err := server.Client().Get(server.URL)
	require.NoError(t, err)
	defer resp.Body.Close()
	bytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	for k, v := range expected {
		for _, s := range v {
			assert.Contains(t, string(bytes), s, "metrics="+k)
		}
	}
}

func TestNewMockMetrics(_ *testing.T) {
	m := NewMockMetrics()

	m.apiRoute.WithLabelValues("200", "POST").Inc()
	m.apiRoute.WithLabelValues("404", "GET").Inc()

	m.findTarget.Observe(100)
	m.findTarget.Observe(200)

	m.lastActivityUpdating.Observe(300)
	m.lastActivityUpdating.Observe(400)

	m.proxyRequests.WithLabelValues("http").Inc()
	m.proxyRequests.WithLabelValues("http").Inc()
	m.proxyRequests.WithLabelValues("ws").Inc()

	m.proxyResponses.WithLabelValues("200").Inc()
	m.proxyResponses.WithLabelValues("404").Inc()
}

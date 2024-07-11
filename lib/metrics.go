package lib

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

type metrics struct {
	apiRoute             *prometheus.CounterVec
	findTarget           prometheus.Summary
	lastActivityUpdating prometheus.Summary
	proxyRequests        *prometheus.CounterVec
	proxyResponses       *prometheus.CounterVec
}

func NewMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{
		apiRoute: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "api_route",
			Help: "Count of API requests, partitioned by status code and HTTP method.",
		}, []string{"code", "method"}),
		findTarget: prometheus.NewSummary(prometheus.SummaryOpts{
			Name: "find_target_for_req",
			Help: "Summary of find target requests",
		}),
		lastActivityUpdating: prometheus.NewSummary(prometheus.SummaryOpts{
			Name: "last_activity_updating",
			Help: "Summary of last activity updating requests",
		}),
		proxyRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "proxy_requests",
			Help: "Count of proxy requests, partitioned by kind(ws/http).",
		}, []string{"kind"}),
		proxyResponses: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "proxy_responses",
			Help: "Count of proxy responses, partitioned by status code.",
		}, []string{"code"}),
	}

	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	reg.MustRegister(m.apiRoute)
	reg.MustRegister(m.findTarget)
	reg.MustRegister(m.lastActivityUpdating)
	reg.MustRegister(m.proxyRequests)
	reg.MustRegister(m.proxyResponses)
	return m
}

func NewMockMetrics() *metrics {
	m := &metrics{
		apiRoute: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "api_route",
			Help: "Count of API requests, partitioned by status code and HTTP method.",
		}, []string{"code", "method"}),
		findTarget: prometheus.NewSummary(prometheus.SummaryOpts{
			Name: "find_target_for_req",
			Help: "Summary of find target requests",
		}),
		lastActivityUpdating: prometheus.NewSummary(prometheus.SummaryOpts{
			Name: "last_activity_updating",
			Help: "Summary of last activity updating requests",
		}),
		proxyRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "proxy_requests",
			Help: "Count of proxy requests, partitioned by kind(ws/http).",
		}, []string{"kind"}),
		proxyResponses: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "proxy_responses",
			Help: "Count of proxy responses, partitioned by status code.",
		}, []string{"code"}),
	}

	return m
}

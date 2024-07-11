package proxy

import (
	"context"
	"errors"
	"fmt"
	log "log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var redirectRegex = regexp.MustCompile(`^(201|30([1278]))$`)

type (
	ctxTargetKey struct{}
	ctxPrefixKey struct{}
)

// Server field TargetForReq should be non-nil
type Server struct {
	Secure          bool              // verify SSL certificate
	IncludePrefix   bool              // include prefix in proxy path
	PrependPath     bool              // prepend target path to proxy path
	ChangeOrigin    bool              // change origin to target host, use requested host if not
	Xfwd            bool              // adds x-forward headers
	Headers         map[string]string // extra headers to proxy request
	AutoRewrite     bool              // rewrites the location on (201/301/302/307/308) redirects based on requested host/port
	ProtocolRewrite string            // rewrites the location on (201/301/302/307/308) redirects to 'http' or 'https'
	ProxyTimeout    int               // http request timeout in milliseconds

	Client       *http.Client
	ErrorHandler func(code int, kind string, w http.ResponseWriter, r *http.Request, err error)

	TargetForReq       func(host, path string) (Target, bool)
	UpdateLastActivity func(path string)

	ServeMetrics    func(kind string)
	ResponseMetrics func(code int)

	proxy *httputil.ReverseProxy
}

type Target struct {
	Target string // target url
	Prefix string // prefix path
}

func (s *Server) Handler() http.HandlerFunc {
	var transport http.RoundTripper
	if s.Client != nil {
		transport = s.Client.Transport
	}
	s.proxy = &httputil.ReverseProxy{
		Rewrite:        s.rewrite,
		Transport:      transport,
		ModifyResponse: s.modifyResponse,
		ErrorHandler: func(writer http.ResponseWriter, request *http.Request, err error) {
			code := http.StatusBadGateway
			if errors.Is(err, context.DeadlineExceeded) {
				code = http.StatusGatewayTimeout
			}
			s.handleError(code, proxyKind(request), writer, request, err)
		},
	}
	return s.serve
}

// rewrite request url, pr.Out and pr.In share the same context
func (s *Server) rewrite(pr *httputil.ProxyRequest) {
	target := pr.In.Context().Value(ctxTargetKey{}).(*url.URL)

	// clean path if not prependPath before SetURL
	if !s.PrependPath {
		target = cloneURL(target)
		target.Path = ""
		target.RawPath = ""
	}
	// set host header for redirect
	if s.ChangeOrigin {
		port, isFromHost := urlPort(target)
		if !isFromHost && port != defaultPort(target.Scheme) {
			pr.Out.Header.Set("Host", target.Host+":"+strconv.Itoa(port))
		} else {
			pr.Out.Header.Set("Host", target.Host)
		}
	} else {
		pr.Out.Header.Set("Host", pr.In.Host)
	}
	pr.SetURL(target)
	// fix reverseproxy.rewriteRequestURL slash suffix: a=b="" -> ""
	if pr.In.URL.Path == "" {
		pr.Out.URL.Path = target.Path
	}

	if s.Xfwd {
		pr.SetXForwarded()
	}
	for k, v := range s.Headers {
		pr.Out.Header.Set(k, v)
	}
}

func (s *Server) modifyResponse(r *http.Response) (err error) {
	if s.ResponseMetrics != nil {
		defer func() {
			// skip the error, it will be handled by the ErrorHandler
			if err == nil {
				s.ResponseMetrics(r.StatusCode)
			}
		}()
	}
	prefix := r.Request.Context().Value(ctxPrefixKey{}).(string)
	if r.StatusCode < 300 {
		s.updateLastActivity(prefix)
	} else {
		log.Debug(fmt.Sprintf("Not recording activity for status %d on %s", r.StatusCode, prefix))
	}
	if s.AutoRewrite && r.Header.Get("Location") != "" && redirectRegex.MatchString(strconv.Itoa(r.StatusCode)) {
		redirectTo, err := url.Parse(r.Header.Get("Location"))
		if err != nil {
			return fmt.Errorf("failed to parse Location header: %v", err)
		}
		if redirectTo.Host != r.Request.URL.Host {
			return nil
		}
		if host := r.Request.Header.Get("Host"); host != "" {
			redirectTo.Host = host
		}
		if s.ProtocolRewrite != "" {
			redirectTo.Scheme = s.ProtocolRewrite
		}
		r.Header.Set("Location", redirectTo.String())
	}
	return nil
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	kind := proxyKind(r)
	if s.ServeMetrics != nil {
		s.ServeMetrics(kind)
	}
	defer func() {
		if err := recover(); err != nil {
			s.handleError(http.StatusInternalServerError, kind, w, r, nil)
		}
	}()
	// notes: r.URL.Path already PathUnescape
	targetInfo, exists := s.TargetForReq(parseHost(r), r.URL.Path)
	if !exists {
		s.handleError(http.StatusNotFound, kind, w, r, nil)
		return
	}
	defer s.updateLastActivity(targetInfo.Prefix)
	// websocket 时此处会先
	targetUrlRaw := targetInfo.Target
	log.Debug(fmt.Sprintf("PROXY %s %s to %s", kind, r.URL, targetUrlRaw))
	targetUrl, err := url.Parse(targetUrlRaw)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !s.IncludePrefix {
		r.URL.Path, _ = strings.CutPrefix(r.URL.Path, targetInfo.Prefix)
	}

	ctx := r.Context()
	// http proxy request timeout, pr.Out and pr.In share the same context
	if kind == "http" && s.ProxyTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(s.ProxyTimeout)*time.Millisecond)
		defer cancel()
	}
	ctx = context.WithValue(ctx, ctxTargetKey{}, targetUrl)
	ctx = context.WithValue(ctx, ctxPrefixKey{}, targetInfo.Prefix)

	rn := r.WithContext(ctx)
	s.handleHttp(w, rn)
}

// proxyKind returns the kind of proxy to use, ws or http
func proxyKind(r *http.Request) string {
	if headerValuesContainsToken(r.Header["Connection"], "Upgrade") &&
		headerValuesContainsToken(r.Header["Upgrade"], "websocket") {
		return "ws"
	}

	return "http"
}

func headerValuesContainsToken(values []string, token string) bool {
	for _, v := range values {
		for _, actual := range strings.Split(v, ",") {
			if strings.TrimSpace(actual) == token {
				return true
			}
		}
	}
	return false
}

func (s *Server) updateLastActivity(path string) {
	if s.UpdateLastActivity != nil {
		s.UpdateLastActivity(path)
	}
}

func (s *Server) handleHttp(w http.ResponseWriter, r *http.Request) {
	if healthCheck(w, r) {
		return
	}

	s.proxy.ServeHTTP(w, r)
}

func (s *Server) handleError(code int, kind string, w http.ResponseWriter, r *http.Request, err error) {
	if s.ResponseMetrics != nil {
		defer s.ResponseMetrics(code)
	}
	errorHandler := s.ErrorHandler
	if errorHandler == nil {
		errorHandler = s.defaultErrorHandler
	}
	errorHandler(code, kind, w, r, err)
}

func (s *Server) defaultErrorHandler(code int, kind string, w http.ResponseWriter, r *http.Request, err error) {
	var errMsg string
	if err != nil {
		errMsg = err.Error()
	}
	log.Error(fmt.Sprintf("%d %s %s %s", code, r.Method, r.URL.Path, errMsg))
	if w == nil {
		log.Debug("Socket error, no response to send")
		return
	}
	w.WriteHeader(code)
	w.Write([]byte(http.StatusText(code)))
}

// health check, url: /_chp_healthz
func healthCheck(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == "/_chp_healthz" {
		w.Header().Set("Content-Type", "application/json")
		//w.WriteHeader(http.StatusOK) // unnecessary
		w.Write([]byte(`{"status": "OK"}`))
		return true
	}
	return false
}

func parseHost(r *http.Request) string {
	host, _, _ := net.SplitHostPort(r.Host)
	// never err, ignore...
	return host
}

func cloneURL(u *url.URL) *url.URL {
	if u == nil {
		return nil
	}
	u2 := new(url.URL)
	*u2 = *u
	if u.User != nil {
		u2.User = new(url.Userinfo)
		*u2.User = *u.User
	}
	return u2
}

// urlPort returns the port and whether it comes from url.host
func urlPort(u *url.URL) (int, bool) {
	portRaw := u.Port()
	if portRaw != "" {
		port, _ := strconv.Atoi(portRaw)
		return port, true
	}
	return defaultPort(u.Scheme), false
}

func defaultPort(protocol string) int {
	switch strings.ToLower(protocol) {
	case "http", "ws":
		return 80
	case "https", "wss":
		return 443
	default:
		return 0
	}
}

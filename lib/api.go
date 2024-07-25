package lib

import (
	"fmt"
	log "log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type ApiServer struct {
	config *ConfigurableProxy
}

func NewApiServer(config *ConfigurableProxy) *ApiServer {
	return &ApiServer{config: config}
}

func (server *ApiServer) Handler() http.Handler {
	router := http.NewServeMux()

	// path allow `/a/b/c`...
	router.HandleFunc("GET /api/routes", server.getRoute)
	router.HandleFunc("GET /api/routes/{path...}", server.getRoute)
	router.HandleFunc("POST /api/routes", server.addRoute)
	router.HandleFunc("POST /api/routes/{path...}", server.addRoute)
	router.HandleFunc("DELETE /api/routes", server.deleteRoute)
	router.HandleFunc("DELETE /api/routes/{path...}", server.deleteRoute)

	middlewares := []Middleware{server.LoggerMiddleware}
	if server.config.authToken != "" {
		middlewares = append(middlewares, server.AuthMiddleware)
	}
	middleware := ChainMiddleware(middlewares...)

	return middleware(router)
}

// handle GET /{path?}/
func (server *ApiServer) getRoute(w http.ResponseWriter, r *http.Request) {
	path := r.PathValue("path")
	if path != "" {
		if route, exists := server.config.getRoute(path); exists {
			WriteJson(w, route)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
		return
	}
	inactiveSinceRaw := r.URL.Query().Get("inactiveSince")
	if inactiveSinceRaw == "" {
		// support snake_case
		inactiveSinceRaw = r.URL.Query().Get("inactive_since")
	}
	inactiveSince := int64(0)
	if inactiveSinceRaw != "" {
		// pattern: RFC3339
		inactiveSinceTime, err := parseTime(inactiveSinceRaw)
		if err != nil {
			fail(w, r, http.StatusBadRequest, "Invalid datestamp '"+inactiveSinceRaw+"' must be RFC3339: "+err.Error())
			return
		}
		inactiveSince = inactiveSinceTime.Unix()
	}

	routes := server.config.getRoutes(inactiveSince)
	WriteJson(w, routes)
}

// handle POST /{path?}/
func (server *ApiServer) addRoute(w http.ResponseWriter, r *http.Request) {
	path := r.PathValue("path")
	if path == "" {
		path = "/"
	}
	// parse body
	data, err := ParseJson(r.Body)
	if err != nil {
		fail(w, r, http.StatusBadRequest, "Body not valid JSON: "+err.Error())
		return
	}
	// check target
	var target any
	var targetValid bool
	if target, targetValid = data["target"]; targetValid {
		_, targetValid = target.(string)
	}
	if !targetValid {
		fail(w, r, http.StatusBadRequest, "Must specify 'target' as string")
		return
	}
	_, err = url.Parse(target.(string))
	if err != nil {
		fail(w, r, http.StatusBadRequest, "target is not valid url: "+err.Error())
		return
	}

	server.config.addRoute(path, data)
	w.WriteHeader(http.StatusCreated)
}

// handle DELETE /{path?}/
func (server *ApiServer) deleteRoute(w http.ResponseWriter, r *http.Request) {
	path := r.PathValue("path")
	exists := server.config.removeRoute(path)
	if !exists {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func parseTime(raw string) (time.Time, error) {
	parsed, err := time.Parse("2006-01-02T15:04:05-0700", raw)
	if err != nil {
		// try RFC3339
		parsed, err = time.Parse(time.RFC3339, raw)
	}
	return parsed, err
}

/* -------------------------- middleware start -------------------------- */

func (server *ApiServer) LoggerMiddleware(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		lrw := newLoggingResponseWriter(w)
		next.ServeHTTP(lrw, r)

		code := lrw.StatusCode
		logF := log.Error
		if code < 400 {
			logF = log.Info
		} else if code < 500 {
			logF = log.Warn
		}

		msg := lrw.logMsg
		logF(fmt.Sprintf("%d %s %s %s", code, r.Method, r.URL.Path, msg))
		server.config.metrics.apiRoute.WithLabelValues(strconv.Itoa(code), r.Method).Inc()
	}
}

func (server *ApiServer) AuthMiddleware(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authRaw := r.Header.Get("authorization")
		auth, _ := strings.CutPrefix(authRaw, "token")
		if strings.TrimSpace(auth) != server.config.authToken {
			msg := authRaw
			if msg == "" {
				msg = "no authorization"
			}
			log.Debug(fmt.Sprintf("Rejecting API request from: %s", msg))
			w.WriteHeader(http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	}
}

type Middleware func(http.Handler) http.HandlerFunc

func ChainMiddleware(middlewares ...Middleware) Middleware {
	return func(next http.Handler) http.HandlerFunc {
		for idx := len(middlewares) - 1; idx >= 0; idx-- {
			next = middlewares[idx](next)
		}

		return next.ServeHTTP
	}
}

/* -------------------------- middleware end -------------------------- */

/* -------------------------- log response writer start -------------------------- */
var _ logMsgWriter = (*loggingResponseWriter)(nil)

type logMsgWriter interface {
	WriteLogMsg(msg string)
}

type loggingResponseWriter struct {
	http.ResponseWriter
	StatusCode int
	logMsg     string
}

func newLoggingResponseWriter(w http.ResponseWriter) *loggingResponseWriter {
	return &loggingResponseWriter{w, http.StatusOK, ""}
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.StatusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

func (lrw *loggingResponseWriter) WriteLogMsg(msg string) {
	lrw.logMsg = msg
}

func fail(w http.ResponseWriter, r *http.Request, code int, msg string) {
	if msgW, ok := w.(logMsgWriter); ok {
		msgW.WriteLogMsg(msg)
	}
	w.WriteHeader(code)
	if msg == "" {
		msg = http.StatusText(code)
	}
	w.Write([]byte(msg))
}

/* -------------------------- log response writer end -------------------------- */

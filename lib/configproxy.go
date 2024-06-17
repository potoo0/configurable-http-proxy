package lib

import (
	"fmt"
	"github.com/potoo0/configurable-http-proxy/lib/proxy"
	"io"
	log "log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type ConfigurableProxy struct {
	authToken   string
	hostRouting bool
	errorTarget string
	errorPath   string
	clientSsl   *SslConfig

	routes BaseStore

	ApiServer   *ApiServer
	ProxyServer *proxy.Server
}

func loadStorage(options *Config) *MemoryStore {
	if options.StorageBackend != "" {
		log.Warn(fmt.Sprintf("storage backend '%s' not implemented, rollback to in-MemoryStore storage", options.StorageBackend))
	}
	return NewMemoryStore()
}

func NewConfigurableProxy(config *Config) *ConfigurableProxy {
	var instance = &ConfigurableProxy{clientSsl: config.ClientSsl}
	instance.routes = loadStorage(config)
	instance.authToken = config.AuthToken
	instance.hostRouting = config.HostRouting
	instance.errorTarget = config.ErrorTarget
	instance.errorPath = config.ErrorPath

	if config.DefaultTarget != "" {
		instance.addRoute("/", map[string]any{"target": config.DefaultTarget})
	}

	instance.ApiServer = NewApiServer(instance)

	instance.ProxyServer = &proxy.Server{
		Secure:          config.Secure,
		IncludePrefix:   config.IncludePrefix,
		PrependPath:     config.PrependPath,
		ChangeOrigin:    config.ChangeOrigin,
		Xfwd:            config.Xfwd,
		Headers:         config.Headers,
		AutoRewrite:     config.AutoRewrite,
		ProtocolRewrite: config.ProtocolRewrite,
		ProxyTimeout:    config.ProxyTimeout,

		ErrorHandler: instance.handleProxyError,

		TargetForReq:       instance.targetForReq,
		UpdateLastActivity: instance.updateLastActivity,
	}
	// go http.Client enable keepalive by default
	return instance
}

func (p *ConfigurableProxy) handleProxyError(code int, kind string, w http.ResponseWriter, r *http.Request, err error) {
	var errMsg string
	if err != nil {
		errMsg = err.Error()
	}
	log.Error(fmt.Sprintf("%d %s %s %s", code, r.Method, r.URL.Path, errMsg))
	if w == nil {
		log.Debug("Socket error, no response to send")
		return
	}
	continueErrHandler := true
	if p.errorTarget != "" {
		err := p.handleErrorTarget(code, kind, w, r)
		continueErrHandler = err != nil
		if err != nil {
			log.Error(err.Error())
		}
	}
	if continueErrHandler {
		err := p.handleErrorPath(code, kind, w, r)
		continueErrHandler = err != nil
		if err != nil {
			log.Error(err.Error())
		}
	}
	if continueErrHandler {
		w.WriteHeader(code)
		w.Write([]byte(http.StatusText(code)))
	}
}

func (p *ConfigurableProxy) handleErrorTarget(code int, kind string, w http.ResponseWriter, r *http.Request) error {
	urlSpec, err := url.Parse(p.errorTarget)
	// error request is $errorTarget/$code?url=$requestUrl
	if err != nil {
		return fmt.Errorf("failed to parse error target: %w", err)
	}
	qs := url.Values{}
	qs.Set("url", r.RequestURI)
	urlSpec.RawQuery = qs.Encode()
	if strings.HasSuffix(urlSpec.Path, "/") {
		urlSpec.Path = urlSpec.Path + strconv.Itoa(code)
	} else {
		urlSpec.Path = urlSpec.Path + "/" + strconv.Itoa(code)
	}
	log.Debug(fmt.Sprintf("Requesting custom error page: %s", urlSpec.String()))

	// todo client ssl
	req, err := http.NewRequestWithContext(r.Context(), "GET", urlSpec.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to new request for error target: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to get custom error page: %w", err)
	}
	defer resp.Body.Close()
	for _, name := range []string{"Content-Type", "Content-Encoding"} {
		if value := resp.Header.Get(name); value != "" {
			w.Header().Set(name, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read custom error page and write response: %w", err)
	}
	return nil
}

func (p *ConfigurableProxy) handleErrorPath(code int, kind string, w http.ResponseWriter, r *http.Request) error {
	filename := strconv.Itoa(code) + ".html"
	bytes, err := p.getErrorFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			log.Debug("No error file " + filename)
			filename = "error.html"
			bytes, err = p.getErrorFile(filename)
			if err != nil {
				if os.IsNotExist(err) {
					return fmt.Errorf("No error file " + filename)
				}
				return fmt.Errorf("error reading %s %w", filename, err)
			}
		} else {
			return fmt.Errorf("error reading %s %w", filename, err)
		}
	}

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(code)
	w.Write(bytes)
	return nil
}

// getErrorFile reads a file from the errorPath or the DefaultErrorPath.
func (p *ConfigurableProxy) getErrorFile(name string) ([]byte, error) {
	if p.errorPath != "" {
		fullpath := filepath.Join(p.errorPath, name)
		return os.ReadFile(fullpath)
	}
	return DefaultErrorPath.ReadFile("error/" + name)
}

func (p *ConfigurableProxy) updateLastActivity(path string) {
	if _, ok := p.routes.Get(path); ok {
		p.routes.Update(path, map[string]any{"lastActivity": time.Now().Unix()})
	}
}

// add a route to the routing table
func (p *ConfigurableProxy) addRoute(path string, data map[string]any) {
	path = cleanPath(path)
	if p.hostRouting && path != "/" {
		index := strings.Index(path, "/")
		if index != -1 {
			data["host"] = path[index+1:]
		}
	}
	log.Info(fmt.Sprintf("Adding route %s -> %s", path, data["target"]))
	p.routes.Add(path, data)
	p.updateLastActivity(path)
	log.Info(fmt.Sprintf("Route added %s -> %s", path, data["target"]))
}

// remove a route from the routing table
func (p *ConfigurableProxy) removeRoute(path string) bool {
	if _, ok := p.routes.Get(path); ok {
		log.Info(fmt.Sprintf("Removing route %s", path))
		p.routes.Remove(path)
		return true
	}
	return false
}

// GET a single route
func (p *ConfigurableProxy) getRoute(path string) (map[string]any, bool) {
	route, exists := p.routes.Get(path)
	return route, exists
}

// GET /api/routes/(path) gets a single route
func (p *ConfigurableProxy) getRoutes(inactiveSince int64) map[string]map[string]any {
	routes := p.routes.GetAll()
	if inactiveSince == 0 {
		return routes
	}
	result := make(map[string]map[string]any, len(routes))
	for path, route := range routes {
		lastActivity, exist := route["lastActivity"]
		if !exist {
			continue
		}
		if unix, ok := lastActivity.(int64); ok && unix < inactiveSince {
			result[path] = route
		}
	}
	return result
}

// return config target for a given url path
func (p *ConfigurableProxy) targetForReq(host, path string) (target proxy.Target, exists bool) {
	basePath := ""
	if p.hostRouting {
		basePath = "/" + host
	}
	fullpath := basePath + path
	urlTrie := p.routes.GetTarget(fullpath)
	if urlTrie == nil {
		return
	}
	target.Target = urlTrie.data.(map[string]any)["target"].(string)
	target.Prefix = urlTrie.prefix
	exists = true
	return target, exists
}

package cmd

import (
	"context"
	"fmt"
	"github.com/potoo0/configurable-http-proxy/lib"
	"github.com/spf13/cobra"
	log "log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
)

type listenerConfig struct {
	port         int
	ip           string
	apiIp        string
	apiPort      int
	metricsIp    string
	metricsPort  int
	redirectPort int
	redirectTo   int
}

var (
	listenerCfg listenerConfig

	sslKey                string
	sslCert               string
	sslCa                 string
	sslRequestCert        bool
	sslRejectUnauthorized bool

	sslProtocol string
	sslCiphers  string
	sslAllowRc4 bool
	sslDhparam  string

	// api args
	apiSslKey                string
	apiSslCert               string
	apiSslCa                 string
	apiSslRequestCert        bool
	apiSslRejectUnauthorized bool

	// client args
	clientSslKey                string
	clientSslCert               string
	clientSslCa                 string
	clientSslRequestCert        bool
	clientSslRejectUnauthorized bool

	defaultTarget string
	errorTarget   string
	errorPath     string
	pidFile       string

	noXForward      bool
	noPrependPath   bool
	noIncludePrefix bool
	autoRewrite     bool
	changeOrigin    bool
	protocolRewrite string
	customHeader    []string
	insecure        bool
	hostRouting     bool

	logLevel         string
	timeout          int
	proxyTimeout     int
	storageBackend   string
	keepAliveTimeout int
)

// configurable-http-proxy main command
var rootCmd = &cobra.Command{
	Use: "configurable-http-proxy",
	Long: `configurable-http-proxy (CHP) provides you with a way to update and manage a proxy table
using a command line interface or REST API. It is a simple wrapper around httputil.ReverseProxy.
httputil.ReverseProxy is an HTTP programmable proxying library that supports websockets and
is suitable for implementing components such as reverse proxies and load balancers.
By wrapping httputil.ReverseProxy, configurable-http-proxy extends this functionality to JupyterHub deployments.
Support env CONFIGPROXY_SSL_KEY_PASSPHRASE and CONFIGPROXY_API_SSL_KEY_PASSPHRASE to set passphrase for SSL key,
and CONFIGPROXY_AUTH_TOKEN to set a token for REST API authentication.`,
	Run: run,
}

func run(cmd *cobra.Command, args []string) {
	options := initConfig()

	proxy := lib.NewConfigurableProxy(options)
	go listen(options.Ssl, listenerCfg.ip, listenerCfg.port, proxy.ProxyServer.Handler())
	go listen(options.ApiSsl, listenerCfg.apiIp, listenerCfg.apiPort, proxy.ApiServer.Handler())

	log.Info(fmt.Sprintf("Proxying %s://%s:%d to %s", schema(options.Ssl),
		defaultIfEmpty(listenerCfg.ip, "*"), listenerCfg.port,
		defaultIfEmpty(options.DefaultTarget, "(no default)")))
	log.Info(fmt.Sprintf("Proxy API at %s://%s:%d/api/routes", schema(options.Ssl),
		defaultIfEmpty(listenerCfg.apiIp, "*"), listenerCfg.apiPort))
	if listenerCfg.metricsPort != 0 {
		log.Warn(fmt.Sprintf("Metrics server not implemented yet"))
		//log.Info(fmt.Sprintf("Serve metrics at %s://%s:%d/metrics", "http", listenerCfg.metricsIp, listenerCfg.metricsPort))
	}

	if pidFile != "" {
		if err := writePidFile(pidFile); err != nil {
			log.Warn(fmt.Sprintf("write pid file error: %v", err))
		}
	}

	// Redirect HTTP to HTTPS on the proxy's port
	if listenerCfg.redirectPort != 0 && listenerCfg.port != 80 {
		redirectPortDst := listenerCfg.redirectTo
		if redirectPortDst == 0 {
			redirectPortDst = listenerCfg.port
		}
		go listen(nil, "", listenerCfg.redirectPort, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Host == "" {
				msg := fmt.Sprintf("This server is HTTPS-only on port %d, but an HTTP request was made and the host could not be determined from the request.",
					redirectPortDst)
				http.Error(w, msg, http.StatusBadRequest)
				return
			}
			host, _, err := net.SplitHostPort(r.Host)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if redirectPortDst != 443 {
				host = host + ":" + strconv.Itoa(redirectPortDst)
			}
			w.Header().Set("Location", "https://"+host+r.RequestURI)
			w.WriteHeader(http.StatusMovedPermanently)
		}))
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	cleanup()
}

func cleanup() {
	if pidFile != "" {
		os.Remove(pidFile)
	}
}

func defaultIfEmpty(s, d string) string {
	if s != "" {
		return s
	}
	return d
}

func schema(ssl *lib.SslConfig) string {
	if ssl == nil {
		return "https"
	}
	return "http"
}

func listen(ssl *lib.SslConfig, ip string, port int, handler http.Handler) {
	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", ip, port),
		Handler: handler,
	}
	// todo
	//if ssl != nil {
	//	server.TLSConfig = &tls.Config{}
	//}
	if err := server.ListenAndServe(); err != nil {
		panic(err)
	}
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// listener args
	rootCmd.Flags().StringVar(&listenerCfg.ip, "ip", "", "Public-facing IP of the proxy")
	rootCmd.Flags().IntVar(&listenerCfg.port, "port", 8000, "Public-facing port of the proxy")
	rootCmd.Flags().StringVar(&listenerCfg.apiIp, "api-ip", "localhost", "Inward-facing IP for API requests")
	rootCmd.Flags().IntVar(&listenerCfg.apiPort, "api-port", 0, "Inward-facing port for API requests (defaults to --port=value+1)")
	rootCmd.Flags().StringVar(&listenerCfg.metricsIp, "metrics-ip", "", "IP for metrics server")
	rootCmd.Flags().IntVar(&listenerCfg.metricsPort, "metrics-port", 0, "Port of metrics server. Defaults to no metrics server")
	rootCmd.Flags().IntVar(&listenerCfg.redirectPort, "redirect-port", 0, "Redirect HTTP requests on this port to the server on HTTPS")
	rootCmd.Flags().IntVar(&listenerCfg.redirectTo, "redirect-to", 0, "Redirect HTTP requests from --redirect-port to this port")

	// ssl
	rootCmd.Flags().StringVar(&sslKey, "ssl-key", "", "SSL key to use, if any")
	rootCmd.Flags().StringVar(&sslCert, "ssl-cert", "", "SSL certificate to use, if any")
	rootCmd.Flags().StringVar(&sslCa, "ssl-ca", "", "SSL certificate authority, if any")
	rootCmd.Flags().BoolVar(&sslRequestCert, "ssl-request-cert", false, "Request SSL certs to authenticate clients")
	rootCmd.Flags().BoolVar(&sslRejectUnauthorized, "ssl-reject-unauthorized", false,
		"Reject unauthorized SSL connections (only meaningful if --ssl-request-cert is given)")

	rootCmd.Flags().StringVar(&sslProtocol, "ssl-protocol", "", "Set specific SSL protocol, e.g. TLSv1_2, SSLv3")
	rootCmd.Flags().StringVar(&sslCiphers, "ssl-ciphers", "", ":-separated ssl cipher list. Default excludes RC4")
	rootCmd.Flags().BoolVar(&sslAllowRc4, "ssl-allow-rc4", false, "Allow RC4 cipher for SSL (disabled by default)")
	rootCmd.Flags().StringVar(&sslDhparam, "ssl-dhparam", "", "SSL Diffie-Hellman Parameters pem file, if any")

	// ssl - api
	rootCmd.Flags().StringVar(&apiSslKey, "api-ssl-key", "", "SSL key to use, if any, for API requests")
	rootCmd.Flags().StringVar(&apiSslCert, "api-ssl-cert", "", "SSL certificate to use, if any, for API requests")
	rootCmd.Flags().StringVar(&apiSslCa, "api-ssl-ca", "", "SSL certificate authority, if any, for API requests")
	rootCmd.Flags().BoolVar(&apiSslRequestCert, "api-ssl-request-cert", false, "Request SSL certs to authenticate clients for API requests")
	rootCmd.Flags().BoolVar(&apiSslRejectUnauthorized, "api-ssl-reject-unauthorized", false,
		"Reject unauthorized SSL connections for API requests (only meaningful if --api-ssl-request-cert is given)")

	// ssl - client
	rootCmd.Flags().StringVar(&clientSslKey, "client-ssl-key", "", "SSL key to use, if any, for proxy to client requests")
	rootCmd.Flags().StringVar(&clientSslCert, "client-ssl-cert", "", "SSL certificate to use, if any, for proxy to client requests")
	rootCmd.Flags().StringVar(&clientSslCa, "client-ssl-ca", "", "SSL certificate authority, if any, for proxy to client requests")
	rootCmd.Flags().BoolVar(&clientSslRequestCert, "client-ssl-request-cert", false, "Request SSL certs to authenticate clients for proxy to client requests")
	rootCmd.Flags().BoolVar(&clientSslRejectUnauthorized, "client-ssl-reject-unauthorized", false,
		"Reject unauthorized SSL connections for proxy to client requests (only meaningful if --client-ssl-request-cert is given)")

	rootCmd.Flags().StringVar(&defaultTarget, "default-target", "", "Default proxy target (proto://host[:port])")
	rootCmd.Flags().StringVar(&errorTarget, "error-target", "", "Alternate server for handling proxy errors (proto://host[:port])")
	rootCmd.Flags().StringVar(&errorPath, "error-path", "", "Alternate server for handling proxy errors (proto://host[:port])")
	rootCmd.Flags().StringVar(&pidFile, "pid-file", "", "Write our PID to a file")

	// pass-through http-proxy options
	rootCmd.Flags().BoolVar(&noXForward, "no-x-forward", false, "Don't add 'X-forward-' headers to proxied requests")
	rootCmd.Flags().BoolVar(&noPrependPath, "no-prepend-path", false, "Avoid prepending target paths to proxied request")
	rootCmd.Flags().BoolVar(&noIncludePrefix, "no-include-prefix", false, "Don't include the routing prefix in proxied requests")
	rootCmd.Flags().BoolVar(&autoRewrite, "auto-rewrite", false, "Rewrite the Location header host/port in redirect responses")
	rootCmd.Flags().BoolVar(&changeOrigin, "change-origin", false, "Changes the origin of the host header to the target URL")
	rootCmd.Flags().StringVar(&protocolRewrite, "protocol-rewrite", "", "Rewrite the Location header protocol in redirect responses to the specified protocol")
	rootCmd.Flags().StringSliceVar(&customHeader, "custom-header", []string{},
		"Custom header to add to proxied requests. Use same option for multiple headers (--custom-header k1:v1 --custom-header k2:v2)")

	rootCmd.Flags().BoolVar(&insecure, "insecure", false, "Disable SSL cert verification")
	rootCmd.Flags().BoolVar(&hostRouting, "host-routing", false, "Use host routing (host as first level of path)")

	rootCmd.Flags().StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	rootCmd.Flags().IntVar(&timeout, "timeout", 0, "Timeout (in millis) when proxy drops connection for a request.")
	rootCmd.Flags().IntVar(&proxyTimeout, "proxy-timeout", 0, "Timeout (in millis) when proxy receives no response from target.")
	rootCmd.Flags().StringVar(&storageBackend, "storage-backend", "", "Define an external storage class. Defaults to in-MemoryStore.")
	rootCmd.Flags().IntVar(&keepAliveTimeout, "keep-alive-timeout", 0, "Set timeout (in milliseconds) for Keep-Alive connections")
}

// initConfig will panic if args illegal
func initConfig() *lib.Config {
	cfg := new(lib.Config)
	level, err := lib.ParseLevel(logLevel)
	if err != nil {
		panic(fmt.Errorf("invalid log level, %s", err))
	}
	lib.InitLogger(os.Stdout, level)

	// ssl cipher
	if sslCiphers == "" {
		var rc4 = "!RC4"
		if sslAllowRc4 {
			rc4 = "RC4"
		}
		sslCiphers = strings.Join(lib.DefaultSslCiphers, ":") + ":" + rc4
	}

	// ssl cfg
	if sslKey != "" || sslCert != "" {
		cfg.Ssl = new(lib.SslConfig)
		if sslKey != "" {
			cfg.Ssl.Key = readFilePanicIfErr(sslKey)
			cfg.Ssl.Passphrase = os.Getenv("CONFIGPROXY_SSL_KEY_PASSPHRASE")
		}
		cfg.Ssl.Cert = readFilePanicIfErr(sslCert)
		cfg.Ssl.Ca = readFilePanicIfErr(sslCa)
		cfg.Ssl.Dhparam = readFilePanicIfErr(sslDhparam)
		if sslProtocol != "" {
			cfg.Ssl.SecureProtocol = sslProtocol + "_method"
		}
		cfg.Ssl.Ciphers = sslCiphers
		cfg.Ssl.HonorCipherOrder = true
		cfg.Ssl.RequestCert = sslRequestCert
		cfg.Ssl.RejectUnauthorized = sslRejectUnauthorized
	}

	// ssl cfg for the API interface
	if apiSslKey != "" || apiSslCert != "" {
		cfg.ApiSsl = new(lib.SslConfig)
		if apiSslKey != "" {
			cfg.ApiSsl.Key = readFilePanicIfErr(apiSslKey)
			cfg.ApiSsl.Passphrase = os.Getenv("CONFIGPROXY_API_SSL_KEY_PASSPHRASE")
		}
		cfg.ApiSsl.Cert = readFilePanicIfErr(apiSslCert)
		cfg.ApiSsl.Ca = loadSslCa(apiSslCa)
		cfg.ApiSsl.Dhparam = readFilePanicIfErr(sslDhparam)
		if sslProtocol != "" {
			cfg.ApiSsl.SecureProtocol = sslProtocol + "_method"
		}
		cfg.ApiSsl.Ciphers = sslCiphers
		cfg.ApiSsl.HonorCipherOrder = true
		cfg.ApiSsl.RequestCert = apiSslRequestCert
		cfg.ApiSsl.RejectUnauthorized = apiSslRejectUnauthorized
	}

	// ssl cfg for the client interface
	if clientSslKey != "" || clientSslCert != "" || clientSslCa != "" {
		cfg.ClientSsl = new(lib.SslConfig)
		cfg.ClientSsl.Key = readFilePanicIfErr(clientSslKey)
		cfg.ClientSsl.Cert = readFilePanicIfErr(clientSslCert)
		cfg.ClientSsl.Ca = loadSslCa(clientSslCa)
		cfg.ClientSsl.Dhparam = readFilePanicIfErr(sslDhparam)
		if sslProtocol != "" {
			cfg.ClientSsl.SecureProtocol = sslProtocol + "_method"
		}
		cfg.ClientSsl.Ciphers = sslCiphers
		cfg.ClientSsl.HonorCipherOrder = true
		cfg.ClientSsl.RequestCert = clientSslRequestCert
		cfg.ClientSsl.RejectUnauthorized = clientSslRejectUnauthorized
	}

	cfg.DefaultTarget = defaultTarget
	cfg.ErrorTarget = errorTarget
	cfg.ErrorPath = errorPath
	cfg.HostRouting = hostRouting
	cfg.AuthToken = os.Getenv("CONFIGPROXY_AUTH_TOKEN")
	cfg.Headers = headersMap(customHeader)
	cfg.Timeout = timeout
	cfg.ProxyTimeout = proxyTimeout
	cfg.KeepAliveTimeout = keepAliveTimeout

	// metrics cfg
	cfg.EnableMetrics = listenerCfg.metricsPort != 0

	// certs need to be provided for https redirection
	if cfg.Ssl == nil && listenerCfg.redirectPort != 0 {
		panic("HTTPS redirection specified but certificates not provided")
	}

	if cfg.ErrorTarget != "" && cfg.ErrorPath != "" {
		panic("Cannot specify both error-target and error-path. Pick one.")
	}

	// pass-through for http-cfg cfg
	cfg.Secure = !insecure
	cfg.Xfwd = !noXForward
	cfg.PrependPath = !noPrependPath
	cfg.IncludePrefix = !noIncludePrefix
	if autoRewrite {
		cfg.AutoRewrite = autoRewrite
		log.Info("AutoRewrite of Location headers enabled.")
	}
	if changeOrigin {
		cfg.ChangeOrigin = changeOrigin
		log.Info("Change Origin of host headers enabled.")
	}
	if protocolRewrite != "" {
		cfg.ProtocolRewrite = protocolRewrite
		log.Info("ProtocolRewrite enabled. Rewriting to " + cfg.ProtocolRewrite)
	}

	if cfg.AuthToken == "" {
		log.Warn("REST API is not authenticated.")
	}

	// external backend class
	cfg.StorageBackend = storageBackend

	// listener cfg
	if listenerCfg.port == 0 {
		listenerCfg.port = 8000
	}
	if listenerCfg.ip == "*" {
		// handle ip=* alias for all interfaces
		log.Warn(
			"Interpreting ip='*' as all-interfaces. Preferred usage is 0.0.0.0 for all IPv4 or '' for all-interfaces.",
		)
		listenerCfg.ip = ""
	}
	if listenerCfg.apiPort == 0 {
		listenerCfg.apiPort = listenerCfg.port + 1
	}

	return cfg
}

func readFilePanicIfErr(name string) []byte {
	if name == "" {
		return nil
	}
	bytes, err := os.ReadFile(name)
	if err != nil {
		panic(err)
	}
	return bytes
}

func loadSslCa(name string) []byte {
	if name == "" {
		return nil
	}
	return nil
}

func headersMap(headers []string) map[string]string {
	m := make(map[string]string)
	for _, header := range headers {
		k, v, found := strings.Cut(header, ":")
		if !found {
			panic("A colon was expected in custom header: " + header)
		}
		m[k] = v
	}
	return m
}

func writePidFile(pidFile string) error {
	// Read in the pid file
	if pidRaw, err := os.ReadFile(pidFile); err == nil {
		// Convert the file contents to an integer.
		if pid, err := strconv.Atoi(string(pidRaw)); err == nil {
			// Look for the pid in the process list.
			if process, err := os.FindProcess(pid); err == nil {
				// Send the process a signal zero kill.
				if err := process.Signal(syscall.Signal(0)); err == nil {
					// We only get an error if the pid isn't running, or it's not ours.
					return fmt.Errorf("pid already running: %d", pid)
				}
			}
		}
	}
	// If we get here, then the pidfile didn't exist,
	// or the pid in it doesn't belong to the user running this app.
	return os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", os.Getpid())), 0664)
}

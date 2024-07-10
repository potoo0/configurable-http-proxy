package lib

import (
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/pem"
	"fmt"
	"github.com/youmark/pkcs8"
	log "log/slog"
	"strings"
)

var DefaultSslCiphers = []string{
	"ECDHE-RSA-AES128-GCM-SHA256",
	"ECDHE-ECDSA-AES128-GCM-SHA256",
	"ECDHE-RSA-AES256-GCM-SHA384",
	"ECDHE-ECDSA-AES256-GCM-SHA384",
	"DHE-RSA-AES128-GCM-SHA256",
	"ECDHE-RSA-AES128-SHA256",
	"DHE-RSA-AES128-SHA256",
	"ECDHE-RSA-AES256-SHA384",
	"DHE-RSA-AES256-SHA384",
	"ECDHE-RSA-AES256-SHA256",
	"DHE-RSA-AES256-SHA256",
	"HIGH",
	"!aNULL",
	"!eNULL",
	"!EXPORT",
	"!DES",
	"!RC4",
	"!MD5",
	"!PSK",
	"!SRP",
	"!CAMELLIA",
}

// DefaultErrorPath read file by ReadFile("error/<filename>")
//
//go:embed error
var DefaultErrorPath embed.FS

type Config struct {
	Ssl       *SslConfig
	ApiSsl    *SslConfig
	ClientSsl *SslConfig

	AuthToken     string
	DefaultTarget string
	ErrorTarget   string
	ErrorPath     string
	HostRouting   bool

	IncludePrefix   bool
	Headers         map[string]string
	Secure          bool
	Xfwd            bool
	PrependPath     bool
	AutoRewrite     bool
	ChangeOrigin    bool
	ProtocolRewrite string
	ProxyTimeout    int

	Timeout          int
	KeepAliveTimeout int

	EnableMetrics  bool
	StorageBackend string
}

type SslConfig struct {
	// Private Key in PEM format
	Key []byte

	// Passphrase used for a single private key and/or a PFX.
	Passphrase string

	// Cert chains in PEM format.
	Cert []byte

	// Optionally override the trusted CA certificates
	Ca []byte

	// Diffie-Hellman parameters
	Dhparam []byte

	// use 'TLSvX_X' to force TLS version X.X
	SecureProtocol string

	// cipher suites specification
	Ciphers string

	// Attempt to use the server's cipher suite preferences instead of the client's.
	HonorCipherOrder bool

	// true to specify whether a server should request a certificate from a connecting client.
	RequestCert bool

	// If not false a server automatically reject clients with invalid certificates.
	RejectUnauthorized bool
}

// TlsConfig returns a tls.Config instance based on the sslCfg.
func (cfg *SslConfig) TlsConfig(isServer bool) (*tls.Config, error) {
	tlsConfig := &tls.Config{}
	var certificates []tls.Certificate
	if cfg.Key != nil && cfg.Cert != nil {
		keyPEM, err := parseKeyPEM(cfg.Key, cfg.Passphrase)
		if err != nil {
			return nil, err
		}
		cert, err := tls.X509KeyPair(cfg.Cert, keyPEM)
		if err != nil {
			return nil, err
		}
		certificates = []tls.Certificate{cert}
		tlsConfig.Certificates = certificates
	}

	if cfg.Ca != nil {
		certPool := x509.NewCertPool()
		certPool.AppendCertsFromPEM(cfg.Ca)
		if isServer {
			tlsConfig.ClientCAs = certPool
			tlsConfig.ClientAuth = parseClientAuth(cfg.RequestCert, cfg.RejectUnauthorized)
		} else {
			tlsConfig.RootCAs = certPool
		}
	}
	// for security, skip setup ca
	//else if certificates != nil {
	//	certificate, err := x509.ParseCertificate(certificates[0].Certificate[0])
	//	if err != nil {
	//		return nil, err
	//	}
	//	certPool.AddCert(certificate)
	//}

	if cfg.Dhparam != nil {
		log.Warn("Dhparam is not supported, ignored")
	}

	if cfg.Ciphers != "" {
		suites, unsupported := parseCipherSuites(cfg.Ciphers)
		if len(unsupported) > 0 {
			log.Warn(fmt.Sprintf("Unsupported ciphers: %v", unsupported))
		}
		if len(suites) > 0 {
			log.Warn("using golang's default cipher suites")
			//TlsConfig.CipherSuites = suites
		}
	}
	if cfg.SecureProtocol != "" {
		ver := parseSSLProtocolMethods(cfg.SecureProtocol)
		tlsConfig.MaxVersion = ver
		tlsConfig.MinVersion = ver
	}
	if cfg.HonorCipherOrder {
		// doc: https://go.dev/blog/tls-cipher-suites
		log.Warn("HonorCipherOrder ignored, because PreferServerCipherSuites is Deprecated")
	}

	// client config
	//InsecureSkipVerify: true,
	return tlsConfig, nil
}

func parseClientAuth(requestCert, rejectUnauthorized bool) tls.ClientAuthType {
	if requestCert {
		if rejectUnauthorized {
			return tls.VerifyClientCertIfGiven
		} else {
			return tls.RequestClientCert
		}
	}
	return tls.NoClientCert
}

// parseCipherSuites parse ciphers from string,
// returns a list of cipher suite IDs and a list of unsupported ciphers.
func parseCipherSuites(ciphers string) ([]uint16, []string) {
	suiteToMap := func(suites []*tls.CipherSuite, dst map[string]uint16) {
		for _, suite := range suites {
			dst[suite.Name] = suite.ID
		}
	}
	suitesByName := make(map[string]uint16, 32)
	suiteToMap(tls.CipherSuites(), suitesByName)
	suiteToMap(tls.InsecureCipherSuites(), suitesByName)

	suitesRaw := strings.Split(ciphers, ":")
	suitesRawUnsupported := make([]string, 0, len(suitesRaw))
	suiteIds := make([]uint16, 0, len(suitesRaw))
	for _, suite := range suitesRaw {
		unsupported := true
		if !strings.HasPrefix(suite, "!") {
			suiteRaw := convertCipherSuiteName(suite)
			if id, exists := suitesByName[suiteRaw]; exists {
				suiteIds = append(suiteIds, id)
				unsupported = false
			}
		}

		if unsupported {
			suitesRawUnsupported = append(suitesRawUnsupported, suite)
		}
	}

	return suiteIds, suitesRawUnsupported
}

// convertCipherSuiteName convert nodejs cipher suite name to the format used by Go.
func convertCipherSuiteName(name string) string {
	name = strings.Replace(name, "-", "_", -1)
	name = strings.Replace(name, "AES128", "AES_128", 1)
	name = strings.Replace(name, "AES256", "AES_256", 1)
	if !strings.HasPrefix(name, "TLS_") {
		name = "TLS_" + name
	}
	for _, prefix := range []string{"TLS_RSA_", "TLS_ECDHE_RSA_", "TLS_ECDHE_ECDSA_", "TLS_DHE_RSA_"} {
		if strings.HasPrefix(name, prefix) {
			name = strings.Replace(name, prefix, prefix+"WITH_", 1)
			break
		}
	}
	return name
}

func parseSSLProtocolMethods(secureProtocol string) uint16 {
	if strings.EqualFold(secureProtocol, "TLSv1_1") {
		return tls.VersionTLS11
	} else if strings.EqualFold(secureProtocol, "TLSv1_2") {
		return tls.VersionTLS12
	} else if strings.EqualFold(secureProtocol, "TLSv1_3") {
		return tls.VersionTLS13
	}
	return 0
}

// parseKeyPEM read and decrypt key, returns PEM-encoded bytes.
// Only support PKCS8!!!
func parseKeyPEM(bytes []byte, password string) ([]byte, error) {
	// read key and try decrypt
	keyBlockMayEnc, _ := pem.Decode(bytes)
	if keyBlockMayEnc == nil {
		return nil, fmt.Errorf("failed to decode PEM data")
	}
	keyBlock, err := pkcs8.ParsePKCS8PrivateKey(keyBlockMayEnc.Bytes, []byte(password))
	if err != nil {
		return nil, err
	}
	keyBytes, err := pkcs8.MarshalPrivateKey(keyBlock, nil, nil)
	if err != nil {
		return nil, err
	}
	// key bytes to pem encode
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}), nil
}

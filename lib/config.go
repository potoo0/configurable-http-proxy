package lib

import "embed"

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
	Key                []byte
	Passphrase         string
	Cert               []byte
	Ca                 []byte
	Dhparam            []byte
	SecureProtocol     string
	Ciphers            string
	RequestCert        bool
	HonorCipherOrder   bool
	RejectUnauthorized bool
}

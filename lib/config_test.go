package lib

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCipherSuites(t *testing.T) {
	ciphers := strings.Join(DefaultSslCiphers, ":")
	suites, unsupported := parseCipherSuites(ciphers)
	t.Log("WARN: cipher suite IDs: ", suites)
	if len(unsupported) > 0 {
		t.Log("WARN: Unsupported ciphers: ", unsupported)
	}
}

func TestTlsConfig_Ca(t *testing.T) {
	cfg := SslConfig{
		Key:        LocalhostKey,
		Passphrase: "1234",
		Cert:       LocalhostCert,
	}

	// build server
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// t.Logf("http request uri: %s", r.RequestURI)
		w.WriteHeader(http.StatusOK)
	})
	server := httptest.NewUnstartedServer(handler)
	tlsConfig, err := cfg.TLSConfig(true)
	require.NoError(t, err)
	server.TLS = tlsConfig
	server.StartTLS()
	defer server.Close()

	t.Run("without-ca", func(t *testing.T) {
		cfg.Ca = nil
		tlsConfig, err = cfg.TLSConfig(false)
		require.NoError(t, err)

		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = tlsConfig
		client := &http.Client{Transport: transport}

		req, _ := http.NewRequest(http.MethodGet, server.URL+"/a", nil)
		_, err := client.Do(req)
		require.Error(t, err)

		var (
			urlError  *url.Error
			certError *tls.CertificateVerificationError
			caError   x509.UnknownAuthorityError
		)
		if assert.ErrorAs(t, err, &urlError) && assert.ErrorAs(t, urlError.Err, &certError) {
			assert.ErrorAs(t, certError.Err, &caError)
		}
	})
	t.Run("with-ca", func(t *testing.T) {
		cfg.Ca = RootCert
		tlsConfig, err = cfg.TLSConfig(false)
		require.NoError(t, err)

		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = tlsConfig
		client := &http.Client{Transport: transport}

		req, _ := http.NewRequest(http.MethodGet, server.URL+"/a", nil)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
	})
}

func TestTlsConfig_SecureProtocol(t *testing.T) {
	cfg := SslConfig{
		Key:            LocalhostKey,
		Passphrase:     "1234",
		Cert:           LocalhostCert,
		Ca:             RootCert,
		SecureProtocol: "TLSv1_2",
	}

	// build server
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// t.Logf("http request uri: %s", r.RequestURI)
		w.WriteHeader(http.StatusOK)
	})
	server := httptest.NewUnstartedServer(handler)
	tlsConfig, err := cfg.TLSConfig(true)
	require.NoError(t, err)
	server.TLS = tlsConfig
	server.StartTLS()
	defer server.Close()

	t.Run("client-default", func(t *testing.T) {
		cfg.SecureProtocol = ""
		tlsConfig, err = cfg.TLSConfig(false)
		require.NoError(t, err)

		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = tlsConfig
		client := &http.Client{Transport: transport}

		req, _ := http.NewRequest(http.MethodGet, server.URL+"/a", nil)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
	})
	t.Run("client-tls1.1", func(t *testing.T) {
		cfg.SecureProtocol = "TLSv1_1"
		tlsConfig, err = cfg.TLSConfig(false)
		require.NoError(t, err)

		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = tlsConfig
		client := &http.Client{Transport: transport}

		req, _ := http.NewRequest(http.MethodGet, server.URL+"/a", nil)
		_, err = client.Do(req)
		assert.ErrorContains(t, err, "remote error: tls: protocol version not supported")
	})
}

/*
## 1. create cert
## 1. create cert
openssl genpkey -algorithm RSA -out domain.key -des3 -pkeyopt rsa_keygen_bits:2048 -pass pass:1234
openssl req -key domain.key -new -out domain.csr -subj "/CN=api.test.io" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
#openssl x509 -signkey domain.key -in domain.csr -req -days 365 -out domain.crt
## openssl req -new -x509 -days 365 -key domain.key -out domain.crt -subj "/CN=api.test.io" -addext "subjectAltName=DNS:api.test.io,IP:127.0.0.1"

## 2. creating ca
openssl genpkey -algorithm RSA -out rootca.key -pkeyopt rsa_keygen_bits:2048
#openssl genpkey -algorithm RSA -out rootca.key -aes256 -pkeyopt rsa_keygen_bits:2048 -pass pass:1234
openssl req -new -x509 -days 36500 -key rootca.key -out rootca.crt -subj "/CN=root"

## 3. sign csr with root ca
openssl x509 -req -in domain.csr -CA rootca.crt -CAkey rootca.key -CAcreateserial -out domain.crt -days 36500 -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1")

## verify certificate
openssl x509 -in domain.crt -text -noout
*/
var (
	LocalhostKey = []byte(`-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFJDBWBgkqhkiG9w0BBQ0wSTAxBgkqhkiG9w0BBQwwJAQQn5LWNYXzOfKRe6XS
cRoVEQICCAAwDAYIKoZIhvcNAgkFADAUBggqhkiG9w0DBwQIdonmFW8NzywEggTI
JaelXmG/0nf2/aQeW2g3A5unbEguQdyXK51Fz5arsLAi4Y0DZj1ju/Y2K6c01kSv
cFl60dwy7T02hQ4caUrX1GPAV/Jz+FLoOqKjujOJVSGKXJenYnZQQvaclxJ2ly14
NonptP69bSRPbzuqWplSLZ8j1BJdJ557NTRCCc7eaFFwPwA70MLOc2g4jxT/8x0a
yOTRAFCUIMBZU/MrYDhA/+MlH+j7dSoIBRiypqNfcirYZ9ISGBxPWBZgAlpCkuV7
2phTen+Zi0p+UIUzTQupbN2jNbyCCNqfIwdxQxAPq2WeEvGQWnwN8pYSoJiaZD7a
hxtQ9XJVTmN56QaJQjRgwP1EbdeIYrzNwiLW/PqJnjFvVjEtFabJKkyHHu0NApSm
dsCi7695bR7CE3+IGdKDkr+ZbfD0yFbO8AAiGRVpJ/XEqqNYnO9J6u1XobBCvJz5
+f/FFZj9GH3QRbkWsvVl7seLElXiv/7reMqtpe+pQGg0whVfB+Dvy5925dLlKIdn
BrPmLWioQ/U9c0ORrq1HP8D9ydblwtxUfIBVkwpkUmlyznmBUbToUXfptstyg1d4
WiWeqcLLBHYu/CH91nMGTUzGNftr4uu55Bl2cGweYt2PWgyL43caEpf7j83lWdMq
hlBxKJu+V/5P+f2pz0g0G9JCH11n52UHTyLPna4Y2vkK85K5AcdczVRH6KlZg34Q
TrtZcmwjC40mbJO/Yjg6OFZO1NV/EzKcNNietA0gDY6St5vfEngWTf3QkDC+ZKmF
KMPsKip/X9CWZE7vVe10CpPAQ3NWLRaPRA7j5bEC4CS07G9VPlMFCvLa+nm1PZzC
TsmGZYSRqAsgGu0cNJRn5OM71qMVEOEzgluBt6nGmVK9XSeuryAonkaCPbMPqTkg
ImaawKCjUrVvXF/5swZLqq/IFeY5vDVNfIiV6GdY63qkjVwU7ZimXHT3hukI8cvL
jMTXKNRE8Bc/h7QyERv/aHyuOXY5vgY3/GB/HoQwKlim8Fl3hrwf+T/zzTxLqMv6
U0DJlb5N5ReQHFqkdksHoojEFdfNFWD79MJtw9En+pjT5CCyjIyX5w/CvnjPoBK0
AZbq5hyqbT1mgfcfzK6NkMPj0Vnp11Dh72sNIIl9NmcjNXwyo2y7lxbmDBbF+hi6
t9CNZxyqdXNZgtDgpJI19DvvDJkLFgyGD1lycQ6yNj9byhCP6P0MxD8ZvxpvwoMF
ENPLlCXrrRSxSmwlFpQAkamKKxr+rq4WQWssoKXdCISPYRJtTbBuAvPkvecr0FY0
Hz55Yac2hm7ChBdAJbSlcfaiNfJ1UYvXFpZzL4bQZAo0a7a2p1iRIospSq6wm9kG
2UiY1ylEhVZvpp2ptKGLzHoBJNgNcOa+9/CgkzuQxtB58NEFNZE4AMhduojxNH8W
BW1yg4fSQDZ9Udh9evrn4c7zzO6MTv+UmA1N5aGcSB9uC57lIoVX6nTcRgcaDwTo
pDPF5kTTTBEFTQks7Bs7z8r4nKQSYLB7BMQOKKQd1nbvG6l1p9AwZ1IBT39ZzizB
VgHeKrlQmYYBHrr5jcUhkkEjJzW2VQK6ex8luFav0f4krjDMPrEyjPFphXCe3a1F
YNSNEYjvKPGMB44d4G8OKjPZWN4rC32U
-----END ENCRYPTED PRIVATE KEY-----`)

	LocalhostCert = []byte(`-----BEGIN CERTIFICATE-----
MIIDEzCCAfugAwIBAgIUMc+HZfUkuZszHpe6IHqfFwcF7UkwDQYJKoZIhvcNAQEL
BQAwDzENMAsGA1UEAwwEcm9vdDAgFw0yNDA3MTAwMzE3MDVaGA8yMTI0MDYxNjAz
MTcwNVowFjEUMBIGA1UEAwwLYXBpLnRlc3QuaW8wggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQCSP7W9AwPRsbKmkoT0vbigv9D67PsmuPR76FCUlvFn9GO+
EeBA1APX2l19PV6cuLCZbDhkRttrZt8kIjDCDFWliLL3PsLvn9YAgcXfYXEgOESp
EHU8Czt5bDsskC7JefE7VPpvTa/MXN7YTkwUbDotvdAuNteBcEmkJMgvuddLVxy7
8i3Xn7yvNyxHCPUGCImn2NvObk64e98yZe63edWo3zUy9WB5uYMCHCtwzwHkkdB2
sakPg1+e9lDFN2pXy3RseKtE+lpyU1xngGDx5lq6Dk4nwGMtwKmEHNXC74KPj+zh
UNTx8E9DtYA3A8DRdSeZD4bvlnou1PYxIFuN1FOTAgMBAAGjXjBcMBoGA1UdEQQT
MBGCCWxvY2FsaG9zdIcEfwAAATAdBgNVHQ4EFgQUoM5Rkcf7ZMB4pBWAZh6AOILq
mV8wHwYDVR0jBBgwFoAUxo4zh65AP5KaR1YwhpJ6eApfoRkwDQYJKoZIhvcNAQEL
BQADggEBAAclap6nGTXBtGWiDz2P3cpWzmt/666oinJ4W3WP/KwTcYrmgyv9Mq7O
btIYOrEljW/v21+w3uBIChffpXMO+bd64YspFYRbKAABdCMZ8+NUZw8lcGK71bWp
bFR+cEpXys+OeKB3jsg6eMQGR8jkAWItYOT7yjytf/hYKWTZDkpYbVVQQBiwBKdi
WrweH2/tahtDFI/5Z1kL5jVKm5aLcO4lprBkjnNfsf9jniepeNUnQYMnpfaElqw1
gMdFBOwKlUuvBDG94Rn8j9meLr+fX9xRZoI5sekW80ciqk++DEluvlgKg9na3i0o
yGwuq4ohHtpabOGWZg5bKkm6PeWDxCA=
-----END CERTIFICATE-----`)

	RootCert = []byte(`-----BEGIN CERTIFICATE-----
MIIDATCCAemgAwIBAgIUGSe93YHtSMssuLoz6rsnqVaeZVkwDQYJKoZIhvcNAQEL
BQAwDzENMAsGA1UEAwwEcm9vdDAgFw0yNDA3MTAwMzEzMzlaGA8yMTI0MDYxNjAz
MTMzOVowDzENMAsGA1UEAwwEcm9vdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBALH6lvOjt9eDk0M19dt76Uz4zAbyPkr7byKdEnXVbTExPjam7vOysI5P
wmIPD4AnzBVedeHW9w+4xmYvN6HqjSmd3NfQ+YLQVzLhwEJHAmRZve6E3SS4r1AJ
uPr0dhiP6Ps3JutlubB9udEBe72Q9RHYLwSgAX2CgESDIjUK0Ev7IQUKQyEf+WFc
OtfP2Ouf/ODZGoWCNeBa1XLiE2/379b1v65dL/7wGTWliHbuoiIAXJgjcRy2qnyy
HhlNtLt3rlJjd6nqdPQjjViiGkxJ9Xpdw8xak3+ukpe59m8EJrUnkvAi7Y/71Wno
Z/cg5zalZ0EnOYi8WUYM3Wgfvkoxl8cCAwEAAaNTMFEwHQYDVR0OBBYEFMaOM4eu
QD+SmkdWMIaSengKX6EZMB8GA1UdIwQYMBaAFMaOM4euQD+SmkdWMIaSengKX6EZ
MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAGNmaWBbED0JbcKH
taL/w8dA+9ARZ5r4rFwvgf4WYavGW9vXxu+0Tp/KHu/PUBLT3J00ONOFp+avtrHe
EP0Ltuc4ZxFnY1FI4q1jzMHfSNVud6OKTSWxy+Y0bhlXbF8464feDDNxFhpPrWb9
lkeZTzKP2sxKufvXodjhp6nKG8KUjgLH23DSKoUUVm5JoKJ9bkPYAcxO7V3cCR0l
NpoStir1cRO0uEnjpAoXFhQ40aNt64N/o5EN5PYzOkX1QVM0mNzW6z+SjQGwXD9H
Eq2/iQogi0pe9IxWGOHS8LdwSw2lxSuq0ZLnPROsmIqKunRx0i5+bmOZt8g96E7Z
bQxWsKQ=
-----END CERTIFICATE-----`)
)

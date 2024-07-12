# configurable-http-proxy

This is a pure go implementation of the
[configurable-http-proxy](https://github.com/jupyterhub/configurable-http-proxy)
written in nodejs. The goal is drop-in replacement of the nodejs version.

[![Build Status](https://github.com/potoo0/configurable-http-proxy/workflows/build/badge.svg)](https://github.com/potoo0/configurable-http-proxy/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/potoo0/configurable-http-proxy)](https://goreportcard.com/report/github.com/potoo0/configurable-http-proxy)
[![codecov](https://codecov.io/gh/potoo0/configurable-http-proxy/graph/badge.svg?token=5EPRKLUUNA)](https://codecov.io/gh/potoo0/configurable-http-proxy)

## Install

### Manually

```
go install github.com/potoo0/configurable-http-proxy
```

### Release

Download the latest release from the releases page.

## Features

Basically synchronized with nodejs version.

Ignored SSL args:
- `--ssl-ciphers`: hard to convert openssl cipher strings to golang's cipher suites, use golang's default cipher suites
  - `--ssl-allow-rc4` is ignored, same as `--ssl-ciphers`.
- `--ssl-dhparam`: Diffie-Hellman parameters is not supported in golang's tls package

## Usage

```
$ ./configurable-http-proxy help   
configurable-http-proxy (CHP) provides you with a way to update and manage a proxy table
using a command line interface or REST API. It is a simple wrapper around httputil.ReverseProxy.
httputil.ReverseProxy is an HTTP programmable proxying library that supports websockets and
is suitable for implementing components such as reverse proxies and load balancers.
By wrapping httputil.ReverseProxy, configurable-http-proxy extends this functionality to JupyterHub deployments.
Support env CONFIGPROXY_SSL_KEY_PASSPHRASE and CONFIGPROXY_API_SSL_KEY_PASSPHRASE to set passphrase for SSL key,
and CONFIGPROXY_AUTH_TOKEN to set a token for REST API authentication.

Usage:
  configurable-http-proxy [flags]
  configurable-http-proxy [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  version     Prints version

Flags:
      --api-ip string                    Inward-facing IP for API requests (default "localhost")
      --api-port int                     Inward-facing port for API requests (defaults to --port=value+1)
      --api-ssl-ca string                SSL certificate authority, if any, for API requests
      --api-ssl-cert string              SSL certificate to use, if any, for API requests
      --api-ssl-key string               SSL key to use, if any, for API requests
      --api-ssl-reject-unauthorized      Reject unauthorized SSL connections for API requests (only meaningful if --api-ssl-request-cert is given)
      --api-ssl-request-cert             Request SSL certs to authenticate clients for API requests
      --auto-rewrite                     Rewrite the Location header host/port in redirect responses
      --change-origin                    Changes the origin of the host header to the target URL
      --client-ssl-ca string             SSL certificate authority, if any, for proxy to client requests
      --client-ssl-cert string           SSL certificate to use, if any, for proxy to client requests
      --client-ssl-key string            SSL key to use, if any, for proxy to client requests
      --client-ssl-reject-unauthorized   Reject unauthorized SSL connections for proxy to client requests (only meaningful if --client-ssl-request-cert is given)
      --client-ssl-request-cert          Request SSL certs to authenticate clients for proxy to client requests
      --custom-header strings            Custom header to add to proxied requests. Use same option for multiple headers (--custom-header k1:v1 --custom-header k2:v2)
      --default-target string            Default proxy target (proto://host[:port])
      --error-path string                Alternate server for handling proxy errors (proto://host[:port])
      --error-target string              Alternate server for handling proxy errors (proto://host[:port])
  -h, --help                             help for configurable-http-proxy
      --host-routing                     Use host routing (host as first level of path)
      --insecure                         Disable SSL cert verification
      --ip string                        Public-facing IP of the proxy
      --keep-alive-timeout int           Set timeout (in milliseconds) for Keep-Alive connections (default 5000)
      --log-level string                 Log level (debug, info, warn, error) (default "info")
      --metrics-ip string                IP for metrics server
      --metrics-port int                 Port of metrics server. Defaults to no metrics server
      --no-include-prefix                Don't include the routing prefix in proxied requests
      --no-prepend-path                  Avoid prepending target paths to proxied request
      --no-x-forward                     Don't add 'X-forward-' headers to proxied requests
      --pid-file string                  Write our PID to a file
      --port int                         Public-facing port of the proxy (default 8000)
      --protocol-rewrite string          Rewrite the Location header protocol in redirect responses to the specified protocol
      --proxy-timeout int                Timeout (in millis) when proxy receives no response from target.
      --redirect-port int                Redirect HTTP requests on this port to the server on HTTPS
      --redirect-to int                  Redirect HTTP requests from --redirect-port to this port
      --ssl-allow-rc4                    (ignored) Allow RC4 cipher for SSL (disabled by default)
      --ssl-ca string                    SSL certificate authority, if any
      --ssl-cert string                  SSL certificate to use, if any
      --ssl-ciphers string               (ignored) :-separated ssl cipher list. Default excludes RC4
      --ssl-dhparam string               (ignored) SSL Diffie-Hellman Parameters pem file, if any
      --ssl-key string                   SSL key to use, if any
      --ssl-protocol string              Set specific SSL protocol, e.g. TLSv1_2, SSLv3
      --ssl-reject-unauthorized          Reject unauthorized SSL connections (only meaningful if --ssl-request-cert is given)
      --ssl-request-cert                 Request SSL certs to authenticate clients
      --storage-backend string           Define an external storage class. Defaults to in-MemoryStore.
      --timeout int                      Timeout (in millis) when proxy drops connection for a request.

Use "configurable-http-proxy [command] --help" for more information about a command.
```

e.g. start a proxy server with error target:

```
configurable-http-proxy --port 8000 --api-ip 127.0.0.1 --api-port 8001 --error-target http://127.0.0.1:8081/error --log-level info
```

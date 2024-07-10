# configurable-http-proxy

This is a pure go implementation of the
[configurable-http-proxy](https://github.com/jupyterhub/configurable-http-proxy)
written in nodejs. The goal is drop-in replacement of the nodejs version.

[![Go Report Card](https://goreportcard.com/badge/github.com/potoo0/configurable-http-proxy)](https://goreportcard.com/report/github.com/potoo0/configurable-http-proxy)

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
- `--ssl-ciphers`: hard to convert openssl cipher strings to golang's cipher suites, use golang's default ciphers
- `--ssl-dhparam`: Diffie-Hellman parameters is not supported in golang's tls package

Missing features (yet):

- Proxy server: `--keep-alive-timeout`, `--timeout`
- Metrics server: `--metrics-port`, `--metrics-ip`

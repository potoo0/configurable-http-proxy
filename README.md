# configurable-http-proxy

This is a pure go implementation of the
[configurable-http-proxy](https://github.com/jupyterhub/configurable-http-proxy)
written in nodejs.

## Install

### Manually

```
go install github.com/potoo0/configurable-http-proxy
```

### Release

Download the latest release from the [releases page]()

## Features

Basically synchronized with nodejs version, but
Missing features (yet):

- Proxy server: `--keep-alive-timeout`, `--timeout`
- Metrics server: `--metrics-port`, `--metrics-ip`
- SSL for proxy, client, API: `--ssl-*`, `--api-ssl-*`, `--client-ssl-*`

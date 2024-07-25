## v0.1.4

- fix get routes by inactiveSince query param
- fix MemoryStore data race

## v0.1.3

- Modify go link flags to reduce binary size
- Publish docker image

## 0.1.2

- Fix string case issue in proxy.proxyKind.
- Support `--metrics-port`, `--metrics-ip` for prometheus metrics.

## 0.1.1

- Support `--keep-alive-timeout` and `--timeout` options to specify the proxy server idle timeout and r/w timeout.
- Support `--ssl-*`, `--api-ssl-*` and `--client-ssl-*` options to specify the ssl configurations.
    - `--ssl-ciphers` is ignored, use golang's default cipher suites.
    - `--ssl-allow-rc4` is ignored, use golang's default cipher suites.
    - `--ssl-dhparam` is ignored, Diffie-Hellman parameters is not supported in golang's tls package.

## v0.1.0

- Support the basic functions provided by jupyterhub/configurable-http-proxy

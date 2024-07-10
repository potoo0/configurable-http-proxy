## 0.1.1

- Support `--keep-alive-timeout` and `--timeout` options to specify the proxy server idle timeout and r/w timeout.
- Support `--ssl-*`, `--api-ssl-*` and `--client-ssl-*` options to specify the ssl configurations.
  - `--ssl-ciphers` is ignored, use golang's default cipher suites.
  - `--ssl-dhparam` is ignored, Diffie-Hellman parameters is not supported in golang's tls package.

## v0.1.0

- Support the basic functions provided by jupyterhub/configurable-http-proxy

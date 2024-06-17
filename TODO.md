TODO list:

- Proxy server: `--keep-alive-timeout`, `--timeout`
- Metrics server: `--metrics-port`, `--metrics-ip`
- SSL for proxy, client, API: `--ssl-*`, `--api-ssl-*`, `--client-ssl-*`

---

```javascript
// https://nodejs.org/api/http.html#serverkeepalivetimeout
// https://nodejs.org/api/net.html#socketsettimeouttimeout-callback
// server.timeout server.keepAliveTimeout socket.timeout
// ProxyServer
httpOptions = {
  keepAlive: true,
  keepAliveTimeout: this.options.keepAliveTimeout || 5000,
};

if(options.timeout) {
  req.socket.setTimeout(options.timeout);
}
```

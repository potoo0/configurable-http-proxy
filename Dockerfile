FROM golang:alpine as builder

WORKDIR /build
COPY . .

RUN apk add --no-cache make git
RUN CGO_ENABLED=0 make build
RUN ./configurable-http-proxy version


FROM alpine:latest

WORKDIR /srv/configurable-http-proxy
COPY --from=builder /build/configurable-http-proxy /build/chp-docker-entrypoint ./

# Switch from the root user to the nobody user
USER 65534

# Expose the proxy for traffic to be proxied (8000) and the
# REST API where it can be configured (8001)
EXPOSE 8000 8001

# Put configurable-http-proxy on path for chp-docker-entrypoint
ENV PATH=/srv/configurable-http-proxy:$PATH
ENTRYPOINT ["/bin/sh", "/srv/configurable-http-proxy/chp-docker-entrypoint"]

# Build the deterministic correlator as a static binary, then ship only the binary
# and the system trust store in the runtime image.
FROM golang:1.27.3-alpine3.24 AS build
WORKDIR /src
COPY services/b89-correlator/go.mod ./services/b89-correlator/go.mod
COPY services/b89-correlator/ ./services/b89-correlator/
WORKDIR /src/services/b89-correlator
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w -buildid=' \
    -o /out/b89-correlator ./cmd/b89-correlator

FROM alpine:3.24
RUN apk add --no-cache ca-certificates \
    && addgroup -S -g 65532 correlator \
    && adduser -S -D -H -u 65532 -G correlator correlator \
    && mkdir -p /app /run/secrets/b89-correlator \
    && chown 65532:65532 /app /run/secrets/b89-correlator
COPY --from=build --chown=65532:65532 /out/b89-correlator /usr/local/bin/b89-correlator
WORKDIR /app
USER 65532:65532
EXPOSE 8080
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD wget -q -T 3 -O /dev/null http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/b89-correlator"]

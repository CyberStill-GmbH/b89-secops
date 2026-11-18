# B89 correlator: static Go binary on distroless (no shell, no package manager), non-root.
# Build context: the repository root (compose: context /opt/b89/src).
FROM golang:1.23.12-bookworm AS build
WORKDIR /src/services/b89-correlator
COPY services/b89-correlator/go.mod ./
COPY services/b89-correlator/ ./
RUN mkdir -p /out /members \
 && CGO_ENABLED=0 GOOS=linux go test ./... \
 && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w -buildid=' \
    -o /out/b89-correlator ./cmd/b89-correlator

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/b89-correlator /usr/local/bin/b89-correlator
COPY --from=build --chown=65532:65532 /members /var/lib/b89/members
USER 65532:65532
EXPOSE 8080
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD ["/usr/local/bin/b89-correlator", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/b89-correlator"]
CMD ["serve"]

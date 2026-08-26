# Multi-stage build minimal untuk service ext_authz.
# Kripto sepenuhnya dari packages/go-sdk (module lokal via replace ../go-sdk).
#
# Build context harus direktori packages/ (lihat deploy/docker-compose.yml):
#   docker build -f envoy-authz/Dockerfile -t sp-envoy-authz .
FROM golang:1.24-alpine AS build

WORKDIR /src/packages

# Tata letak di dalam image meniru struktur repo (packages/go-sdk sebagai
# tetangga envoy-authz) sehingga replace ../go-sdk pada go.mod valid apa adanya,
# tanpa modifikasi saat build.
COPY go-sdk ./go-sdk
COPY envoy-authz/go.mod envoy-authz/go.sum ./envoy-authz/
RUN cd envoy-authz && go mod download
COPY envoy-authz/cmd ./envoy-authz/cmd
RUN cd envoy-authz && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/authz ./cmd/server

FROM alpine:3.20
# Tidak ada secret di image; semua konfigurasi lewat environment saat runtime.
COPY --from=build /out/authz /usr/local/bin/authz
# Non-root, tanpa izin menulis apapun.
USER nobody
EXPOSE 9000
HEALTHCHECK --interval=10s --timeout=3s CMD wget -qO- http://127.0.0.1:9000/healthz || exit 1
ENTRYPOINT ["authz"]

# syntax=docker/dockerfile:1

# Three stages: build the PWA, build the server with the PWA embedded, then ship
# only the binary.

FROM oven/bun:1 AS web
WORKDIR /web
COPY web/package.json web/bun.lock* ./
RUN bun install --frozen-lockfile || bun install
COPY web/ ./
RUN bun run build

FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS server
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY web/embed.go ./web/
# The freshly built UI, which go:embed compiles into the binary.
COPY --from=web /web/dist ./web/dist

# An empty directory for the runtime stage to adopt as /data. Docker initialises
# a fresh named volume from the image's directory, ownership included, and the
# server must be able to create blobs/ and staging/ under it as a non-root user.
RUN mkdir -p /blobroot

# Cross-compile to whatever the target platform is rather than assuming amd64.
ARG TARGETOS
ARG TARGETARCH
# No BuildKit cache mounts: Railway requires a literal id=s/<service-id>-<path>
# on every cache mount, which would hardcode one service into this repo.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w" -o /out/simplecas ./cmd/simplecas

# distroless static ships CA certificates (needed for S3, GCS, Azure and OIDC
# over TLS) and a nonroot user, without a shell or package manager.
FROM gcr.io/distroless/static-debian12:nonroot

# 65532 is distroless's nonroot user. Named numerically because a bind-mounted
# host directory has to be chowned to the same uid to be writable.
COPY --from=server --chown=65532:65532 /blobroot /data

WORKDIR /app
COPY --from=server /out/simplecas /usr/local/bin/simplecas
# Read from the working directory at startup; every field can still be
# overridden with SIMPLECAS__ environment variables.
COPY simplecas.toml ./simplecas.toml

EXPOSE 9000
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/simplecas"]

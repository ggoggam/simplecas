# Multi-stage build: compile the PWA, then the Rust server that embeds it.

FROM oven/bun:1 AS web
WORKDIR /web
COPY web/package.json web/bun.lock* ./
RUN bun install --frozen-lockfile || bun install
COPY web/ ./
RUN bun run build

FROM rust:1-slim AS server
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations
COPY build.rs ./
# Bring in the freshly built UI so rust-embed picks up the real assets.
COPY --from=web /web/dist ./web/dist
RUN cargo build --release

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=server /app/target/release/simplecas /usr/local/bin/simplecas
COPY simplecas.toml ./simplecas.toml
EXPOSE 9000
ENTRYPOINT ["simplecas"]

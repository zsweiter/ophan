# ═══════════════════════════════════════════════════════════════
# Ophan API Gateway — Docker Image
# Build:   docker build -t ophan:latest .
# Run:     docker run -p 8080:80 -v /path/to/config:/etc/ophan ophan:latest
# ═══════════════════════════════════════════════════════════════

# ── Stage 1: Build ────────────────────────────────────────────
FROM rust:1.81-alpine3.21 AS build

ARG VERSION=dev

RUN apk add --no-cache musl-dev upx

WORKDIR /src

# Cache dependencies
COPY Cargo.toml Cargo.lock ./
COPY libs/ophan-net/Cargo.toml libs/ophan-net/
COPY libs/ophan-auth/Cargo.toml libs/ophan-auth/
COPY libs/ophan-waf/Cargo.toml libs/ophan-waf/
COPY libs/ophan-static/Cargo.toml libs/ophan-static/
COPY libs/ophan-router/Cargo.toml libs/ophan-router/
COPY ophan/Cargo.toml ophan/

RUN mkdir libs/ophan-net/src libs/ophan-auth/src libs/ophan-waf/src \
         libs/ophan-static/src libs/ophan-router/src ophan/src \
    && echo "fn main() {}" > ophan/src/main.rs \
    && for lib in libs/*/src; do echo "" > "$$lib/lib.rs"; done \
    && cargo build --release --target x86_64-unknown-linux-musl 2>/dev/null || true

# Full source build
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl \
    && upx --best target/x86_64-unknown-linux-musl/release/ophan

# ── Stage 2: Runtime ──────────────────────────────────────────
FROM alpine:3.21

RUN addgroup -S ophan && adduser -S -G ophan ophan

COPY --from=build /src/target/x86_64-unknown-linux-musl/release/ophan /usr/local/bin/ophan
COPY config/ /etc/ophan/

RUN mkdir -p /var/log/ophan /var/run/ophan \
    && chown -R ophan:ophan /var/log/ophan /var/run/ophan /etc/ophan

USER ophan
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/ophan"]

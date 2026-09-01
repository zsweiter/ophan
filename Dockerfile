# ═══════════════════════════════════════════════════════════════
# Ophan API Gateway — Docker Image (Multi-Architecture)
# Build:   docker buildx build --platform linux/amd64,linux/arm64 -t ophan:latest --push .
# Run:     docker run -d -p 80:80 -p 443:443 -v /path/to/config:/etc/ophan ophan:latest
# ═══════════════════════════════════════════════════════════════

FROM --platform=$BUILDPLATFORM lukemathwalker/cargo-chef:latest-rust-1.94 AS chef
WORKDIR /src

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM --platform=$BUILDPLATFORM chef AS builder
COPY --from=planner /src/recipe.json recipe.json

ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    musl-tools \
    && rm -rf /var/lib/apt/lists/*

RUN case "${TARGETARCH}" in \
        amd64) \
            rustup target add x86_64-unknown-linux-musl; \
            echo "x86_64-unknown-linux-musl" > /.target ;; \
        arm64) \
            rustup target add aarch64-unknown-linux-musl; \
            echo "aarch64-unknown-linux-musl" > /.target ;; \
        *) echo "Unsupported target: ${TARGETARCH}"; exit 1 ;; \
    esac

ENV CXX_x86_64_unknown_linux_musl=g++
ENV CXX_aarch64_unknown_linux_musl=g++

RUN TARGET=$(cat /.target) && cargo chef cook --release --target "$TARGET" --recipe-path recipe.json

COPY . .
RUN TARGET=$(cat /.target) \
    && cargo build --release --target "$TARGET" --bin ophan \
    && cp "target/$TARGET/release/ophan" /ophan

FROM alpine:3.21

RUN apk add --no-cache libcap

RUN addgroup -S ophan && adduser -S -G ophan ophan

RUN mkdir -p /etc/ophan /var/www/ /var/log/ophan /var/run/ophan

COPY --from=builder /ophan /usr/local/bin/ophan

COPY defaults/config/ /etc/ophan/
COPY defaults/www/ /var/www/

RUN chown -R ophan:ophan /etc/ophan /var/www /var/log/ophan /var/run/ophan \
    && setcap 'cap_net_bind_service=+ep' /usr/local/bin/ophan \
    && apk del libcap # Clean up to keep the image lightweight

USER ophan

EXPOSE 80
EXPOSE 443

ENV OPHAN_CONFIG_DIR=/etc/ophan
ENV OPHAN_WWW_DIR=/var/www
ENV OPHAN_PID_FILE=/var/run/ophan/ophan.pid

ENTRYPOINT ["/usr/local/bin/ophan"]

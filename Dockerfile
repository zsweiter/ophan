# ═══════════════════════════════════════════════════════════════
# Ophan API Gateway — Docker Image (Multi-Architecture)
# Build:   docker buildx build --platform linux/amd64,linux/arm64 -t ghcr.io/zsweiter/ophan:latest --push .
# Run:     docker run -d -p 80:80 \
#            -v ophan-config:/etc/ophan -v ophan-www:/var/www -v ophan-logs:/var/log/ophan \
#            -v ophan-run:/run/ophan \
#            ghcr.io/zsweiter/ophan:latest
# ═══════════════════════════════════════════════════════════════

FROM --platform=$BUILDPLATFORM lukemathwalker/cargo-chef:latest-rust-1.94 AS chef
WORKDIR /src

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM --platform=$BUILDPLATFORM chef AS builder
COPY --from=planner /src/recipe.json recipe.json
COPY vendor/ vendor/

ARG TARGETARCH
ARG BUILDARCH
ARG ZIG_VERSION=0.13.0
ARG CARGO_ZIGBUILD_VERSION=0.23.4

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    curl \
    libcap2-bin \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Zig acts as the C/C++ cross compiler and linker for the musl targets,
RUN case "${BUILDARCH}" in \
        amd64) ZIG_ARCH=x86_64 ;; \
        arm64) ZIG_ARCH=aarch64 ;; \
        *) echo "Unsupported build platform: ${BUILDARCH}"; exit 1 ;; \
    esac \
    && curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-linux-${ZIG_ARCH}-${ZIG_VERSION}.tar.xz" \
        | tar -xJ -C /opt \
    && ln -s "/opt/zig-linux-${ZIG_ARCH}-${ZIG_VERSION}/zig" /usr/local/bin/zig

RUN cargo install cargo-zigbuild --version "${CARGO_ZIGBUILD_VERSION}" --locked

RUN case "${TARGETARCH}" in \
        amd64) \
            rustup target add x86_64-unknown-linux-musl; \
            echo "x86_64-unknown-linux-musl" > /.target ;; \
        arm64) \
            rustup target add aarch64-unknown-linux-musl; \
            echo "aarch64-unknown-linux-musl" > /.target ;; \
        *) echo "Unsupported target: ${TARGETARCH}"; exit 1 ;; \
    esac

RUN TARGET=$(cat /.target) && cargo chef cook --release --zigbuild --target "$TARGET" --recipe-path recipe.json

COPY . .
RUN TARGET=$(cat /.target) \
    && cargo zigbuild --release --target "$TARGET" --bin ophan \
    && cp "target/$TARGET/release/ophan" /ophan \
    && setcap 'cap_net_bind_service=+ep' /ophan

RUN mkdir -p /rootfs/etc/ophan /rootfs/usr/share/ophan /rootfs/var/www /rootfs/var/log/ophan /rootfs/run/ophan \
    && cp -R packaging/docker/. /rootfs/etc/ophan/ \
    && cp -R packaging/docker /rootfs/usr/share/ophan/config \
    && cp -R defaults/www/. /rootfs/var/www/

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /ophan /usr/local/bin/ophan
COPY --from=builder /rootfs/usr/share/ophan /usr/share/ophan
COPY --from=builder --chown=65532:65532 /rootfs/etc/ophan /etc/ophan
COPY --from=builder --chown=65532:65532 /rootfs/var/www /var/www
COPY --from=builder --chown=65532:65532 /rootfs/var/log/ophan /var/log/ophan
COPY --from=builder --chown=65532:65532 /rootfs/run/ophan /run/ophan

USER 65532:65532

ENV CONFIG_PATH=/etc/ophan/master.conf
ENV OPHAN_CONFIG_SEED_DIR=/usr/share/ophan/config
ENV OPHAN_PID_FILE=/tmp/ophan/ophan.pid

VOLUME ["/etc/ophan", "/var/www", "/var/log/ophan", "/run/ophan"]

EXPOSE 80

ENTRYPOINT ["/usr/local/bin/ophan"]

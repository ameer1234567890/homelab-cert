# Cross-compiles on the build host (no QEMU needed) for amd64, arm64 and arm/v7.
# The stage name is picked from the target platform: build-amd64 / build-arm64 / build-armv7
FROM --platform=$BUILDPLATFORM ghcr.io/rust-cross/rust-musl-cross:x86_64-musl AS build-amd64
FROM --platform=$BUILDPLATFORM ghcr.io/rust-cross/rust-musl-cross:aarch64-musl AS build-arm64
FROM --platform=$BUILDPLATFORM ghcr.io/rust-cross/rust-musl-cross:armv7-musleabihf AS build-armv7

ARG TARGETARCH
ARG TARGETVARIANT
FROM --platform=$BUILDPLATFORM build-${TARGETARCH}${TARGETVARIANT} AS build
WORKDIR /home/rust/src
COPY --chown=rust:rust Cargo.toml ./
COPY --chown=rust:rust src src
COPY --chown=rust:rust static static
RUN cargo build --release

FROM scratch
COPY --from=build /home/rust/src/target/*/release/homelab-cert /homelab-cert
ENV DATA_DIR=/data
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/homelab-cert"]

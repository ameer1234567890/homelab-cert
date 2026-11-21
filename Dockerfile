FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev gcc
WORKDIR /src
COPY Cargo.toml ./
COPY src src
COPY static static
RUN cargo build --release

FROM scratch
COPY --from=build /src/target/release/homelab-cert /homelab-cert
ENV DATA_DIR=/data
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/homelab-cert"]

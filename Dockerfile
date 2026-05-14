# syntax=docker/dockerfile:1.6

ARG RUST_VERSION=1.74

FROM rust:${RUST_VERSION}-bookworm AS builder
WORKDIR /build

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git pkg-config \
    && rm -rf /var/lib/apt/lists/*

ARG KELI_CORE_RS_REPO=https://github.com/keli-123456/keli-core-rs.git
ARG KELI_CORE_RS_REF=main
RUN git clone --depth 1 --branch "${KELI_CORE_RS_REF}" "${KELI_CORE_RS_REPO}" keli-core-rs \
    || (git clone "${KELI_CORE_RS_REPO}" keli-core-rs && cd keli-core-rs && git checkout "${KELI_CORE_RS_REF}")

COPY . kelinode-rs

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/kelinode-rs/target \
    --mount=type=cache,target=/build/keli-core-rs/target \
    cargo build --manifest-path kelinode-rs/Cargo.toml --release --locked --features embedded-core \
    && mkdir -p /build/out \
    && cp kelinode-rs/target/release/kelinode-rs /build/out/kelinode-rs

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl jq tzdata iproute2 iptables \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /etc/v2node /usr/local/v2node

COPY --from=builder /build/out/kelinode-rs /usr/local/v2node/kelinode-rs
COPY --from=builder /build/out/kelinode-rs /usr/local/bin/v2node
COPY docker-entrypoint.sh /docker-entrypoint.sh

RUN chmod +x /usr/local/v2node/kelinode-rs /usr/local/bin/v2node /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["v2node", "server"]

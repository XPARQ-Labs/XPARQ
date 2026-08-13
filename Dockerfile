# syntax=docker/dockerfile:1

ARG RUST_VERSION=1.90
FROM rust:${RUST_VERSION}-bookworm AS builder

ARG XPARQ_NETWORK=mainnet
WORKDIR /src
COPY . .

RUN case "${XPARQ_NETWORK}" in \
        mainnet) cargo build --release --locked -p node ;; \
        testnet|devnet) cargo build --release --locked -p node \
            --no-default-features --features "${XPARQ_NETWORK}" ;; \
        *) echo "unsupported XPARQ_NETWORK=${XPARQ_NETWORK}; expected mainnet, testnet, or devnet" >&2; exit 2 ;; \
    esac

FROM debian:12-slim AS runtime

ARG XPARQ_NETWORK=mainnet
LABEL org.opencontainers.image.title="XPARQ Node" \
      org.opencontainers.image.description="XPARQ full node" \
      org.opencontainers.image.source="https://github.com/XPARQ-Labs/XPARQ" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.xparq.network="${XPARQ_NETWORK}"

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates libgcc-s1 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 xparq \
    && useradd --uid 10001 --gid xparq --home-dir /var/lib/xparq \
        --no-create-home --shell /usr/sbin/nologin xparq \
    && install --directory --owner xparq --group xparq /var/lib/xparq/data

COPY --from=builder --chown=root:root /src/target/release/node /usr/local/bin/node

USER xparq:xparq
WORKDIR /var/lib/xparq
ENV XPARQ_LOG=info

VOLUME ["/var/lib/xparq/data"]
EXPOSE 5555/tcp

ENTRYPOINT ["/usr/local/bin/node"]
CMD ["node", "run"]

# Multi-stage build for the `cambium` binary (both the `sync` daemon and the
# `ropc-proxy` subcommand ship in this one image — same binary, different
# CMD). Matches the structure of `grafter`'s Dockerfile (deps cached
# separately from source) but built from stock Docker Hub images rather than
# Smartech's internal registry mirror, since this image is meant to be
# buildable by anyone cloning this repo, not just from inside Smartech's
# network.
FROM rust:1-slim-bookworm AS builder

WORKDIR /build

# Cache deps separately from source.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs
RUN cargo build --release --locked 2>/dev/null || true
RUN rm -rf src

COPY src ./src
RUN touch src/main.rs && cargo build --release --locked

# ── Final image ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim

# Nexus/Keycloak in the dev stack use plain HTTP, but `reqwest` is built with
# rustls (see Cargo.toml) and its cert store still gets consulted; ca-certs
# also matter for anyone pointing this image at a real TLS-terminated
# Keycloak/Nexus.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /build/target/release/cambium ./cambium

ENTRYPOINT ["./cambium"]
CMD ["sync"]

FROM rust:1.88-slim AS builder
WORKDIR /build

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations
RUN cargo build --release

FROM debian:13.6-slim
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 ca-certificates curl tini \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/tim /app/tim
# Ship the demo self-contained: tim.yaml + migrations baked in.
# Operators bind-mount over any of these to override.
COPY tim.yaml /app/tim.yaml
COPY migrations /app/migrations

EXPOSE 8085
RUN useradd -m -u 1000 tim && chown -R tim:tim /app
USER tim

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/app/tim", "--config", "/app/tim.yaml"]

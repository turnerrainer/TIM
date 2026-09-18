# syntax=docker/dockerfile:1
#
# Two-stage build: `rust:1.88-slim` compiles the binary; the runtime
# stage is Google's distroless `cc-debian12` image (glibc + libgcc +
# libssl3 + ca-certificates, nothing else). No shell, no package
# manager, no curl, no useradd — the attack surface is a single
# statically-linkable-runtime binary.
#
# Trivy baseline (h2ck.me v1 NEXT-TASKS T-12): the previous
# `debian:13.6-slim` runtime reported 59 HIGH + 3 CRITICAL CVEs from
# the base image alone. Distroless brings that down to whatever
# jsonwebtoken / sqlx / reqwest crates surface plus glibc / openssl —
# a much smaller list, most of it TIM's own dep tree.
#
# Zero-shell means the container HEALTHCHECK must exec the tim binary
# directly: `tim healthcheck` probes /health via reqwest.

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

# Distroless :nonroot runs as UID 65532; no root, no shell, no apt.
# `cc-debian12` includes glibc + libgcc + libstdc++ + libssl3 for
# TIM's native-tls / openssl runtime linkage.
FROM gcr.io/distroless/cc-debian12:nonroot
WORKDIR /app

COPY --from=builder /build/target/release/tim /app/tim
# Ship the demo self-contained: tim.yaml + migrations baked in.
# Operators bind-mount over any of these to override.
COPY tim.yaml /app/tim.yaml
COPY migrations /app/migrations

EXPOSE 8085
USER nonroot:nonroot

# HEALTHCHECK lives in docker-compose.yml so both the compose stack
# and Kubernetes operators pick it up. Distroless has no shell for
# CMD-SHELL — compose uses the CMD-array form, invoking
# `tim healthcheck` directly.

# No tini: TIM is a single-process axum server that does not fork.
# The child-reaping role tini plays for multi-process containers is a
# no-op here; K8s / `docker run --init` cover the PID-1 signal
# forwarding role if needed.
ENTRYPOINT ["/app/tim"]
CMD ["--config", "/app/tim.yaml", "serve"]

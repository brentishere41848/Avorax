FROM rust:1-bookworm AS builder
WORKDIR /workspace
COPY services/api/Cargo.toml services/api/Cargo.toml
COPY services/api/src services/api/src
COPY infra infra
WORKDIR /workspace/services/api
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /workspace/services/api
COPY --from=builder /workspace/services/api/target/release/zentor_api /usr/local/bin/zentor_api
COPY --from=builder /workspace/infra /workspace/infra
EXPOSE 8000
CMD ["zentor_api"]

# syntax=docker/dockerfile:1
ARG RUST_VERSION=1.96

FROM rust:${RUST_VERSION}-slim AS builder
WORKDIR /src
RUN apt-get update     && apt-get install -y --no-install-recommends ca-certificates pkg-config cmake make clang     && rm -rf /var/lib/apt/lists/*
COPY . .
RUN cargo build --release -p zuicity-cli --bins

FROM debian:trixie-slim AS runtime
RUN apt-get update     && apt-get install -y --no-install-recommends ca-certificates tzdata     && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/zuicity-server /usr/bin/zuicity-server
COPY install/example-server.json /etc/zuicity/server.json
CMD ["zuicity-server", "run", "-c", "/etc/zuicity/server.json"]

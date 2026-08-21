# syntax=docker/dockerfile:1.7

# The build toolchain, pinned to the workspace's rust-version. OpenSSL is linked
# from the system, so the runtime below carries the same major.
FROM rust:1.97-bookworm AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends pkg-config libssl-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
# The registry and the target directory survive between builds, so a change to
# one crate rebuilds that crate and not the dependency graph. Cargo decides
# freshness by mtime, and a file copied in can carry a time older than a cached
# artifact built from its previous contents, so the workspace's own sources are
# touched: its crates always rebuild, the dependency graph never does.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    find crates -name '*.rs' -exec touch {} + \
 && cargo build --release -p saffui \
 && install -D target/release/saffui /out/saffui

# Nothing but the binary, its shared libraries, and a user that is not root.
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends libssl3 ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --no-create-home saffui
COPY --from=build /out/saffui /usr/local/bin/saffui
USER saffui
# Traffic, and the probes on a port of their own.
EXPOSE 8080 8081
ENTRYPOINT ["saffui"]
CMD ["serve", "--bind", "0.0.0.0:8080", "--ops", "0.0.0.0:8081"]

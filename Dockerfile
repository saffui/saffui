# syntax=docker/dockerfile:1.7

# The console first, with a toolchain that never reaches the runtime: the
# built pages are handed to the compiler below and embedded into the binary,
# so the image ships one process and no node.
FROM node:22-bookworm-slim AS front
RUN corepack enable && corepack prepare pnpm@10.29.2 --activate
WORKDIR /src
COPY pnpm-workspace.yaml pnpm-lock.yaml ./
COPY packages packages
COPY admin admin
RUN pnpm install --frozen-lockfile \
 && pnpm --dir admin build

# The build toolchain, pinned to the workspace's rust-version. OpenSSL is linked
# from the system, so the runtime below carries the same major.
FROM rust:1.97-bookworm AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends pkg-config libssl-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
COPY --from=front /src/admin/dist admin/dist
# The registry and the target directory survive between builds, so a change to
# one crate rebuilds that crate and not the dependency graph. Cargo decides
# freshness by mtime, and a file copied in can carry a time older than a cached
# artifact built from its previous contents, so the workspace's own sources are
# touched: its crates always rebuild, the dependency graph never does.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    find crates -name '*.rs' -exec touch {} + \
 && cargo build --release --locked -p saffui --features server/embedded-admin \
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

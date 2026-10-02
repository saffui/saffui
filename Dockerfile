# syntax=docker/dockerfile:1.7

# The consoles first, with a toolchain that never reaches the runtime: the
# built pages are handed to the compiler below and embedded into the binary,
# so the image ships one process and no node.
FROM node:26-bookworm-slim AS front
RUN corepack enable && corepack prepare pnpm@10.29.2 --activate
WORKDIR /src
COPY pnpm-workspace.yaml pnpm-lock.yaml ./
COPY packages packages
COPY admin admin
COPY account account
# The fonts both stylesheets point at. Vite leaves a url it cannot resolve as
# written, so without them the builds passed and the fonts 404ed once served;
# the listing after the builds refuses that.
COPY assets/fonts assets/fonts
RUN pnpm install --frozen-lockfile \
 && pnpm --dir admin build \
 && pnpm --dir account build \
 && ls admin/dist/assets/*.woff2 account/dist/assets/*.woff2 > /dev/null

# The build toolchain, pinned to the workspace's rust-version. OpenSSL is linked
# from the system, so the runtime below carries the same major.
FROM rust:1.97-bookworm AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends pkg-config libssl-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
COPY --from=front /src/admin/dist admin/dist
COPY --from=front /src/account/dist account/dist
# The registry and the target directory survive between builds, so a change to
# one crate rebuilds that crate and not the dependency graph. Cargo decides
# freshness by mtime, and a file copied in can carry a time older than a cached
# artifact built from its previous contents, so the workspace's own sources are
# touched: its crates always rebuild, the dependency graph never does.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    find crates -name '*.rs' -exec touch {} + \
 && cargo build --release --locked -p saffui --features server/embedded-admin,server/embedded-account \
 && install -D target/release/saffui /out/saffui

# Nothing but the binary, its shared libraries, and a user that is not root.
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends libssl3 ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --no-create-home saffui
COPY --from=build /out/saffui /usr/local/bin/saffui
# The binary embeds the consoles' fonts, and their licence travels with them.
COPY assets/fonts/ibm-plex/LICENSE.txt /usr/share/licenses/saffui/ibm-plex/LICENSE.txt
# It embeds three JSON-LD contexts too, and theirs travel the same way.
COPY crates/jsonld/contexts/w3c/LICENSE.md /usr/share/licenses/saffui/jsonld-contexts/w3c/LICENSE.md
COPY crates/jsonld/contexts/digitalbazaar/LICENSE /usr/share/licenses/saffui/jsonld-contexts/digitalbazaar/LICENSE
USER saffui
# Traffic, and the probes on a port of their own.
EXPOSE 8080 8081
ENTRYPOINT ["saffui"]
CMD ["serve", "--bind", "0.0.0.0:8080", "--ops", "0.0.0.0:8081"]

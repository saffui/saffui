# Nothing that does not serve a request compiles a web framework

Held since the crate split. Read in `crates/commons/Cargo.toml` and in the `ci`
job.

## The decision

The workspace is sixteen crates, and a feature exists to keep a dependency out
of the crates that do not need it rather than to switch behaviour on. Everything
depends on `commons`, so `commons` carries the web framework behind `http`, the
subscriber stack behind `tracing-json`, and the per-request span behind
`request-span`, which needs both of the others. All three are off by default.

`crypto` gates the same way: `chacha20`, `pkcs11`, `pq-hybrid` and `fips-strict`.
`server` gates `kerberos` and `mesh`, so a build without the mesh carries none
of its protocol machinery.

## What it stands against

The shape the reference implementation has, where the equivalent of `commons`
pulls the web framework and the database driver into every crate that depends
on it. The cost is paid by every deployment: a longer build, a wider dependency
tree, more to audit, and more that a `cargo-deny` run has to answer for.

## How it is held

The `ci` job runs `cargo clippy --workspace --all-targets -- -D warnings` seven
more times, once per feature combination, so a crate that quietly starts using
what a feature was meant to gate does not reach `develop` compiling only in the
configuration someone happened to build.

## What it costs

Seven extra clippy runs on every pull request, and the discipline of deciding
which side of a feature a new dependency belongs on before adding it.

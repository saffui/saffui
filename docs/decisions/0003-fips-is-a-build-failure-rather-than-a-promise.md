# A build that cannot hold a claim does not compile

Held since `crypto` gained `fips-strict`. Read in `crates/crypto/src/lib.rs`.

## The decision

Nothing is claimed without the validation standing behind it. A binary built
with `fips-strict` may not link an algorithm outside the validated set, and the
place to catch that is the build.

Two pairs are refused. `fips-strict` with `chacha20`, because a binary claiming
FIPS while linking a non-validated cipher is a contradiction. `fips-strict`
with `pq-hybrid`, because ML-DSA and ML-KEM live in OpenSSL's default provider
rather than the validated one, so no build linking them holds the claim today.

## What it stands against

Catching it in an audit that reads the feature list, months later, after the
claim has been made to somebody.

## How it is held

A `compile_error!` on each pair. A guard nobody fires is a guard nobody notices
losing, so the `ci` job builds both forbidden pairs on purpose, expects the
build to fail, and reads the log for the guard's own message: a build broken
for any other reason would otherwise be taken as the guard holding.

## What it costs

Two builds per run that exist to fail, and the care of writing a guard's message
so that a test can tell it apart from an unrelated breakage.

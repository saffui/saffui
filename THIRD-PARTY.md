# Third-party code

Register of source code **vendored into this repository** — copied, adapted, or
otherwise derived from another project.

It does not cover ordinary dependencies. Those are declared in `Cargo.toml`,
resolved by Cargo and audited by `cargo deny` (see `deny.toml`); they are not
part of this repository's source.

## Current state

The JOSE layer is vendored from josekit. See the entry below.

---

## josekit

- **Upstream:** https://github.com/hidekatsu-izuno/josekit-rs
- **Author:** Hidekatsu Izuno <hidekatsu.izuno@gmail.com>
- **Licence:** Apache-2.0 OR MIT — Apache-2.0 relied on here, matching this
  repository. Upstream ships no `NOTICE` file and no per-file copyright headers,
  so §4(c) and §4(d) have nothing to carry over; **§4(b) is the live obligation**,
  discharged by the notice at the top of every derived file.
- **Version taken:** **0.10.3**, tag `v0.10.3`, commit
  `8fc5c143f258757c20c02841be9cfb088926d41d` (upstream commit date 2025-05-21)
- **Date taken:** 2026-07-29
- **Files derived:** the whole of upstream `src/` except `lib.rs`, placed under
  `crates/crypto/src/jose/` — 58 files, ~21 500 lines: `jose_error.rs`,
  `jose_header.rs`, `jwe*`, `jwk*`, `jws*`, `jwt*`, `util*`. Upstream `data/`
  (222 test fixtures) copied to `crates/crypto/data/`.
- **Modifications:**
  1. Vendored as a module of the `crypto` crate rather than as its own crate.
     Upstream `lib.rs` became `jose/mod.rs`, minus the doctest wiring.
  2. Module paths rewritten `crate::` → `crate::jose::` (47 files).
  3. Edition 2021 → 2024: removed three explicit `ref` bindings in
     `jwt/jwt_payload.rs` tests, which edition 2024 rejects inside
     implicitly-borrowing patterns.
  4. A §4(b) modification notice added at the top of every derived file.
  5. `PartialEq for Box<dyn T>` rewritten in five places. Upstream wrote
     `self == other`, which resolves to the impl being defined: comparing two
     boxed values recursed until the stack ran out. It affected
     `JweAlgorithm`, `JwsAlgorithm`, `JweCompression`, `JweContentEncryption`
     and `KeyPair`. The four algorithm traits now compare `name()`, the header
     parameter that identifies them; `KeyPair` compares the DER *public* key,
     which identifies the pair without a non-constant-time comparison of secret
     material. Report upstream. See the defect table below.
  6. Three `for … { …; break }` bodies guarded by `len() == 1` replaced with
     `into_iter().next()` in `set_audience` (`jwt/jwt_payload.rs`,
     `jwe/jwe_header.rs`, `jwe/jwe_header_set.rs`). Same behaviour; the loop
     form is what `clippy::never_loop` rejects, and it is deny-by-default. The
     dead `vec2` in the `jwt_payload.rs` copy went with it.
  7. Formatted with this repository's `rustfmt`, and the machine-applicable
     `clippy` suggestions applied across the vendored tree. This is the largest
     source of divergence and the one that will cost the most at the next port:
     it touches almost every file. Taken deliberately, so that the CI can hold
     the whole tree to one standard rather than carve out an exemption.
  8. The lints `clippy` cannot rewrite on its own, cleared by hand: 45 match
     guards of the form `val if val == LIT` replaced by the literal pattern,
     `&Vec<T>` narrowed to `&[T]` in the eight `set_critical` and
     `set_x509_certificate_chain` signatures, `Default` derived on the five
     types that had a bare `new()`, and `is_empty` added to `JoseHeader` with a
     default body.
  9. Three lints kept with a local `#[allow]` and a written reason instead of a
     rewrite, because each would restructure upstream rather than improve it:
     `module_inception` on `jwk::jwk`, `should_implement_trait` on
     `DerReader::next` (it returns a `Result` and is not an iterator), and
     `unbuffered_bytes` in `DerReader::from_reader` (every construction here
     reads from an in-memory slice, so buffering would allocate for nothing).
- **Verification:** the 144 upstream tests pass unmodified after vendoring, and
  145 after the boxed-equality regression test added with modification 5.
- **Upstream tracking:** watch https://github.com/hidekatsu-izuno/josekit-rs/releases.
  Record every port in this entry, extending the Modifications list.

### Why the version matters

A prior codebase in this stack forked josekit 0.8.1 (July 2022) and never
recorded the base. Three years later the upstream had moved to 0.10.3, nobody
could say what had been changed locally, and the accumulated upstream fixes could
not be ported without reconstructing the fork base by hand. Forking a current
release and writing the version down is the whole difference between a
maintainable fork and a dead end.

### Known upstream defects to patch after vendoring

Verified against josekit master on 2026-07-29. A fresh fork will contain these;
they are not hypothetical.

| Defect | Location | Effect |
|---|---|---|
| The `crit` header claim is read as `"critical"` on the JSON deserialization path | `src/jws/jws_context.rs` (`deserialize_json_with_selector`) | The whole critical-extension validation is dead code. A JWS naming an extension the implementation does not understand is **accepted**, in violation of RFC 7515 §4.1.11. The compact path reads `"crit"` correctly, which is what hides it. |
| `JwkSet::remove_key` does not clear `kid_map` | `src/jwk/jwk_set.rs` | A key removed from the set still resolves through `get(kid)`. Revoking a key does not stop it being selected. |
| `PartialEq for Box<dyn T>` is written `self == other` | `src/jwe/jwe_algorithm.rs`, `src/jwe/jwe_compression.rs`, `src/jwe/jwe_content_encryption.rs`, `src/jws/jws_algorithm.rs`, `src/jwk/key_pair.rs` | The impl calls itself. Comparing two boxed algorithms, compressions, content encryptions or key pairs recurses until the stack is exhausted and the process dies. Patched here (modification 5); still present upstream. No upstream test covers it, and none could: the test process would go down with it. |

Both are worth reporting upstream rather than only patching locally.

Also missing upstream, and worth adding while you are in the code: PBES2 has an
iteration-count ceiling but **no floor**, so `p2c = 1` derives a key encryption
key in a single PBKDF2 round (RFC 7518 §4.8.1.2 recommends at least 1000), and
the encrypt path reads `p2c` from the incoming header with no bound at all.

## Before vendoring anything

Record the entry **in the same commit that introduces the code**, never
afterwards. The two fields that decide everything are the exact version and the
date: without them no future diff against upstream is possible.

Then add the notice required by the upstream licence to each derived file.
Apache-2.0 §4(b) requires modified files to carry a *prominent* notice stating
that you changed them — top of the file, not buried in it.

### Entry template

```markdown
## <project name>

- Upstream: <URL>
- Version taken: <exact version or commit SHA> (<upstream release date>)
- Date taken: <YYYY-MM-DD>
- Licence: <SPDX identifier>
- Files derived:
  - <path>
- Modifications: <what changed>
- Upstream tracking: <who watches upstream, how ports are decided>
```

### Per-file notice template

```rust
// Portions of this file are derived from josekit
// <https://github.com/hidekatsu-izuno/josekit-rs>, version <X.Y.Z>,
// Copyright (c) hidekatsu-izuno, licensed under Apache-2.0 OR MIT.
//
// Modified by Kodjo Michel Touglo, <year>: <summary of the changes>.
```

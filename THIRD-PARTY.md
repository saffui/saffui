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
  10. The `crit` header claim read as `crit` on the JSON deserialization path,
      where upstream reads `critical`. First of the three defects this file
      already listed to patch after vendoring. A regression test covers both
      answers: refused by default, accepted once the context declares the
      extension acceptable.
  11. `JwkSet::remove_key` now rebuilds `kid_map`. Second of the three listed
      defects. Rebuilt rather than pruned entry by entry, because the map is
      keyed by `(kid, position in keys)` and a removal shifts every later
      position; the regression test keeps a key after the removed one for
      exactly that reason.
  12. A PBES2 iteration floor of 1000, named alongside the existing ceiling and
      applied on both paths. `set_iter_count` already refused less; a `p2c`
      taken from a header did not go through it. The encrypt side is the one
      that mattered: it used a caller-supplied `p2c` unbounded in either
      direction, so a JWE could be emitted whose password was a thousand times
      cheaper to attack offline than the configuration allowed. Refused rather
      than raised silently — a JWE that states one count while having been
      built with another is worse than one that fails.
  13. The upstream test vectors under `crates/crypto/data` removed, and with
      them the 85 tests that read through `CARGO_MANIFEST_DIR/data`. 63 tests
      remain, including every regression test written for modifications 5, 10,
      11 and 12 — the `crit` one was rewritten to generate its key rather than
      load it, so the coverage survives the vectors.
  14. Regression tests for the JWS, JWE and key-detection paths, written with
      generated key material rather than the removed vectors.
  15. `DerBuilder::append_integer_from_u64` fixed to write big-endian octets,
      and to write zero as one `0x00` rather than none. Found by putting the
      builder and the reader in the same test; see the defect table.
  16. `b64` type-checked in `JwsHeader::check_claim`, which upstream leaves out
      of the match entirely.
  17. `RsaPssKeyPair::from_der` and `from_pem` now take the MGF1 digest from
      the key's own MGF1 field when the caller does not state one, instead of
      from its signing digest.
- **Verification:** the 144 upstream tests passed unmodified at the point of
  vendoring, which is what established that the port was faithful. That
  evidence is no longer reproducible from the tree: modification 13 removed the
  vectors those tests read, so 63 of them remain. Read the claim as a fact
  about commit 972d82c, not about HEAD.

  The consequence belongs here rather than in a commit message: the next port
  from upstream cannot be checked the way this one was. Whoever takes josekit
  0.10.4 will have to restore the vectors from git history — `git show
  972d82c -- crates/crypto/data` — or regenerate them from the openssl
  invocations recorded in the `memo.md` that came with them, and run the
  deleted tests against the merge before deleting them again.
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
| ~~The `crit` header claim is read as `"critical"` on the JSON deserialization path~~ — **patched here**, modification 10 | `src/jws/jws_context.rs` (`deserialize_json_with_selector`) | The whole critical-extension validation is dead code. A JWS naming an extension the implementation does not understand is **accepted**, in violation of RFC 7515 §4.1.11. The compact path reads `"crit"` correctly, which is what hides it. Still present upstream; report it. |
| ~~`JwkSet::remove_key` does not clear `kid_map`~~ — **patched here**, modification 11 | `src/jwk/jwk_set.rs` | A key removed from the set still resolves through `get(kid)`. Revoking a key does not stop it being selected. The index is also keyed by position in `keys`, so a removal invalidates every entry after it. Still present upstream; report it. |
| `PartialEq for Box<dyn T>` is written `self == other` | `src/jwe/jwe_algorithm.rs`, `src/jwe/jwe_compression.rs`, `src/jwe/jwe_content_encryption.rs`, `src/jws/jws_algorithm.rs`, `src/jwk/key_pair.rs` | The impl calls itself. Comparing two boxed algorithms, compressions, content encryptions or key pairs recurses until the stack is exhausted and the process dies. Patched here (modification 5); still present upstream. No upstream test covers it, and none could: the test process would go down with it. |
| `DerBuilder::append_integer_from_u64` writes the octets least significant first | `src/util/der/der_builder.rs` | A DER INTEGER is big-endian and never zero octets long (X.690 8.3.2). The builder emitted the bytes reversed, and wrote zero as an INTEGER of no length. Its own reader decodes big-endian, so the two halves of the module disagreed. Nothing upstream or here calls it — the production paths use the single-byte variant, where order does not arise — so it is latent rather than exploitable. Patched here (modification 15); still present upstream. |
| `check_claim` does not type-check the `b64` header claim | `src/jws/jws_header.rs` | RFC 7797 3 makes `b64` a boolean. Every other typed claim is checked; this one falls through, so `"b64": "false"` is stored and then read back as absent, because the getter only recognises a bool. The sender's instruction is dropped rather than obeyed. Both sides default to `true` the same way, so it fails closed rather than opening anything. Patched here (modification 16); still present upstream. |
| `RsaPssKeyPair::from_der` and `from_pem` fall back to the signing digest for MGF1 | `src/jwk/alg/rsapss.rs` | When the caller passes `mgf1_hash: None`, both take the digest from the `hash` field of the key's algorithm identifier instead of its MGF1 field. A key whose two digests differ is silently rewritten on read, and re-encodes as a different algorithm identifier than it was given. Invisible in the common configuration, where the two digests are equal. Patched here (modification 17); still present upstream. |

Both are worth reporting upstream rather than only patching locally.

Also missing upstream, and **added here** (modification 12): PBES2 had an
iteration-count ceiling but no floor, so `p2c = 1` derived a key encryption key
in a single PBKDF2 round (RFC 7518 §4.8.1.2 recommends at least 1000), and the
encrypt path read `p2c` from the incoming header with no bound at all.

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

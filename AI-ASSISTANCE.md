# How this is built

saffui has one maintainer and is written with AI tooling. The history says so
already, to anyone who looks: branches named `claude/…`, worktrees under
`.claude/`, and a rate of change one person does not type. This document says
which part is the tooling's and which is not, so that a reader is not left to
work it out and guess at the rest.

It is here because a security product is taken on trust before it is taken on
merit, and trust survives a disclosure better than a discovery.

## The design was written down before the code existed

The decisions this server implements were made in thirty planning documents,
twenty-seven of them written before this repository's first commit on 22 July
2026. They cover the backend and its crate split, the protocol surface,
tenancy, data and encryption, the event fabric, the gRPC surface,
observability, operations, offline and air-gapped deployment, the admin
contract, the consoles, and certification. The one deciding the certification
strategy is dated nine days before this repository began.

Those documents are not published. This is the one claim on this page a reader
cannot check, and it is marked as such rather than left to be assumed. What can
be checked is what the decisions became, and the rest of this page is about
that.

The implementation was written against them. Where this tree and a plan
disagree, the tree is what runs, and the disagreement is a decision someone
took and should be able to name.

## Decisions that do not move

The unit of work here is the slice, and what a slice does is settled before it
is written. That is why a commit subject states a behaviour rather than a
change: the sentence existed before the diff did.

These are the decisions a later slice is not allowed to drift from:

- which library a thing is built on, one per layer, and never a cryptographic
  primitive written here;
- the provider: the abstraction the implementations sit behind, and what it is
  allowed to expose;
- which algorithms are used, and which are refused;
- the split into crates, and the feature gating that keeps it honest, so that
  nothing which does not serve a request compiles a web framework;
- the layering, with the server no longer naming the store's rows and a guard
  holding it to an allow list;
- the database schema, every migration that moves it, and the policy every
  connection to Postgres follows;
- the design of the wallet and of federation: what a realm presents, what it
  accepts from an issuer or an upstream provider, and what it refuses;
- the certification strategy, and what may be claimed under it.

## What the tooling writes

The implementation under those decisions, the tests around it, and the prose.

The comments and the doc comments throughout this tree are drafted by the
tooling. That is worth saying plainly, because this repository asks its
comments to carry the reason a guard exists, and a reader could take the
sentences themselves as the evidence of a person's judgement. They are not. The
decision each one records was made by the maintainer; the sentence recording it
was drafted and then kept, cut or rewritten.

## A decision, and what became of it

One of those documents settles, before any of this was written, that nothing is
claimed without the validation standing behind it: no FIPS claim without a
module currently validated and running in that mode, and no post-quantum under
such a claim until a validated module's boundary actually contains ML-KEM and
ML-DSA.

In `crates/crypto/src/lib.rs` that is a build failure:

```rust
#[cfg(all(feature = "fips-strict", feature = "pq-hybrid"))]
compile_error!(
    "feature 'fips-strict' is incompatible with 'pq-hybrid': ML-DSA and ML-KEM are not FIPS-validated"
);
```

And in `.github/workflows/rust.yml` a job builds the forbidden pair on purpose
to check that the guard still fires, and that the build broke on the guard's
own message rather than on anything else. A principle, a mechanism, and a test
that the mechanism has not quietly been removed.

## Other decisions visible in the history

Three slices, each a refusal reached by reading rather than by generating:

- [#324](https://github.com/saffui/saffui/pull/324), plain http reaches an
  upstream only when its host is loopback;
- [#391](https://github.com/saffui/saffui/pull/391), an arrival from a provider
  trusted for addresses is linked only to an account that proved the address;
- [#436](https://github.com/saffui/saffui/pull/436), a typed name is counted
  under a key the database does not hold.

[#428](https://github.com/saffui/saffui/pull/428) is the same decision made
about a shape. Work reaches the database through a unit that owns its
connection, because a connection borrowed from a binding goes back to the pool
when the binding drops and not when the transaction ends: work done after a
commit, or a second connection taken while holding the first, held a slot
nobody could use, and a pool with every slot held that way stops without
raising anything. `UnitOfWork` is named in 195 files, and the version that
borrows is the one that gets written when nobody has decided otherwise.

Two habits are worth naming because they shape what gets accepted. A document
is refused where the specification would let part of it be dropped in silence,
rather than read for less than it says. And a test that did not run must not be
able to pass for green, which is why the `pooler` job counts the lines saying a
suite finished and fails when there are too few.

## What stands between a change and `develop`

All of it is readable, and none of it takes the maintainer's word:

- `develop` refuses an unsigned push. The key the history is held to is named
  in `.github/allowed_signers`, so a clone verifies the commits itself.
- `ci` holds the workspace to `cargo fmt --check` and to clippy with warnings
  denied, under seven feature combinations, and runs the tests. `hsm`,
  `postgres`, `pooler` and `pq` drive what a laptop does not. `deny` refuses a
  dependency by advisory, licence or source.
- Every crate but `crypto` forbids `unsafe`, and `crypto` denies it outside the
  five modules that reach OpenSSL's C API, each one saying which call has no
  binding.
- `THREAT-MODEL.md` cites its countermeasures by file and line, and the
  citations move in the same branch as the lines they cite.
- The pull request template asks for what no job observes: which boundary the
  slice crosses, what was run by hand, what breaks if it is wrong, and whether
  reverting is enough.
- `mutants` mutates the lines a pull request changed and reports which of them
  no test holds to anything.

## What is missing

No second person has read this code. For a product whose whole purpose is to be
trusted with other people's identities, that is the honest limit of everything
above, and no amount of tooling closes it.

What is planned against it, in order: the OpenID Foundation conformance suite
run in CI, an external audit, and a second reviewer. Until those exist, read
the plans, read the threat model, run the rigs under `deploy/`, and judge the
artifacts rather than this page.

`SECURITY.md` says where a finding goes.

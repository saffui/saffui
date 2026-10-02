# How this is built

saffui has one maintainer and is written with AI tooling. The history says so
already, to anyone who looks: branches named `claude/…`, worktrees under
`.claude/`, and a rate of change one person does not type. This document says
which part is the tooling's and which is not, so that a reader is not left to
work it out and guess at the rest.

It is here because a security product is taken on trust before it is taken on
merit, and trust survives a disclosure better than a discovery.

## What the maintainer decides

These are settled before any code is written for them, and none of them is
delegated:

- which library a thing is built on;
- the provider: the abstraction the implementations sit behind, and what it is
  allowed to expose;
- which algorithms are used, and which are refused;
- the database schema, and every migration that moves it;
- the design of the wallet and of federation: what a realm presents, what it
  accepts from an issuer or an upstream provider, and what it refuses.

A slice that would change one of these is not a slice. It is a decision taken
first, and then written down.

## What the tooling writes

The implementation under those decisions, the tests around it, and the prose.

The comments and the doc comments throughout this tree are drafted by the
tooling. That is worth saying plainly, because this repository asks its
comments to carry the reason a guard exists, and a reader could take the
sentences themselves as the evidence of a person's judgement. They are not. The
decision each one records was made by the maintainer; the sentence recording it
was drafted and then kept, cut or rewritten.

## Where a decision is visible in the history

Three slices, each one a refusal reached by reading rather than by generating:

- [#324](https://github.com/saffui/saffui/pull/324), plain http reaches an
  upstream only when its host is loopback;
- [#391](https://github.com/saffui/saffui/pull/391), an arrival from a provider
  trusted for addresses is linked only to an account that proved the address;
- [#436](https://github.com/saffui/saffui/pull/436), a typed name is counted
  under a key the database does not hold.

Each of them narrows what the server accepts, and each depends on a boundary
`THREAT-MODEL.md` names. Nothing in the code as it stood asked for them.

[#428](https://github.com/saffui/saffui/pull/428) is the same decision made
about a shape rather than about a rule. Work reaches the database through a
unit that owns its connection, because a connection borrowed from a binding
goes back to the pool when the binding drops and not when the transaction ends:
work done after a commit, or a second connection taken while holding the first,
held a slot nobody could use, and a pool with every slot held that way stops
without raising anything. The commit consumes the unit and the slot comes back
with it. `UnitOfWork` is named in 195 files, and the version that borrows is the
one that gets written when nobody has decided otherwise.

The wallet and the federation arms are the clearest case of the division above.
What a realm presents to a wallet, which issuers it trusts and through which
authorities, and what a SAML or OpenID Connect upstream is believed about a
person, were decided first and written second.

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
the threat model, run the rigs under `deploy/`, and judge the artifacts rather
than this page.

`SECURITY.md` says where a finding goes.

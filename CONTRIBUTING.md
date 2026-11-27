# Contributing to saffui

saffui is pre-alpha and has a single maintainer. The design still moves and
review time is limited. Both shape what follows.

## Before you write code

Open an issue first and say what problem you want to solve. Wait for an
answer before starting anything larger than a typo or an obvious fix. A
change that goes against a decision already taken costs you the work and
costs the maintainer the review.

Do not open an issue for a vulnerability. Report it privately, as the
[security policy](.github/SECURITY.md) explains.

## Building and testing

The toolchain is pinned in `rust-toolchain.toml`, and rustup uses that
version inside the repository. CI runs five commands, and a pull request
needs all five to pass. The last one needs cargo-deny, at the version
pinned in `.github/workflows/ci.yml`.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
scripts/dev-postgres.sh gen-schema --check
cargo deny check -D index-failure
```

The tests need a PostgreSQL cluster. `scripts/dev-postgres.sh start`
starts a throwaway one on the loopback interface, creates the roles the
tests use, and prints the `SAFFUI_TEST_PG` line to export. It looks for
PostgreSQL 15 from Homebrew; `SAFFUI_DEV_PG_BIN` names another.

```sh
eval "$(scripts/dev-postgres.sh start)"
```

A migration changes the table and column constants the store compiles
against. `scripts/dev-postgres.sh gen-schema` writes
`crates/store/src/schema/generated.rs` from a database the migrations
built, and `--check` fails when the committed file differs from it.

Run the five commands before you push. `unsafe` code is forbidden and
clippy's pedantic lints are enabled across the workspace, except in the
crypto crate, a fork kept as it is: it reaches the C API of OpenSSL where
its binding exposes nothing, allows `unsafe` back in the five modules
that need it, and holds only its adapters to the pedantic lints. CI
treats every warning as an error.

## The conformance bench

`conformance/run.sh` runs the conformance suite of the OpenID Foundation
against a node built from your tree: nine plans for an OpenID provider
with static clients (Basic, Implicit, Hybrid, each also with Form Post,
Config, RP-Initiated Logout and Front-Channel Logout). It tells, it never
gates: no pull request requires it, and `.github/workflows/conformance.yml`
runs it once a day and on demand. GitHub turns that schedule off after
60 days without activity in the repository; turn it back on in the Actions
tab.

```sh
conformance/run.sh
```

It needs Docker with Compose v2, run with root (a daemon without root
cannot let the runner write its exports, and the script stops), `python3`
3.11 or later with `pip`, and the PostgreSQL that `scripts/dev-postgres.sh`
looks for. It builds the binary, starts a node on a database of its own,
provisions a person and five clients, and runs the plans; every secret it
draws, the root key included, is new for each run. `conformance/run.sh
check-tree` refuses under `conformance/` any file but its scripts, lists
and settings in printable ASCII, any it cannot read, and any that holds
PEM armor, a PuTTY key or the member `kty` of a JSON Web Key; a key in
another form that is printable ASCII, base64 for one, it does not see.

On your machine, as you, run the node, its cluster, `pip`, which fetches
the wheels of the runner and installs nothing, and the two scripts of the
bench that provision the node and summarize the run. In containers run the
suite, its database, the proxies, and the runner of the suite with its
wheels: the runner runs as your user, on a root it cannot write, with its
scripts, its wheels and the configurations read-only and the exports alone
writable. Only `conformance/` and four directories of `target/conformance/`
(`runner`, `wheels`, `configs` and `exports`) are mounted in it; your home
directory is not.

It fetches five images, pinned by digest in `conformance/compose.yaml`, the
scripts of the runner at the commit `conformance/suite.lock` names, each
checked against its SHA-256, and the wheels of
`conformance/requirements.txt`, each checked against its hash. A fetch that
fails, or a file that does not match its pin, stops the run before anything
of it runs: that is not a deviation of saffui. Nothing updates these pins:
to move to a new release of the suite, read its tag, take the digests of
both its images and of the four scripts at its commit, check the wheels the
runner needs, and change the three files together.

The suite, its database and its runner are on a network with no way out.
Each run checks it from the server of the suite before it provisions
anything: its gateway must be no address at all (under Linux, none of this
host either), an address off the network unreachable or silent, no name
known, and IPv6 off there and in the runner; anything else stops the run.
Only nginx and Caddy, which give the node its origin `https://saffui.test`,
reach the host. The API of the suite is published on `127.0.0.1:8443`
without any credential: do not browse the web while a run lasts, since a
page could reach it through your browser.

What a run leaves is under `target/conformance/`, never committed: the
exports of the suite, which hold the whole configuration and its secrets,
the journals, and `summary.txt`, which says for each module its result,
how long it ran, and the name of each condition that failed or warned. A
run cut short, by an interrupt or by the 38 minutes CI gives its step,
still summarizes the plans that ended. CI keeps the summary alone, for
seven days.

The runner exits with 1 on a warning, a skip or a failure it was not told
to expect, and on an expected one that did not happen: the two lists of
`conformance/expected-*.json` say what is expected. An entry names its
module, condition and block as `--verbose` prints them, and its comment
says the standard that allows the result and why saffui answers so; a
deviation with no such standard is a defect to fix. Options after `--` go
to the runner: `-- --verbose`, or `-- --rerun 2:6` for one module again.

## What a change looks like

A pull request does one thing: a behaviour that fits in one sentence. That
sentence is its title. If you need "and" to join two changes, send two pull
requests.

A new behaviour comes with the test that proves it, and a fix comes with a
test that fails without it. If the change makes a document wrong, correct
the document in the same pull request.

A few habits of the code base:

- A function name says what the function does: a verb and its object.
- A comment states a constraint the code cannot show, such as a security
  invariant or an order that matters. It does not restate the next line.
- A new dependency needs a reason. Say in the description what it brings
  and why it is not written here.
- Do not copy third-party code into the repository without discussing it
  first. It would have to be recorded with its license.

Only send what you understand. You will be asked why the code does what it
does, and a change that its author cannot explain is not merged.

Dependency updates are opened by Dependabot. There is no need to send them
by hand.

## AI tools

You may use AI tools to write or review a change. The rules above do not
change: you answer for every line, and a change you cannot explain is not
merged. If a tool helped, say so in a comment on the pull request. Do not
list a tool as an author or in a commit trailer.

The maintainer works the same way. Tools write a large part of saffui,
its core included, and review every change. The maintainer reads each
change before it is merged and answers for every line.

## Commit messages and pull requests

Pull requests are merged by squash. The title and the description of the
pull request become the commit on `develop`, so write them as a commit
message. They are what remains in the history.

### Title

```
<type>(<scope>): <description>
```

The title follows
[Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).
Write the description in the imperative ("add", not "added" or "adds"), in
lowercase, without a final period. Keep the whole title within 65
characters, because the pull request number is appended to it. Say what
changes for whoever uses saffui, not how the code does it: "refuse an
unknown option with exit code 2", not "add error handling".

| Type | Use it for |
|---|---|
| `feat` | a new behaviour |
| `fix` | a behaviour that was wrong |
| `perf` | the same behaviour at a lower cost, with a measurement |
| `refactor` | the same behaviour in a different shape |
| `test` | tests only |
| `docs` | documentation only |
| `build` | Cargo manifests, toolchain, dependency policy |
| `ci` | workflows and automation |
| `chore` | repository upkeep |
| `revert` | reverting a commit |

The scope is optional. It names the crate or the area that the change
touches. Add `!` before the colon when the change breaks something a user
relies on.

### Description

Write plain text without Markdown headings: it is read in `git log`.
Describe the problem first, in the present tense, as the code behaves
without your change. Then say what the change does, in the imperative, and
why it does it this way. Add what it costs or breaks if there is anything
to say. A change that the title fully describes needs no description.

End with `Fixes #123` when the pull request fixes an issue, or `Refs #123`
when it only relates to one. A breaking change adds a line that starts with
`BREAKING CHANGE:` and says what breaks and what to do about it.

For example:

```
fix(cli): exit with code 2 on an unknown option

saffui exits with 0 when it is given an option it does not know, so a
script cannot tell a typo from a success.

Return a usage error instead and print the help on stderr. A test runs
the binary with an unknown option.

Fixes #123
```

Notes that only serve the review, such as the commands you ran or where to
start reading, go in a comment on the pull request, not in the description.

### Commits in your branch

Keep each commit to one logical change that builds on its own. They help
the review, and they are squashed at merge. Sign them: the protected
branches require verified signatures.

Once the pull request is open, add commits instead of rewriting the branch,
so that a review can follow what changed. If `develop` has moved, merge it
into your branch.

## Review and merge

Target `develop`. `main` only receives releases. Open the pull request as a
draft while it is not ready.

The maintainer reviews and merges. The four CI checks must pass on a
branch that is up to date with `develop`, and every review conversation
must be resolved.

## License

saffui is licensed under the Apache License, Version 2.0. As section 5 of
the license states, a contribution you submit for inclusion is licensed
under the same terms.

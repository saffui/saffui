# Contributing

saffui has one maintainer. That is worth knowing before you spend a weekend on
it: a pull request may wait, and a large one may be answered with a reason it
will not be taken rather than a review. Opening an issue before writing the
code costs less than finding that out afterwards.

A vulnerability is not an issue. `SECURITY.md` says where it goes.

## Building it

The toolchain is pinned in `rust-toolchain.toml` and rustup installs it on the
first cargo command, components included. From the system it needs a C
toolchain, OpenSSL's headers, and Kerberos's: the SPNEGO bench holds the client
half of a real exchange, so building the workspace's tests links GSSAPI whether
or not the feature is on. On Debian that is `pkg-config`, `libssl-dev` and
`libkrb5-dev`.

```
cargo test --workspace
```

The consoles are a pnpm workspace:

```
pnpm install --frozen-lockfile
```

`deploy/local` brings up a realm to work against, and the other rigs are listed
in the README. They are driven deliberately rather than by CI.

## What the branch looks like

Branches are taken from `develop` and merge back into it. A branch carries one
slice: the behaviour it changes can be said in a sentence, and that sentence is
the commit subject.

Commits carry a subject and nothing else. No body, no trailers, no prefix. The
subject says what the software does after the change, in the present tense, as
a person reading the changelog would want it said. The history is written to be
read.

Commits are signed. The key the history is held to is named in
`.github/allowed_signers`, so a clone verifies it against a file it already
has:

```
git config gpg.ssh.allowedSignersFile .github/allowed_signers
git log --format='%G? %s'
```

`develop` refuses an unsigned push.

## What the pull request answers

The template has the headings. Four of them are there because no job observes
what they ask for: which boundary of `THREAT-MODEL.md` the slice crosses, what
you ran by hand and saw, what breaks if the change is wrong, and whether
reverting it is enough.

"None: this slice does not cross a trust boundary" is an answer, and it is the
usual one. A heading left blank is not.

Where a slice moves lines that `THREAT-MODEL.md` cites, the citations move with
it in the same branch. The document is kept true by line, not by intention.

## What runs before it merges

`ci` holds the workspace to `cargo fmt --check` and to clippy with warnings
denied, under each of the seven feature combinations, and runs the tests.
`deny` refuses a dependency carrying an advisory, a licence outside the list in
`deny.toml`, or a source the project does not take from. `hsm`, `postgres`, `pooler` and `pq` drive what a laptop does not.

`mutants` mutates the lines the pull request changed and reports which of them
no test holds to anything. It does not block a merge. It is read.

## Style

Comments say why a guard exists, not what the line below does. A guard nobody
fires is a guard nobody notices losing, and the comment is how the next reader
knows it is still earning its place.

Nothing is claimed that was not read out of the tree first. That holds for
`THREAT-MODEL.md`, for `README.md`, and for the body of a pull request.

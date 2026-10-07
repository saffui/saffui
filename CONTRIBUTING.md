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
version inside the repository. CI runs four commands, and a pull request
needs all four to pass. The last one needs cargo-deny, at the version
pinned in `.github/workflows/ci.yml`.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo deny check -D index-failure
```

Run them before you push. `unsafe` code is forbidden across the workspace,
clippy's pedantic lints are enabled, and CI treats every warning as an
error.

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

The maintainer works the same way and writes the core of saffui by hand:
the domain types, rules and use cases, the transaction layer, the SQL
builder and the sealing of secrets at rest. Tools review changes and write
some of the code around that core.

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

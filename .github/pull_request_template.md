<!--
The headings below are the ones every pull request answers. A slice that needs
a section of its own, on how a credential is held to its issuer or on what the
parts are, adds it after the first heading and before the last four, as the
slices before it did.

CI already runs fmt, clippy against the feature matrix, the workspace tests,
the HSM, Postgres, pooler and post-quantum jobs, and cargo-deny. None of that
is repeated here. The last four headings ask for what no job observes: what a
person decided, what a person ran by hand, and what it costs if the decision is
wrong.

Leave a heading out only when it does not apply, and say so in those words
rather than deleting it.
-->

## What this does

<!--
The behaviour after the change, stated as behaviour, and what stood there
before it. Not the diff.
-->

## Threat model

<!--
Which boundary in THREAT-MODEL.md this crosses, strengthens or moves, and the
line it is cited at. "None: this slice does not cross a trust boundary" is an
answer, and it is the usual one. Where the document had to move with the code,
say which section was re-anchored.
-->

## Verified by hand

<!--
What was run and observed outside CI, and what was seen: a flow clicked through
in the console, a token decoded, a request replayed, a migration applied and
rolled back. Where nothing was run by hand because a test covers it, name the
test and say why it is enough.
-->

## Blast radius

<!--
What breaks if this is wrong, and who notices first. Name the realms, the
grants, the stored rows or the deployments it would reach. Say plainly where
the failure is silent, as in a token accepted that should have been refused.
-->

## Rollback

<!--
Whether reverting the commit is enough. It is not, where a migration ran, a key
rotated, or a stored shape changed: say what else has to be undone, and in what
order.
-->

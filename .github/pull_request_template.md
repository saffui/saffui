<!--
CI already runs fmt, clippy against the feature matrix, the workspace tests,
the HSM, Postgres, pooler and post-quantum jobs, and cargo-deny. None of that
needs repeating here. What this template asks for is the part no job can
observe: what a person decided, what a person ran by hand, and what the change
would cost if the decision is wrong.

Leave a section out only when it does not apply, and say so in those words
rather than deleting the heading.
-->

## What this slice does

<!-- The behaviour after the change, stated as behaviour. Not the diff. -->

## Threat model

<!--
Which boundary in THREAT-MODEL.md this crosses, strengthens or moves, and the
line it is cited at. "None: this slice does not cross a trust boundary" is an
answer, and it is the usual one. If the document had to move with the code, say
which section was re-anchored.
-->

## Verified by hand

<!--
What was run and observed outside CI, and what was seen. A flow clicked through
in the console, a token decoded, a request replayed, a migration applied and
rolled back. If nothing was run by hand because the tests cover it, say which
test covers it and why that is enough.
-->

## Blast radius

<!--
What breaks if this is wrong, and who notices first. Name the realms, the
grants, the stored rows or the deployments that would be affected. "A startup
failure, before any request is served" is a good answer; so is "silently
accepts a token it should refuse", which is a much worse one and should be
said plainly.
-->

## Rollback

<!--
Whether reverting the commit is enough. It is not, when a migration ran, a key
rotated, or a stored shape changed; say what else has to be undone, and in
what order.
-->

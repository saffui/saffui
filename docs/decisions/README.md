# Decisions

What was decided before the code was written, and what in the tree holds each
decision in place.

These records are written after the fact, from what is in the tree. They are
not the deliberation: the design was settled in planning documents that are not
published, and these say which decisions reached the code and how a later slice
is stopped from drifting from them.

Each one names a mechanism. A decision nothing enforces is a decision until the
first afternoon somebody is in a hurry.

| | Decision |
| --- | --- |
| [0001](0001-the-doors-ask-services.md) | The doors reach the store's rows through services and nowhere else |
| [0002](0002-the-crate-split-and-what-a-feature-is-for.md) | Nothing that does not serve a request compiles a web framework |
| [0003](0003-fips-is-a-build-failure-rather-than-a-promise.md) | A build that cannot hold a claim does not compile |
| [0004](0004-one-connection-policy-and-one-owner.md) | Every connection follows one stated policy, and the work owns the one it runs on |
| [0005](0005-refuse-rather-than-read-for-less.md) | A document is refused rather than read for less than it says |
| [0006](0006-a-test-that-did-not-run-is-not-green.md) | A test that did not run does not pass for green |

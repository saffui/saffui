# A test that did not run does not pass for green

Held in the `pooler` job, and in #433, merged 24 September 2026.

## The decision

A job proves something or it fails. A suite that was skipped, filtered out or
never reached must not leave a run reading as passed.

## What it stands against

The ordinary way a test suite rots. A filter stops matching, an ignored test
stays ignored, a harness exits zero having run nothing, and the badge stays
green for months while the thing it was watching is unwatched.

## How it is held

The `pooler` job pipes the test output through `tee` and counts the lines saying
a suite finished with at least one test passed. Fewer than five and the job
fails with the words "the end to end plane tests did not run; the job proved
nothing."

The same reading applies elsewhere. #433 changed a round trip test to count
requests rather than to time them, because a timing assertion passes on a
machine that is slow for an unrelated reason and tells nobody.

Every job is bounded by a timeout, so a job that hangs fails rather than holding
a runner for the default six hours and leaving the run reading as still in
progress.

## What it costs

A number in the workflow that has to be raised when a suite is split, and a job
that fails loudly the first time somebody reorganises the tests.

# The doors reach the store's rows through services and nowhere else

Landed by #435, #437, #438, #439, #440 and #441, merged 24 September 2026.

## The decision

A door parses a request, opens a unit of work, commits and answers. Which rows
to read or write, and what they mean, is decided below it. The same holds for
the calls out and for the timed passes, which reach the store through services
as the doors do.

## What it stands against

The shape where a handler reaches the store directly. It is quicker to write
and it spreads: the meaning of a row ends up stated in one door, where no other
door shares it and no test of the services sees it. Two doors then disagree
about the same row, and the disagreement is found by a person rather than by a
build.

## How it is held

`crates/server/src/lib.rs` carries a test, `no_door_reaches_the_store_rows_itself`,
which walks the sources of `server`, `outbound` and `scheduler` and fails on any
line naming a part of the store outside an allow list of six. The six are what a
door may name: the unit of work it opens, the seal it opens secrets with, the
errors, the live feed's message and the shape of a listing.

The test reads grouped imports, so `store::{tenancy::Tenancy, audit}` is caught
as the plain form is, and it truncates itself before its own `#[cfg(test)]`
module so that the paths it hunts for do not count as offences.

## What it costs

A service method for work a handler could have done in three lines, and a layer
to step through when reading a request end to end.

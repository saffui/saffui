# A document is refused rather than read for less than it says

Held across `jsonld`, `crypto` and `saml`.

## The decision

Where a specification allows a reader to drop part of a document, or to go on
with less of it than it carries, this server refuses the document instead.

`crates/jsonld` reads strictly: wherever the JSON-LD algorithms would drop part
of a document in silence, and so leave it out of what a proof signs, it refuses
the document, as VC Data Integrity requires.

Revocation reads the same way. A certificate publishing its revocation any way
other than a distribution point naming its whole list at an http or https
address is refused. A delta list, a partitioned one, and an entry another
authority issued are refused rather than read for less than they say.

## What it stands against

A reader that accepts almost anything and is lenient at the edges. What is
dropped in silence is what a proof then does not cover, and the gap between
what a person believes they signed and what the server verified is where the
interesting attacks live.

## How it is held

In the refusals themselves, and in the tests that assert a refusal rather than
a tolerated reading. `THREAT-MODEL.md` cites them by file and line.

## What it costs

Documents that other implementations accept are refused here, and a report of
that is a report worth reading rather than one to be dismissed. Where the
refusal is wrong, it is a bug; where it is right, it is the point.

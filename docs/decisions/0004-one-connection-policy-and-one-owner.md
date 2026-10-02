# Every connection follows one stated policy, and the work owns the one it runs on

Landed by #428 and #429, merged 23 and 24 September 2026.

## The decision

How a connection to Postgres is made, and what it verifies about the server it
reaches, is stated once and handed to every site that opens one, inside the
pool and outside it.

The work that runs on a connection owns it. A unit of work holds the connection
until the commit consumes the unit, and the slot returns with it.

## What it stands against

A connection borrowed from a binding, which is the shape that gets written when
nobody has decided otherwise. It goes back to the pool when the binding drops
rather than when the transaction ends, so work done after a commit, or a second
connection taken while holding the first, holds a slot nobody can use. A pool
with every slot held that way stops, and it stops without raising anything: the
deployment hangs rather than failing.

## How it is held

`UnitOfWork` in `crates/store/src/tenancy.rs` takes the connection rather than
borrowing it, and the commit consumes the unit. It is named in 195 files, so
the shape is the one the tree already has rather than one a new slice has to be
talked into.

`BEGIN` is sent as a statement because the driver's typed transaction borrows
its connection, and a value holding both would refer to itself.

The `pooler` rig drives both planes through a connection pooler, which is where
a slot held too long shows.

## What it costs

A unit threaded through the call path, and a commit that consumes rather than
one that can be called twice.

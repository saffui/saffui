# Operating two or more instances

Several saffui instances against one Postgres are one deployment: every
instance serves every request, state lives in the database, and the jobs
split the work by realm under transaction-scoped advisory locks. There is no
leader and nothing to elect; a deliberate decision, recorded with the
two-writer proof.

What holds this together, and where it is proven:

- **The audit chain cannot fork.** Appends serialise in the database itself
  (the chain head is taken `FOR UPDATE` inside `audit_append`), so two
  writers queue rather than branch. Proven in-process by the
  `two_writers` suite, and across real processes by this rig.
- **An outbox event is claimed by one pass at a time** (`FOR UPDATE SKIP
  LOCKED`), and a pass that dies mid-work rolls its claim back whole: the
  survivor redelivers, and the reconcile-then-write far side makes the
  redelivery land as a repeat, never a second creation.
- **Sweep, outbox and federation passes** take a per-realm advisory lock, so
  instances ticking together split the realms instead of doubling the work.

## The rig

```
docker build -t saffui:local .
node deploy/ha/harness.mjs          # add --keep to leave the stack up
```

Two instances (host ports 18080/18081 and 28080/28081), one Postgres, and an
ear playing the provisioned SCIM application. The harness signs in through
both instances and across them, births and mutates people through both at
once, kills whichever instance is mid-delivery, and then asserts: nothing
lost, nothing doubled, the journal verified whole by both instances, and a
rolling restart under a login flood that never fails.

## Runbook: rolling restart, zero downtime

1. One instance at a time, always.
2. Send SIGTERM (`docker stop`, a pod eviction). The instance fails its
   readiness first, keeps answering traffic for the 5-second drain so the
   orchestrator routes around it, finishes what is in flight, then exits.
   Give it a grace period longer than the drain; 30 seconds is plenty.
3. Wait for `/readyz` on the replacement before touching the next instance.
   `/readyz` also refuses when the database schema is ahead of the binary,
   which is what makes step 4 safe.
4. Upgrades in this order: migrate first, then replace instances one by one.
   An old binary against a newer schema takes itself out of service rather
   than writing what its peers can no longer read.

## Runbook: an instance died

Nothing to repair; the guarantees above are crash-shaped. Verify rather than
assume:

1. `GET /admin/realms/{realm}/journal/verify` must answer `holds: true`.
2. The outbox drains on its own: whatever the dead instance had claimed
   frees with its connections, and the next pass takes it. Watch
   `event_outbox`: rows in `pending` should be moving; rows in `dead`
   exhausted their eight attempts and are named in the log; they stay
   visible and are yours to decide about.
3. A login mid-flight on the dead instance is lost as a request, not as
   state: the person retries and lands on a live instance.

## Runbook: the database is the deployment

One Postgres is the single point of truth and of failure. Its availability
story (replication, failover, backups) is the platform's, not saffui's;
what saffui promises is only that any number of its instances against that
database stay one coherent deployment.

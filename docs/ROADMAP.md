# Road to v1

What the persistence layer still owes, in the order the dependencies impose,
and the decisions that have to be settled before the work that rests on them.

The rule this list follows: a slice lands schema, provider and tests against a
real server together, and every invariant a test claims is mutation tested.

## Where the schema stands

Five migrations, thirteen tables.

| Migration | Tables |
| --- | --- |
| V001 | `tenants`, `realms` |
| V002 | `users`, `clients` |
| V003 | `user_credentials` |
| V004 | `user_sessions`, `client_sessions`, `one_time_tokens` |
| V005 | `roles`, `groups`, `users_roles`, `users_groups`, `groups_roles` |

Six enums in `models` carry a Postgres type name that no migration declares:
`orgmembershiptypeenum`, `authenticatorrequirementenum`, `policytypeenum`,
`policyenforcementmodeenum`, `decisionlogicenum`, `decisionstrategyenum`. Each
one is a table that has not landed, and each name is aligned with the schema as
its slice arrives, the way the eight already declared were.

## The slices, in order

1. **Organizations.** `organizations`, their domains and their memberships.
   Settles `orgmembershiptypeenum`. Nothing else waits on it, which is why it
   goes first: it is the cheapest slice that removes a dangling name.

2. **Authentication flows.** Flows, executions and authenticator configuration.
   Settles `authenticatorrequirementenum`. Required by anything that decides
   how a user proves who they are.

3. **Authorization services.** Resource servers, resources, scopes, policies
   and permissions. Settles the four remaining names. This is the largest
   slice and the one that most needs splitting across several commits.

4. **Identity providers.** Broker configuration, mappers and federated
   identities. Depends on realms only, so it can move ahead of 3 if the
   brokering work is wanted sooner.

5. **Realm keys.** Signing keys and the data encryption keys, with their
   rotation. Everything that mints or verifies a token waits on this.

6. **The audit chain.** An append-only log with a sequence and a previous
   hash, one serialized writer, and the heads and anchors that let a reader
   verify it was not cut. See decision D4 before starting.

7. **Cluster membership.** The node table and the leader row. The schema
   contraction gate reads it: a contraction is only safe once every live node
   runs a version that no longer needs the old shape.

8. **Events.** Partitioned by occurrence, with subscriptions and a dead letter
   table. Retention is a partition drop, which is why it comes after 6: a
   partition may not be dropped before the chain covering it is anchored.

9. **Compliance.** The records the compliance entities already model.

10. **Replay order.** One catalogue naming every realm-scoped table and the
    order it must be replayed in, shared by export and import so the two
    cannot disagree.

## Foundation work, independent of any table

- **F1. A maintenance role.** `saffui_app` is `NOBYPASSRLS`, which is correct
  for the application and wrong for a backfill: a data migration walking every
  tenant sees nothing. A second role, used by the runner only, is needed before
  the first data migration.

- **F2. A compatibility window.** The binary should refuse to start against a
  schema it does not understand, in either direction. `MigrationRunner::status`
  is the read that answers it without applying anything. See D1.

- **F3. Destructive migrations.** A migration that drops is not a migration
  that adds, and applying one by habit is how a column comes back empty. The
  distinction should be in the file name and cost an explicit flag.

- **F4. The lock timeout default.** `MigrationOptions::lock_timeout_ms` unset
  means wait forever, and its own comment explains that this is how a migration
  takes the application down with it. The safe default is a few seconds, with
  waiting forever available on request.

- **F5. Resumable backfills.** `DataMigration` promises a cursor that resumes
  rather than restarts. Nothing records the cursor yet.

## Decisions to settle first

- **D1. Who applies.** One process applies, and it is the operator's, not a
  node serving traffic. A starting node verifies and refuses, it does not
  migrate. Nothing in the code decides this yet, and F2 is the shape of the
  answer.

- **D2. Numbering.** Three digits allow 999 migrations, which is not the
  constraint. Changing the width later renames history, so it is settled now or
  never.

- **D3. Backfill isolation.** Whether the maintenance role of F1 bypasses row
  level security or is granted per table. Bypassing is simpler and gives one
  role the whole estate.

- **D4. One log or two.** Either the audit chain is its own table and events
  are a separate stream, or the events table carries the sequence and the hash.
  Two designs cost two writers and two verifiers.

- **D5. One binary or two.** A single artifact with subcommands shares the
  configuration and the schema window for free. Two binaries keep the serving
  path smaller. This decides where the command line work lands, not whether it
  happens.

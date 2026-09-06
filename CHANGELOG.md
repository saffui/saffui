# Changelog

All notable changes to saffui are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
No version has been tagged yet; entries accumulate under Unreleased until the
first release is cut.

## [Unreleased]

### Added
- A two-instance rig (`deploy/ha/`): compose file, a SCIM-shaped counting
  far side, and a harness that logs in through both instances and across
  them, mutates people through both at once, kills one mid-delivery, and
  asserts the journal verifies whole and no outbox event is lost or lands
  twice. Runbook stubs for rolling restarts and instance loss ride along.
- Registered client defaults (`default_max_age`, `default_acr_values`) now
  instruct the authorization endpoint when the request is silent.
- The consent screen offers the client's registered privacy policy and terms
  pages as links, https only.
- The signup page shows the realm's password rules as a living checklist,
  ticked while the person types; the server keeps sole judgement.
- The verification mail leaves at registration, so the page's promise that
  one is on its way is kept.

### Changed
- The server test harness clones a per-binary template database instead of
  re-migrating and re-provisioning for every test.

### Fixed
- The server drains on SIGTERM as it always did on SIGINT: readiness fails
  first, in-flight requests finish, and only then does it stop. A `docker
  stop` or a pod eviction used to kill it outright.
- A one-time token bound to no login is spendable from whichever login of
  that person follows it.
- Test rigs stop their local servers abruptly on cleanup, so a keep-alive
  connection can no longer hang a run.

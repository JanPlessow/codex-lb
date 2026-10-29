# Integration context

The original publication commit `8332aac` captured the installed 1.24.0 source
and current macOS dispatcher. The integrated build combines that feature line
with upstream main `72630bb` (1.25.0-beta.9); it is not byte-identical to the old
installation. Newer refresh ownership, token CAS, cancellation, overload
retention, role authorization, and replay ownership remain in use.

The original dispatcher came from claude-mac-ops `83784e41`. Its format was
adapted to this repository and malformed native binding configuration is now
rejected explicitly. The canonical PoolTests behavioral suite is retained in
`tests/unit/test_dispatcher.py` and runs on macOS.

The additive migration `20261029_000000_merge_local_feature_history` joins the
main and local-browser heads without renaming deployed revisions. The topology
checker accepts a historical branch only after it converges with every base
head. Tests upgrade empty, main, and local schemas and preserve synthetic
credentials and browser associations.

Integration reproductions exposed two old snapshot defects: a revoked listener
accepted new tunnels using its cached route, and an enabled quota cutoff
admitted accounts with no reported windows. Tunnels now validate current route
ownership and revoked listeners stay closed until explicitly reopened. Pool
admission requires at least one fresh non-placeholder window; a weekly-only
plan remains supported.

Local host mutations use `security:write` and current dashboard step-up rules.
Browser mutations retain verified password sign-in, raw loopback-peer checks,
and strict same-origin constraints. Read-only conversation access is insufficient.

The source checkout remains required for the serving-identity digest, and the
browser and dispatcher remain macOS capabilities. No private deployment state,
accounts, tokens, profiles, or generated assets are distributed. The running
installation is not modified by publishing or merging this source.


## Local verification before the integration PR

The frontend build and lint/type checks passed. The full frontend run passed
1,657 tests and exposed three missing locale/endpoint inventory entries; after
repair, the 173-test accounts, locale, and handler suite passed. Backend runs
covered 419 routing/config/browser tests, 95 OAuth/dispatcher/migration checks,
and six route-level native replay variants. The last migration, dispatcher, and
refresh run passed 83 tests plus 19 subtests, including fence-enabled concurrent
waiters, cancellation, peer rotation, and token compare-and-set cases. These
counts overlap and are not a combined total.

An isolated fresh service started, served the built dashboard, accepted admin
setup, measured the native executable, and returned dispatcher metadata. Empty
pool admission stayed closed, sealed settings returned 409, and missing request
identity returned 409. No operator accounts or credentials were copied. The
full cloud suite, PostgreSQL lane, and macOS dispatcher lane remain required
before merge.


Cloud CI exposed migration replay over existing browser tables, stale routed-probe test doubles, collection-time quota samples expiring during the full suite, and Orca scope copying before shared request state existed. The integration repairs those failures with populated ledger-recovery coverage, per-test fresh samples, Linux-safe browser capability stubs, and existing route-level 413 regression tests. Inherited Rust and Python security findings are resolved by targeted dependency updates; supported compression and proxy features remain enabled, and advisory checks are not waived.

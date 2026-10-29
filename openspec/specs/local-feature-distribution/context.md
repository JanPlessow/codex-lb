# Publication evidence and limits

This development branch shares the installed LB feature line captured on
October 29, 2026. Its application and frontend source match the installed
`ec1031ef8ae5ebe91902b1062deb62768378daca` tree. The public snapshot has an
upstream 1.24.0 parent and excludes deployment-specific browser account notes
from its commit history. Test and handoff additions do not change the LB runtime.

The three bundled dispatcher files instead match the currently deployed
`dispatcher-7cb22dd252d1` generation, whose implementation is already published
in `JanPlessow/claude-mac-ops` at
`83784e41c69d8e619e302e732ac34368c63dd819`. This replaces the older dispatcher
captured in the LB snapshot. No installer or private hook/personal files are
needed to import the dispatcher; setup requirements are in
[the installation guide](../../../docs/local-feature-build.md).

## Checks performed

- A fresh `uv sync --frozen --dev` and Bun 1.3.14 frozen dependency install
  completed. The TypeScript check and production dashboard build passed.
- Frontend lint passed. The browser-flow, accounts-page, and account-detail
  frontend tests passed: 3 files, 10 tests.
- A fresh SQLite database upgraded to
  `20261020_000000_add_local_browser_personas`; migration policy passed and the
  drift check reported no differences.
- An isolated server started with a fresh database and built dashboard. Password
  setup, policy configuration, current-dispatcher native binding and metadata,
  closed admission for an empty pool, policy sealing, and rejection of missing
  serving identity passed. No account was imported and no model request was
  issued. This validates local bootstrap, not authenticated usage on another
  machine.
- The measured-quota selection regression has four cases. Both below-quota
  cases failed against the pre-fix implementation; both real-exhaustion controls
  passed. All four passed with the installed fix. The previous unit assertion
  that treated concurrency pressure as measured quota was updated.
- The current dispatcher's 32 `PoolTests` and 19 subtests passed using tests
  extracted from its pinned canonical commit against the bundled implementation.
- OpenSpec validation passed for all 59 specifications with existing warnings.
  The publication change passed strict validation.

## Existing validation failures

This branch is a source handoff, not a fully green release candidate. The
installed runtime source was preserved instead of expanding publication into a
behavior-change project.

The broader LB feature run reached 457 passing tests and two failing
`test_pool_policy` parameter cases before being interrupted at a browser
transport test that did not complete. The failing cases expect missing primary
or secondary quota windows to reject admission; the installed implementation
permits single-window plans. These expectations and the intended complete
quota-evidence policy need reconciliation before declaring that suite green.

A separate bounded browser/OAuth run completed with 85 passing and 11 failing
tests. Ten failures were in the preexisting OAuth flow suite; several directly
reported test doubles that do not accept the new `account_id` routing argument.
The other failure was a 20-second timeout in
`test_live_tunnel_is_revoked_and_port_retains_persona_ownership`. Those failures
have not been adjudicated as test-only or runtime defects. Counts from the two
runs overlap and must not be added.

Repository-wide Python lint, formatting, and typing are not green. The first
lint check on the historical snapshot reported eight issues; the current
dispatcher is copied unchanged from its canonical repository and uses that
repository's style. Formatting found five files that would change, type checking
reported 45 diagnostics, and the architecture check found 1,102 lines in
`streaming/mixin.py` against a 1,100-line limit. These are recorded rather than
silently reformatted or suppressed during source publication.

Full unit/integration/e2e, PostgreSQL, package, Docker, Helm, Kind, and browser
automation gates were not completed. Actual Chrome launches and authenticated
model traffic were not exercised in this publication task. Use this branch to
inspect and reproduce the current features; complete those gates before a
separate merge or release decision.

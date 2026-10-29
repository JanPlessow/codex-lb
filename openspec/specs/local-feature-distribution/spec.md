# Local Feature Distribution

## Purpose

Make the complete locally deployed Codex LB feature line available as a
reproducible source checkout without publishing private installation state.

## Requirements

### Requirement: Complete source publication
The distribution SHALL include the application, frontend, dispatcher, and local
database migrations from the installed feature line. It SHALL exclude account
credentials, browser profiles, local databases, deployment-specific identities,
and generated build artifacts from new published commits.

#### Scenario: Rebuild the dashboard
- **WHEN** a developer installs the frozen dependencies and builds the frontend
- **THEN** the account browser and Orca actions are available in the built source
- **AND** their platform and configuration requirements are documented.

### Requirement: Reproducible optional dispatcher setup
The distribution SHALL document a source-checkout setup with private dispatcher
state, locally supplied dashboard credentials, a measured native executable,
closed initial admission, and explicit serving-identity validation. It SHALL
identify the macOS requirement and the need for operator-owned accounts.

#### Scenario: Initialize without production state
- **WHEN** a developer initializes a fresh database and dispatcher configuration
- **THEN** metadata can be authenticated and measured against the local LB
- **AND** admission stays closed until the operator opens it after enrollment.

### Requirement: Measured quota governs sticky cutoffs
Measured primary and secondary usage SHALL govern sticky quota cutoffs and
quota-based health draining. Concurrent request pressure SHALL remain available
for routing preference without itself changing measured usage.

#### Scenario: Concurrent requests exceed a soft pressure threshold
- **GIVEN** an existing sticky owner below its measured quota thresholds
- **WHEN** inflight requests raise its effective routing pressure above a threshold
- **THEN** the pressure alone does not reassign the sticky owner or mark it draining
- **AND** actual measured usage above a cutoff still permits reallocation.


### Requirement: Integration preserves deployed histories
The integrated build SHALL upgrade fresh databases, current main databases, and prior local-feature databases to one Alembic head without rewriting deployed revisions or losing account credentials, browser ownership, or terminal references. The topology checker SHALL accept an old branch only when a descendant joins that branch and every base head; unjoined forks SHALL remain errors.

#### Scenario: Both published histories converge
- **WHEN** either published history upgrades
- **THEN** the same integration head is reached with existing rows preserved.

### Requirement: Local host actions require privileged access
Browser mutations and Orca terminal commands SHALL require security:write with the dashboard's current step-up policy. Browser mutations SHALL additionally retain verified sign-in, raw loopback peer, and same-origin checks. Conversation readers and operators without security:write SHALL be denied before host actions run.

#### Scenario: Conversation reader requests a local host action
- **WHEN** a signed-in conversation reader requests an account browser or terminal switch
- **THEN** permission is denied and no host process is launched.

### Requirement: Newer routing and refresh invariants remain effective
The integration SHALL preserve request-local overload substitution, shared refresh ownership and cancellation, token compare-and-set persistence, file-account pinning, and reservation settlement while adding the published pool protections and native replay projection.

#### Scenario: Quota pressure has no burn-first candidate
- **WHEN** an owner crosses its measured quota threshold and an eligible lower-quota sibling exists
- **THEN** the request can reallocate independently of burn-first routing.

### Requirement: Revoked browser routes remain closed
The browser listener SHALL retain its port after revocation but SHALL refuse new tunnels until the dashboard explicitly reopens a currently valid persona route. Every new tunnel SHALL validate its saved route before contacting upstream.

#### Scenario: A revoked browser reconnects
- **WHEN** the browser opens another connection after its route was removed
- **THEN** the listener returns an error without opening an upstream connection.

### Requirement: Pool admission requires current evidence
An enabled pool quota cutoff SHALL require at least one current non-placeholder quota window. Plans exposing one window SHALL be admitted when that window meets policy. An account without any quota evidence SHALL be denied.

#### Scenario: No quota windows exist
- **WHEN** a fresh or bound request considers an account without a quota sample
- **THEN** the account is excluded until a current sample exists.

### Requirement: Native replay proof includes derived affinity
Native inline replay SHALL validate lossless input before projection and revalidate after deriving affinity metadata. The final proof SHALL match each dispatched payload, and explicit file, turn-state, and stored-response owners SHALL remain authoritative.

#### Scenario: Derived cache key precedes quota failover
- **WHEN** a native inline request receives a derived prompt cache key and its first account rejects quota before visible output
- **THEN** an eligible second account receives the same projected wire payload
- **AND** the API-key reservation settles exactly once.

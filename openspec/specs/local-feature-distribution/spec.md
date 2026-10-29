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

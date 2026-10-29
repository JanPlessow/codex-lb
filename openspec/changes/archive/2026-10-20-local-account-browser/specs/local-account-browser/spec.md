## ADDED Requirements

### Requirement: Account actions select the account's persistent browser
The local browser capability SHALL be opt-in, macOS-only, and available only to a verified local dashboard administrator. The server SHALL select the executable, profile, and authorization URL. User requests SHALL NOT supply executable paths or arbitrary URLs.

#### Scenario: Reauthenticate a selected account
- **GIVEN** an existing account and a verified same-origin local admin request
- **WHEN** its reauthentication action is clicked
- **THEN** the account's persistent Chrome profile opens or is reused
- **AND** the dashboard browser does not determine the login profile
- **AND** closing and reopening preserves the account's browser data.

### Requirement: Browser and OAuth exchange preserve one route
Managed proxied personas SHALL use exactly one active endpoint, SHALL authenticate using encrypted server-side proxy credentials, and SHALL NOT fall back to another endpoint or a direct route. Route changes SHALL invalidate existing browser tunnels and pending OAuth flows. Listener ownership SHALL persist across restarts and SHALL NOT transfer between personas. The transport SHALL support HTTPS CONNECT and reject other non-loopback HTTP requests explicitly.

#### Scenario: Assigned proxy fails
- **GIVEN** a managed account with a single proxy endpoint
- **WHEN** that endpoint is unavailable or its credentials are rejected
- **THEN** the browser request fails
- **AND** no direct connection to the target is attempted.

#### Scenario: Route changes during authentication
- **GIVEN** a managed browser and pending OAuth flow
- **WHEN** the account binding, endpoint, or proxy credentials change
- **THEN** existing tunnels are revoked and new requests on the stale persona revision fail
- **AND** code exchange does not proceed on the changed route.

### Requirement: Enrollment configures the persona before first login
New-account enrollment SHALL explicitly choose direct routing or a single-endpoint proxy pool before creating its browser flow. Account creation, persona association, and proxy binding SHALL become visible atomically before account activation. Enrollment resolving to an existing account SHALL NOT overwrite its credentials or persona.

#### Scenario: Enroll another account
- **GIVEN** an enrollment with an explicitly chosen route
- **WHEN** authentication succeeds for a new identity
- **THEN** the new account is activated with the same persona and route used during login
- **AND** no unbound account traffic occurs before the binding is committed.

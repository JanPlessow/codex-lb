# Local account browser operations

This capability is a local macOS customization. It is enabled with `CODEX_LB_LOCAL_BROWSER_ENABLED=true` in the installed release's `.env.local`. It is not submitted upstream. It requires Chrome in Applications, the local SQLite store, and an explicitly authenticated dashboard administrator. Refresh the dashboard after installation to load the account-aware actions.

In Accounts, select the account and click Re-authenticate. The backend opens that account's persistent Chrome data directory under the configured data directory's `browser-personas` folder. Reopen account Chrome resumes a pending login in the same profile. Sign-in, consent, and verification codes stay in Chrome. Closing the dialog cancels the pending OAuth flow; it does not remove saved credentials. Closing Chrome does not delete its profile.

For Add account, choose OAuth, then choose Direct or an existing proxy pool before opening Chrome. A managed proxy pool must contain exactly one active endpoint. An existing account cannot be silently reassigned through enrollment; use its targeted reauthentication action. Direct enrollment is rejected when the global proxy policy would route the resulting account differently.

Each profile uses its own loopback CONNECT listener. The listener follows the stored account binding, authenticates to the upstream proxy using the existing encrypted endpoint credentials, and passes HTTPS through without decrypting it. A failed or changed route blocks requests rather than trying another endpoint or going direct. Ordinary non-loopback HTTP is unsupported. Localhost OAuth callbacks bypass the proxy. This feature governs LB-launched account browsers and does not claim system-wide traffic isolation.

If a profile is already running with incompatible proxy flags, quit that dedicated Chrome instance before retrying. If port 1455 is occupied by another sign-in, finish or close that sign-in and retry. Reopening after an LB restart restores both the persisted route and the callback listener. Native launching is intentionally unavailable through a remote dashboard connection.

The local migration adds `browser_personas` and `browser_oauth_flows`. Future upstream updates must carry and reconcile this migration and the local patch before they can use this database. Replacing the installation with an unmodified upstream build will fail its schema checks. The recovery bundle retains the additive model definitions and migration while reverting browser behavior, so rollback does not discard account tokens, persona ownership, or browser data. Do not downgrade by restoring an older account database over newer credentials.

Verification covers local dashboard authorization, isolated direct and proxy profiles, route revocation, callback recovery, and duplicate enrollment. Each installation must perform its own live browser checks with its own accounts.

# Install the local feature build

This build integrates the application, dashboard, and dispatcher features from
the local installation captured on October 29, 2026, with the fork's newer
`main` (1.25.0-beta.9). Build from this repository to obtain those features.
This source integration does not install or release a packaged application.

The requirements for this distribution are in
[Local feature distribution](../openspec/specs/local-feature-distribution/spec.md).
The browser contract and operating notes are in
[Local account browser](../openspec/specs/local-account-browser/spec.md) and its
[context](../openspec/specs/local-account-browser/context.md).

## Included features

| Capability | Setup and platform |
| --- | --- |
| Persistent account-specific Chrome profiles, direct/proxy enrollment, reauthentication, and callback recovery | Opt-in; macOS, local SQLite, Google Chrome in Applications, and a password-authenticated local dashboard session |
| Account-specific OAuth and probe routing | Configure account proxy bindings in Settings; credentials belong to your installation |
| Request-log links that open the originating Orca terminal | Orca CLI on the server's PATH; the caller supplies `x-orca-terminal-handle`; local dashboard security:write permission and recent verification |
| Native inline Responses replay | Opt-in with `CODEX_LB_NATIVE_INLINE_REPLAY_ENABLED=true` |
| Protected account identities, fresh/bound quota cutoffs, and durable refresh fencing | Opt-in settings below; choose your own identity exclusions |
| Measured serving identity and isolated native Codex dispatcher | Source checkout, macOS, a native Codex executable, and private dispatcher configuration |
| Measured quota separated from concurrent-request pressure | Included automatically; active streams still affect routing pressure, but do not by themselves cross measured quota thresholds |
| Updated host-model choice for internal probes and images | Included in the source; actual model availability still depends on the account |

The bundled dispatcher matches the deployed generation `dispatcher-7cb22dd252d1`.
Its three source files originated from
[claude-mac-ops commit 83784e41](https://github.com/JanPlessow/claude-mac-ops/commit/83784e41c69d8e619e302e732ac34368c63dd819).
Repository formatting and native-binding validation were adapted during integration.
The bundled canonical regression suite covers the current session history/resume, settlement, workspace trust, and
optional personal-settings/hook inheritance support to the older dispatcher
that was captured in the LB snapshot. Optional `CODEX_POOL_PERSONAL_DIR` files
and Orca hook files belong to the operator; they are not included here.

The core LB does not require Orca. Native Chrome launching and the dispatcher
process tracker require macOS. A remote dashboard cannot launch a local account
browser. This repository does not contain account tokens, proxy credentials,
browser profiles, databases, encryption keys, or machine service configuration.

## Build and start from source

Install Git, Python 3.13 or newer, `uv`, and Bun 1.3.14. Use a fresh data directory
for the first installation:

```sh
git clone --branch main --single-branch \
  https://github.com/JanPlessow/codex-lb.git
cd codex-lb
uv sync --frozen --dev
(cd frontend && bun install --frozen-lockfile && bun run build)
mkdir -p .local/data
chmod 700 .local/data
export CODEX_LB_DATA_DIR="$PWD/.local/data"
uv run codex-lb-db upgrade head
uv run codex-lb-db check
uv run codex-lb --host 127.0.0.1 --port 2455
```

Open `http://127.0.0.1:2455`, configure a dashboard password, and enroll your own
accounts. The frontend build writes ignored files to `app/static`; these assets
must be rebuilt after changing frontend source. Do not install the upstream
PyPI package or use an upstream container image expecting this branch's patches.

Keep the data directory stable across restarts. It contains the database and
encryption key needed to decrypt your credentials. When migrating an existing
installation, preserve its database and matching encryption key together. Do not
point an unmodified upstream build at this branch's database: the local Orca and
browser migrations are part of its schema. Replacing current data with an older
snapshot can also overwrite refreshed credentials.

## Enable account browsers

Stop the process, add the following to the checkout's ignored `.env.local`, and
restart using the same data directory:

```dotenv
CODEX_LB_LOCAL_BROWSER_ENABLED=true
```

Use the local dashboard and sign in with its password. Browser actions require
`security:write` (the administrator preset) and the dashboard's recent-verification policy. In Accounts,
Re-authenticate opens the selected account's persistent profile. Add account
allows explicit Direct or proxy-pool selection. Each managed proxy pool must
have exactly one active endpoint. Enter your proxy credentials through the
dashboard, then perform your own sign-in and verification challenges in Chrome.
See the browser context linked above for route changes and callback recovery.

## Enable the optional native pool

Run this capability from the source checkout: its serving identity hashes
`app/**/*.py`, `pyproject.toml`, and `uv.lock`. A standalone wheel does not contain
all of those source-adjacent inputs.

Before starting the LB, add these settings to `.env.local`. Replace the example
email with the desktop identity you want excluded from automation. Principals
can also be excluded with a JSON array in `CODEX_LB_POOL_PROTECTED_PRINCIPALS`.

```dotenv
CODEX_LB_NATIVE_INLINE_REPLAY_ENABLED=true
CODEX_LB_POOL_PROTECTED_EMAILS='["desktop-user@example.com"]'
CODEX_LB_POOL_FRESH_WORK_CUTOFF_PERCENT=95
CODEX_LB_POOL_BOUND_WORK_CUTOFF_PERCENT=99.5
CODEX_LB_POOL_USAGE_MAX_AGE_SECONDS=180
CODEX_LB_POOL_REFRESH_REPLAY_FENCE_ENABLED=true
CODEX_LB_POOL_SERVING_CONTRACT_ENABLED=true
CODEX_LB_HTTP_RESPONSES_SESSION_BRIDGE_ENABLED=false
CODEX_LB_UPSTREAM_STREAM_TRANSPORT=http
CODEX_LB_HTTP_DOWNSTREAM_TRANSPORT_POLICY=always_http
```

Restart the LB. In dashboard Settings, enable API-key authentication and select
HTTP for upstream transport and Always HTTP for downstream transport. Complete
all dashboard policy changes before requesting dispatcher metadata: that request
seals the serving policy until the next LB restart. Ordinary clients that omit
the measured identity header cannot use Responses endpoints while this contract
is enabled. Use the dispatcher for this mode.

In another terminal, from the same source checkout, create the private
dispatcher configuration. `CODEX_NATIVE` must resolve to the actual installed
Codex executable or a supported npm entrypoint. A custom shell wrapper will be
rejected. The password is read from the terminal and is never printed.

```sh
export CODEX_POOL_ROOT="$PWD/.local/dispatcher"
export CODEX_NATIVE="$(command -v codex)"
uv run python - <<'PY'
import getpass
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path("dispatcher/bin/codex-ring").resolve()))
from pool import pin_native, private_path

os.umask(0o077)
root = Path(os.environ["CODEX_POOL_ROOT"]).resolve()
root.mkdir(mode=0o700, parents=True, exist_ok=True)
private_path(root, directory=True)
native = Path(os.environ["CODEX_NATIVE"]).resolve()
binding = pin_native(native)
config = {
    "endpoint": "http://127.0.0.1:2455",
    "admin_password": getpass.getpass("LB dashboard password: "),
    "admission": "closed",
    "require_serving_identity": True,
    "native_binaries": {str(native): binding},
}
with (root / "dispatcher.json").open("x") as stream:
    json.dump(config, stream, indent=2)
    stream.write("\n")
print("Private dispatcher configuration created; admission remains closed.")
PY

uv run python dispatcher/bin/codex-pool --root "$CODEX_POOL_ROOT" \
  metadata --profile implementation --native "$CODEX_NATIVE"
uv run python dispatcher/bin/codex-pool --root "$CODEX_POOL_ROOT" status
```

The metadata command verifies the native executable, authenticates against the
LB, and measures the current serving policy. The status output is private account
information; do not paste it into an issue or commit it. Enroll a non-protected
account and verify its usage before opening admission:

```sh
uv run python dispatcher/bin/codex-pool --root "$CODEX_POOL_ROOT" trust-workspace "$PWD"
uv run python dispatcher/bin/codex-pool --root "$CODEX_POOL_ROOT" open
uv run python dispatcher/bin/codex-pool --root "$CODEX_POOL_ROOT" \
  interactive --native "$CODEX_NATIVE"
```

Workspace trust covers the approved directory and its subdirectories. Approve
only the workspace you intend the job to access; additional writable directories
need their own approval. The interactive profile defaults to `workspace-write`
with `on-request` approvals; explicit bypass options change those protections. For a constrained automation job, use `metadata`, `new`, and
`run` with the `review` (read-only) or `implementation` (workspace-write) profile;
pass the returned identity as `--expected-identity` at allocation and execution.
Run `--help` on those commands for their argument order. Close finished sessions
to revoke their per-session API keys. If a job ends with an uncertain state,
inspect and reconcile it before resuming.

After a Codex upgrade, inspect the new executable and refresh its approved
binding in the private configuration. After an LB or serving-policy change,
close admission, finish or reconcile existing jobs, restart the LB as needed,
and obtain a new identity before allocating new sessions. Never reuse a stale
identity by bypassing the validation.

## Verification

The publication checks and their actual results are recorded in
[distribution context](../openspec/specs/local-feature-distribution/context.md).
Local source publication does not demonstrate installation or authenticated
traffic on another computer. Complete your own account sign-in and a request
through the selected route after setup.

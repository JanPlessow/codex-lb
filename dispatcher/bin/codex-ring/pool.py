"""Private native sessions backed by one loopback Responses credential owner.

The dispatcher never reads a ChatGPT credential. Administration uses the proxy's
authenticated API; per-session API keys grant access to the non-desktop pool.
Account eligibility and OAuth refresh remain exclusively in the proxy.
"""

import argparse
import contextlib
import fcntl
import hashlib
import http.cookiejar
import json
import os
import platform
import re
import select
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from functools import lru_cache
from pathlib import Path


def orca_hook_decisions(config):
    """Read Orca's generated hook-state tables without requiring Python 3.11.

    Only scalar decisions in exact hooks.state tables are admitted. Unsupported
    syntax grants no trust; the native remains responsible for checking hashes.
    """
    decisions, current = {}, None
    for line in config.splitlines():
        line = line.strip()
        if line.startswith("["):
            current = None
            header = re.fullmatch(r"\[hooks\.state\.(.+)\]\s*(?:#.*)?", line)
            if header:
                key = header.group(1)
                try:
                    key = key[1:-1] if key.startswith("'") and key.endswith("'") else json.loads(key)
                except ValueError:
                    continue
                if isinstance(key, str):
                    current = decisions.setdefault(key, {})
        elif current is not None:
            enabled = re.fullmatch(r"enabled\s*=\s*(true|false)\s*(?:#.*)?", line)
            digest = re.fullmatch(r'trusted_hash\s*=\s*"(sha256:[0-9a-f]{64})"\s*(?:#.*)?', line)
            if enabled:
                current["enabled"] = enabled.group(1) == "true"
            if digest:
                current["trusted_hash"] = digest.group(1)
    return decisions


# What an interactive pane may take from the personal directory's codex.toml,
# each with the exact value shape admitted. Effort values are the set the
# native validates `model_reasoning_effort` against.
PERSONAL_SETTINGS = {
    "model_reasoning_effort": r"none|minimal|low|medium|high|xhigh|max",
    "personality": r"[a-z][a-z_-]{0,31}",
}
PERSONAL_FILE_MAX_BYTES = 256 * 1024


class PoolError(RuntimeError):
    pass


def file_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def file_magic(path, length=4):
    with Path(path).open("rb") as stream:
        return stream.read(length)


def pin_native(entry):
    """Resolve the supported npm layout without executing its mutable launchers."""
    entry = Path(entry).resolve()
    payload = entry
    measured = [entry]
    if file_magic(entry, 2) == b"#!":
        # pnpm's .bin shim or npm's resolved JS entrypoint. No arbitrary script
        # parsing, PATH lookup or wrapper execution participates in resolution.
        if entry.parent.name == ".bin":
            package = (entry.parent.parent / "@openai/codex").resolve()
        elif entry.name == "codex.js" and entry.parent.name == "bin":
            package = entry.parent.parent
        else:
            raise PoolError("unsupported native launcher; provide the actual Codex executable")
        metadata = package / "package.json"
        info = json.loads(metadata.read_text())
        if info.get("name") != "@openai/codex":
            raise PoolError("unrecognized Codex package")
        target = {
            ("Darwin", "arm64"): ("darwin-arm64", "aarch64-apple-darwin"),
            ("Darwin", "x86_64"): ("darwin-x64", "x86_64-apple-darwin"),
        }.get((platform.system(), platform.machine()))
        if target is None:
            raise PoolError("native package resolution is not proved on this platform")
        suffix, triple = target
        platform_package = package.parent / ("codex-" + suffix)
        payload = (platform_package / "vendor" / triple / "bin/codex").resolve()
        measured += [metadata, package / "bin/codex.js", platform_package / "package.json", payload]
    magic = file_magic(payload)
    if magic not in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\x7fELF") or not os.access(
        payload, os.X_OK
    ):
        raise PoolError("resolved Codex payload is not a native executable")
    return {"executable": str(payload), "files": {str(p.resolve()): file_sha256(p) for p in measured}}


@lru_cache(maxsize=16)
def native_version(native, digest):
    result = subprocess.run(
        [native, "--version"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=5,
        env=clean_environment(os.environ),
    )
    version = result.stdout.strip()
    if result.returncode != 0 or not version.startswith("codex-cli "):
        raise PoolError("native executable did not report a verified CLI version")
    return version


def supervise(fd, root=None, session=None, report=None):
    """The native process shares this watchdog's process group.

    A pipe owned only by the dispatcher makes SIGKILL/parent death observable,
    including while native is starting. EOF kills this entire isolated group.

    A normal exit writes one completion receipt to *report*, a pipe only the
    launching dispatcher holds: the native's own exit code plus whether every
    process it started was observed and settled. The return code cannot carry
    that -- 125 means both "settlement unproven" and "the native exited 125".
    The parent-death and deadline paths write none.
    """
    with os.fdopen(fd, "rb", buffering=0) as control:
        raw = bytearray()
        while not raw.endswith(b"\n"):
            byte = control.read(1)
            if not byte:
                return 125
            raw.extend(byte)
        command = json.loads(raw)
        deadline = None
        child = None

        def stopping(signum, _frame):
            nonlocal deadline
            if signum in (signal.SIGINT, signal.SIGWINCH) and child is not None and child.poll() is None:
                # The native process SHARES this watchdog's group, so `child.pid`
                # is not a process group id and `killpg` on it raises ESRCH --
                # out of a signal handler, which took the supervisor down with
                # it on every window resize. Signalling the group instead would
                # re-enter this handler, so the target is the process itself:
                # `_exec` execs the native in place, so `child.pid` IS it.
                try:
                    os.kill(child.pid, signum)
                except (ProcessLookupError, PermissionError):
                    # It exited between the poll above and here. Nothing to
                    # interrupt, and the settlement pass below still runs.
                    pass
            else:
                deadline = deadline or time.monotonic() + 3

        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGWINCH):
            signal.signal(signum, stopping)
        from pool_processes import descendants, identity, process_table, settle

        # Hold execution until its kernel identity is registered, so even a
        # native program that immediately detaches a child and exits is known.
        gate_read, gate_write = os.pipe()
        child = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "_exec", str(gate_read)], pass_fds=(gate_read,)
        )
        os.close(gate_read)
        try:
            known = {identity(child.pid)[0]}
            os.write(gate_write, (json.dumps(command) + "\n").encode())
        finally:
            os.close(gate_write)
        observation_complete = True
        while child.poll() is None:
            try:
                known |= descendants(process_table(), known)
            except (OSError, ValueError, subprocess.SubprocessError):
                observation_complete = False
            ready, _, _ = select.select([control], [], [], 0.2)
            if ready and not control.read(1):
                if root and session:
                    try:
                        path = Path(root) / "sessions" / session / "session.json"
                        record = read_json(path)
                        record.update(state="uncertain", outcome="supervisor-parent-death", ended_at=time.time())
                        write_json(path, record)
                    except (OSError, PoolError, ValueError):
                        pass
                settle(known)
                os.killpg(os.getpgrp(), signal.SIGKILL)
            elif deadline and time.monotonic() >= deadline:
                settle(known)
                os.killpg(os.getpgrp(), signal.SIGKILL)
        settled = settle(known)
        native_exit = child.returncode if child.returncode >= 0 else 128 - child.returncode
        if report is not None:
            with contextlib.suppress(OSError, ValueError):
                os.write(
                    int(report),
                    (
                        json.dumps(
                            {
                                "native_exit": native_exit,
                                "settled": bool(settled),
                                "observation_complete": observation_complete,
                            }
                        )
                        + "\n"
                    ).encode(),
                )
        if not settled or not observation_complete:
            return 125
        return native_exit


def read_receipt(fd):
    """The supervisor's receipt, or None. The supervisor has exited, so its end
    is closed; the bounded wait only guards a descendant that kept a copy."""
    data = b""
    try:
        while len(data) < 4096:
            ready, _, _ = select.select([fd], [], [], 1)
            if not ready:
                break
            chunk = os.read(fd, 4096)
            if not chunk:
                break
            data += chunk
    except OSError:
        return None
    finally:
        os.close(fd)
    try:
        receipt = json.loads(data.decode().splitlines()[0]) if data else None
    except (ValueError, UnicodeDecodeError, IndexError):
        return None
    if not isinstance(receipt, dict) or not isinstance(receipt.get("native_exit"), int):
        return None
    return receipt


def tree_bytes(root):
    """Allocated bytes under *root*, without following symlinks."""
    total = 0
    for folder, _, files in os.walk(root):
        for name in files:
            with contextlib.suppress(OSError):
                total += os.lstat(os.path.join(folder, name)).st_blocks * 512
    return total


def private_path(path, *, directory=False):
    path = Path(path).expanduser().absolute()
    for parent in [path, *path.parents]:
        if parent.is_symlink():
            # macOS /var and /tmp are system aliases. Resolve those at the
            # caller; user-controlled aliases are never silently followed.
            raise PoolError("pool paths must not contain symlinks: " + str(parent))
    if path.exists():
        info = path.stat()
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise PoolError("pool state must be owned by you and private: " + str(path))
        if directory != stat.S_ISDIR(info.st_mode):
            raise PoolError("unexpected pool path type: " + str(path))
    return path


def write_json(path, value):
    private_path(path)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary.exists():
            temporary.unlink()


def read_json(path):
    private_path(path)
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        raise PoolError("pool state is missing: " + str(path)) from None


@contextlib.contextmanager
def pool_lock(root):
    """Serialise pool state mutations without leaking the lock descriptor.

    Lives here rather than beside the installer's callers because the dispatcher
    itself has to take the same lock: `dispatcher.json` has several writers now
    that a dispatcher generation can be rolled under a live pool, and a writer
    that reads a record, thinks, and writes the whole record back is a lost
    update waiting for the other writer to commit first.
    """
    lockfd = os.open(Path(root) / "pool.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lockfd, fcntl.LOCK_EX)
        yield lockfd
    finally:
        os.close(lockfd)


def clean_environment(environment):
    banned = {
        "OPENAI_API_KEY",
        "CODEX_API_KEY",
        "OPENAI_BASE_URL",
        "OPENAI_ORG_ID",
        "OPENAI_ORGANIZATION",
        "OPENAI_PROJECT_ID",
        "CODEX_HOME",
        "CODEX_POOL_API_KEY",
        "CODEX_AUTH_JSON",
        "CODEX_CONFIG",
        "CODEX_CONFIG_PATH",
    }
    env = {
        key: value
        for key, value in environment.items()
        if key not in banned and not key.startswith(("CODEX_RING_", "CODEX_LB_"))
    }
    # Only the loopback proxy bypasses ambient network proxies. Tool subprocesses
    # retain their ordinary network environment.
    for key in ("NO_PROXY", "no_proxy"):
        env[key] = ",".join(filter(None, [env.get(key), "127.0.0.1", "localhost", "::1"]))
    return env


VALUE_FLAGS = {
    "-m",
    "--model",
    "-s",
    "--sandbox",
    "-C",
    "--cd",
    "--output-schema",
    "-o",
    "--output-last-message",
    "--color",
    "--add-dir",
    "-i",
    "--image",
}
SWITCH_FLAGS = {
    "--skip-git-repo-check",
    "--ignore-user-config",
    "--json",
    "--dangerously-bypass-hook-trust",
    "--ephemeral",
    "--no-alt-screen",
}
CONFIG_KEYS = {
    "model_reasoning_effort",
    "model_reasoning_summary",
    "project_doc_max_bytes",
    "model_auto_compact_token_limit",
}

# A review caller may opt into ONE narrowing permission profile: Codex's
# `default_permissions=<name>` plus `permissions.<name>.filesystem={...}` that
# grants only "read" (to absolute paths and the `:minimal` baseline) or "none"
# (to absolute paths). No network, extends or other subkey is admitted, and neither is any
# built-in (`:read-only`, `:workspace`, `:danger-full-access`) profile name.
# The one exception is WRITABLE_PROFILES: such a profile may also grant "write" to
# exactly one absolute path that sits inside a path the same table reads.
# The value is re-encoded from what was validated, so the native parses exactly
# the table this check approved rather than its own reading of the caller's text.
PROFILE_NAME = re.compile(r"\A[A-Za-z0-9_-]{1,64}\Z")
PROFILE_TABLE_KEY = re.compile(r"\Apermissions\.([A-Za-z0-9_-]{1,64})\.filesystem\Z")
PROFILE_PATH_FORBIDDEN = re.compile(r"[\x00-\x1f\x7f*?\[\]{}]")
# Profiles admitted to carry one scratch write grant. `close-adjudicated probe`
# (stratos-autopilot) runs a finding's reproduction, which needs somewhere to write
# its output; every other profile, the consult one included, stays read-only.
WRITABLE_PROFILES = {"close_adjudicated_probe"}


# Subcommands an interactive pane must never reach: they manage credentials,
# attach to another server, or mutate the installation the dispatcher measured.
INTERACTIVE_FORBIDDEN = {
    "login",
    "logout",
    "app",
    "app-server",
    "remote-control",
    "update",
    "mcp",
    "plugin",
    "debug",
    "completion",
}

# A conversation is named by the uuid the native puts in the rollout filename and
# repeats inside the transcript's own `session_meta`. Both are checked; neither is
# trusted alone.
UUID_TEXT = r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}"
UUID_PATTERN = re.compile(r"\A" + UUID_TEXT + r"\Z")
# `archived_sessions` is flat and `sessions` is date-nested, so the date comes from
# the NAME rather than from the directory a transcript happens to sit in.
ROLLOUT_PATTERN = re.compile(r"\Arollout-(\d{4})-(\d{2})-(\d{2})T[0-9:.T-]+?-(" + UUID_TEXT + r")\.jsonl\Z")

# Pane options that decide where the pane actually runs and how confined it is.
# The pool has to resolve these itself: the trust gate and `effective_posture`
# describe the directory the native will really use, not the one the dispatcher
# happened to be launched from.
PANE_VALUE_FLAGS = {
    "-c",
    "--config",
    "--enable",
    "--disable",
    "-i",
    "--image",
    "-m",
    "--model",
    "--local-provider",
    "-p",
    "--profile",
    "-s",
    "--sandbox",
    "-C",
    "--cd",
    "--add-dir",
    "-a",
    "--ask-for-approval",
    "--remote",
    "--remote-auth-token-env",
}
# Picker-driven entry points. They choose a conversation from whatever history the
# home happens to hold, which is the opposite of an explicitly selected resume.
PANE_PICKER_FLAGS = {"--last", "--all"}


def conversation_of(name):
    """The conversation uuid a rollout filename names, or None."""
    found = ROLLOUT_PATTERN.match(str(name))
    return found.group(4) if found else None


def rollout_date(name):
    """The `<yyyy>/<mm>/<dd>` a transcript belongs under in a home-shaped tree."""
    found = ROLLOUT_PATTERN.match(str(name))
    if not found:
        raise PoolError("unsupported transcript filename: " + str(name))
    return Path(found.group(1), found.group(2), found.group(3))


def interactive_plan(args):
    """What a pane's argv actually asks for: where it runs, and how confined.

    A targeted parse, not a native grammar: the pool only has to answer the
    questions its own gates ask. Everything it does not recognise passes through
    to the native unchanged, exactly as before -- but a flag that MOVES the
    workspace or CHANGES the posture is one the pool must read, because it is the
    one recording what the pane was allowed to do.
    """
    plan = {
        "resume": None,
        "cd": None,
        "add_dirs": [],
        "sandbox": None,
        "approval": None,
        "bypass": False,
        "approve_for_me": False,
    }
    i = 0
    while i < len(args):
        value = args[i]
        flag, equal, inline = value.partition("=")
        if flag in PANE_VALUE_FLAGS and not equal:
            if i + 1 >= len(args):
                raise PoolError("missing value for " + flag)
            inline = args[i + 1]
            i += 1
        elif flag not in PANE_VALUE_FLAGS:
            flag, inline = value, None
        if flag in ("-C", "--cd"):
            plan["cd"] = inline
        elif flag == "--add-dir":
            plan["add_dirs"].append(inline)
        elif flag in ("-s", "--sandbox"):
            plan["sandbox"] = inline
        elif flag in ("-a", "--ask-for-approval"):
            plan["approval"] = inline
        elif flag == "--dangerously-bypass-approvals-and-sandbox":
            plan["bypass"] = True
        elif flag == "--approve-for-me":
            plan["approve_for_me"] = True
        elif flag == "--worktree":
            # The native creates the directory during startup, so no gate here
            # could check the workspace the pane will actually write in.
            raise PoolError("a pool pane cannot run in a managed worktree; point it at the directory with --cd instead")
        elif flag in PANE_PICKER_FLAGS:
            raise PoolError(
                "a pool pane resumes one explicitly selected conversation; picker options are not available: " + flag
            )
        i += 1
    if args[:1] == ["fork"]:
        raise PoolError("fork is not available in a pool pane; resume the conversation explicitly instead")
    if args[:1] == ["resume"]:
        selected = args[1] if len(args) > 1 else ""
        if not UUID_PATTERN.match(selected):
            raise PoolError(
                "a pool pane resumes one explicit conversation uuid; the picker and session names are not available"
            )
        plan["resume"] = selected.lower()
    elif "resume" in args:
        # Refusing rather than reinterpreting: the pool must not have to guess
        # which token was a subcommand and which was prompt text.
        raise PoolError("put `resume <uuid>` first in a pool pane invocation")
    if plan["bypass"] and (plan["sandbox"] or plan["approval"]):
        raise PoolError("the bypass flag and an explicit sandbox or approval policy cannot both describe one pane")
    if plan["sandbox"] and plan["sandbox"] not in ("read-only", "workspace-write", "danger-full-access"):
        raise PoolError("unsupported sandbox for this profile")
    if plan["approval"] and plan["approval"] not in ("on-request", "never"):
        raise PoolError("unsupported approval policy: " + str(plan["approval"]))
    return plan


def validate_interactive_args(args):
    """An interactive pane launches the TUI, optionally resuming a conversation.

    Unlike exec there is no leading subcommand: the first positional is a prompt.
    Only an explicit `resume` is admitted, and nothing that could change which
    credential or server the pane talks to.
    """
    args = list(args)
    if args[:1] and args[0] in INTERACTIVE_FORBIDDEN:
        raise PoolError("not available inside a pool pane: " + args[0])
    if args[:1] and args[0] == "exec":
        raise PoolError("use the review or implementation profile for codex exec")
    interactive_plan(args)
    normalized = []
    i = 0
    while i < len(args):
        value = args[i]
        flag = value.partition("=")[0]
        if flag in ("--remote", "--remote-auth-token-env", "--oss", "--home", "--config-path"):
            raise PoolError("alternate transports are not permitted in a pool pane")
        if flag in ("-c", "--config"):
            if "=" not in value:
                i += 1
                if i >= len(args):
                    raise PoolError("missing value for " + flag)
                value = args[i]
            option = value.split("=", 1)[0] if "=" in value else ""
            key = option.strip()
            if key not in CONFIG_KEYS:
                raise PoolError("provider, auth and home configuration overrides are not permitted")
            normalized += ["-c", value]
            i += 1
            continue
        # Admitted for this profile alone, and normalised into the posture that
        # provider_options pins; a pane Orca launched must not start prompting.
        if value == "--dangerously-bypass-approvals-and-sandbox":
            normalized.append(value)
            i += 1
            continue
        normalized.append(value)
        i += 1
    return normalized


def refuse_profile(reason):
    raise PoolError("narrowing permission profile refused: " + reason)


def toml_value(text):
    """Parse a -c value the way the native does: TOML, else the raw string.

    None means it is not valid TOML. tomllib ships with Python 3.11+; without it
    nothing can be validated, so the profile is refused rather than passed on.
    """
    try:
        import tomllib
    except ImportError:
        refuse_profile("this Python cannot parse TOML")
    try:
        document = tomllib.loads("value = " + text)
    except tomllib.TOMLDecodeError:
        return False, None
    # Text that smuggles a second TOML statement after the value is not one value.
    if list(document) != ["value"]:
        refuse_profile("a -c value must be a single TOML value")
    return True, document["value"]


def profile_name_value(text):
    parsed, value = toml_value(text)
    if not parsed:
        value = text
    if not isinstance(value, str) or not PROFILE_NAME.match(value):
        refuse_profile(
            "default_permissions must name a custom profile ([A-Za-z0-9_-]); built-in profiles are not admitted"
        )
    return value


def profile_filesystem_value(text, name=None):
    """Only {":minimal"="read", "<absolute path>"="read"|"none", ...}, one read path at least.

    "none" denies reads below a path. It only narrows, and it is what takes back
    what `:minimal` lends: that baseline makes /private/tmp readable, where whole
    checkouts live. Codex 0.160.0 lets a more specific "read" path under a "none"
    one stay readable. It is admitted for absolute paths alone, never `:minimal`
    or `/`: a denied root is not proven harmless to the native's own helpers.

    A profile *name* in WRITABLE_PROFILES may also give "write" to ONE absolute
    path strictly inside a path the table reads, with no "none" entry between
    them: the grant adds a scratch folder to what is already visible, never a
    new root. `:minimal` never takes "write".
    """
    parsed, table = toml_value(text)
    if not parsed or not isinstance(table, dict):
        refuse_profile("the filesystem value must be one inline TOML table")
    paths, writes = [], []
    for entry, access in table.items():
        if access == "write":
            if entry == ":minimal":
                refuse_profile("the :minimal baseline cannot be granted write")
            if name not in WRITABLE_PROFILES:
                refuse_profile(
                    "only " + ", ".join(sorted(WRITABLE_PROFILES)) + " may grant write: " + json.dumps(entry)
                )
        elif access not in ("read", "none") or (access == "none" and entry == ":minimal"):
            refuse_profile('only "read", or "none" on an absolute path, may be given: ' + json.dumps(entry))
        if entry == ":minimal":
            continue
        if (
            not entry.startswith("/")
            or entry == "/"
            or os.path.normpath(entry) != entry
            or PROFILE_PATH_FORBIDDEN.search(entry)
        ):
            refuse_profile(
                "only :minimal and normalized absolute paths without globs may be named: " + json.dumps(entry)
            )
        if access == "read":
            paths.append(entry)
        elif access == "write":
            writes.append(entry)
    if not paths:
        refuse_profile("the filesystem table must grant read on at least one absolute path")
    if len(writes) > 1:
        refuse_profile("at most one path may be granted write")
    for target in writes:
        # The nearest named ancestor decides what the folder above it is: it must
        # be a read path, so a "none" between them cannot be written through.
        enclosing = [entry for entry in table if entry != ":minimal" and target.startswith(entry + "/")]
        if not enclosing or table[max(enclosing, key=len)] != "read":
            refuse_profile("the write path must lie inside a path the profile reads: " + json.dumps(target))
    return "{" + ",".join(json.dumps(k) + "=" + json.dumps(v) for k, v in table.items()) + "}"


def narrowing_profile(configs, flags, profile):
    """Validate the opt-in profile; return {arg index: canonical value} or {}.

    *configs* holds (key, value, index, prefix) for every -c whose key is not one of the
    ordinary CONFIG_KEYS. Without a profile it must be empty, exactly as before.
    """
    if not configs:
        return {}
    names, tables = [], []
    for key, value, index, _ in configs:
        match = PROFILE_TABLE_KEY.match(key)
        if key == "default_permissions":
            names.append((profile_name_value(value), index))
        elif match:
            tables.append((match.group(1), profile_filesystem_value(value, match.group(1)), index))
        elif key.startswith("permissions"):
            refuse_profile(
                "only permissions.<name>.filesystem is admitted; network, extends "
                "and every other permissions key are refused: " + key
            )
        else:
            raise PoolError("provider, auth and home configuration overrides are not permitted")
    if profile != "review":
        refuse_profile("only the review profile may narrow its permissions")
    if len(names) != 1 or len(tables) != 1 or names[0][0] != tables[0][0]:
        refuse_profile(
            "pass exactly one default_permissions=<name> and one "
            "permissions.<name>.filesystem table naming the same profile"
        )
    # `-s` silently overrides a permission profile, and --add-dir adds roots the
    # profile never granted; either would undo the narrowing without a word.
    for flag in flags & {"-s", "--sandbox", "--add-dir"}:
        refuse_profile(flag + " cannot be combined with a permission profile")
    return {names[0][1]: json.dumps(names[0][0]), tables[0][2]: tables[0][1]}


# The oldest native measured to enforce every entry the profile admits. 0.154.0
# applied the profile but let a "none" path be read, which is a silent widening of
# what the caller asked for, so an older native refuses the profile outright.
PROFILE_MIN_NATIVE = (0, 160, 0)


def require_profile_native(binding):
    executable = binding["executable"]
    reported = native_version(executable, binding["files"][executable])
    match = re.fullmatch(r"codex-cli (\d+)\.(\d+)\.(\d+)(?:-\S+)?", reported)
    if not match or tuple(int(p) for p in match.groups()) < PROFILE_MIN_NATIVE:
        refuse_profile(
            reported
            + " does not enforce every profile entry; needs codex-cli "
            + ".".join(map(str, PROFILE_MIN_NATIVE))
            + " or newer"
        )


def validate_native_args(args, profile):
    """Parse execution positions; prompt text can contain any flag-like words."""
    return parse_native_args(args, profile)[0]


def parse_native_args(args, profile):
    """Validated args, and whether they carry the narrowing permission profile."""
    args = list(args)
    if profile == "interactive":
        return validate_interactive_args(args), False
    if not args or args[0] != "exec":
        raise PoolError("this dispatcher entry point requires codex exec")
    configs, flags = [], set()
    i, positional, resume = 1, 0, False
    if len(args) > 1 and args[1] == "resume":
        resume, i = True, 2
    while i < len(args):
        value = args[i]
        if value == "--":
            positional += len(args) - i - 1
            break
        if not value.startswith("-") or value == "-":
            positional += 1
            i += 1
            continue
        flag, equal, inline = value.partition("=")
        if flag in SWITCH_FLAGS:
            if equal:
                raise PoolError("unexpected flag value: " + flag)
            if flag == "--dangerously-bypass-hook-trust" and profile != "implementation":
                raise PoolError("hook trust bypass requires the implementation profile")
            if flag == "--ignore-user-config" and profile == "implementation":
                raise PoolError("implementation hooks must not be suppressed")
            i += 1
            continue
        if flag not in VALUE_FLAGS | {"-c", "--config"}:
            raise PoolError("unsupported execution option: " + flag)
        if equal:
            argument = inline
        else:
            i += 1
            if i >= len(args):
                raise PoolError("missing value for " + flag)
            argument = args[i]
        flags.add(flag)
        if flag in {"-c", "--config"}:
            key, sep, setting = argument.partition("=")
            if not sep:
                raise PoolError("provider, auth and home configuration overrides are not permitted")
            if key.strip() not in CONFIG_KEYS:
                configs.append((key.strip(), setting, i, flag + "=" if equal else ""))
        if flag in {"-s", "--sandbox"}:
            allowed = {"read-only"} if profile == "review" else {"read-only", "workspace-write"}
            if argument not in allowed:
                raise PoolError("unsupported sandbox for this profile")
        i += 1
    if positional > (2 if resume else 1):
        raise PoolError("too many native positional arguments")
    canonical = narrowing_profile(configs, flags, profile)
    for key, _, index, prefix in configs:
        args[index] = prefix + key + "=" + canonical[index]
    return args, bool(canonical)


class Admin:
    def __init__(self, endpoint, password):
        url = urllib.parse.urlsplit(endpoint)
        if url.scheme != "http" or url.hostname != "127.0.0.1" or not url.port or url.path:
            raise PoolError("pool endpoint must be an explicit loopback HTTP port")
        self.endpoint = endpoint
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )
        self.request("POST", "/api/dashboard-auth/password/login", {"password": password})

    def request(self, method, path, value=None):
        request = urllib.request.Request(
            self.endpoint + path,
            method=method,
            data=None if value is None else json.dumps(value).encode(),
            headers={"Content-Type": "application/json"},
        )
        try:
            with self.opener.open(request, timeout=20) as response:
                raw = response.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as error:
            # API errors may echo import fields or keys; never print their body.
            raise PoolError("pool administration refused request (HTTP %d)" % error.code) from None
        except urllib.error.URLError:
            raise PoolError("pool proxy is unavailable") from None


class Pool:
    def __init__(self, root=None, admin=None):
        self.root = private_path(root or Path.home() / ".config/codex-pool", directory=True)
        self.config = read_json(self.root / "dispatcher.json")
        self._admin = admin

    def set_admission(self, state):
        """Open/close dispatcher admission with a durable, validated seal.

        Closing is always allowed. Opening requires the proxy policy to report
        at least one account and the protected identity fence to be enabled;
        this prevents an empty or desktop-only pool being advertised as live.
        """
        if state not in ("open", "closed"):
            raise PoolError("admission must be open or closed")
        if state == "open":
            policy = self.admin.request("GET", "/api/pool/metadata")
            accounts = self.admin.request("GET", "/api/accounts")
            if isinstance(accounts, dict):
                accounts = accounts.get("accounts")
            if not isinstance(policy, dict) or policy.get("contract_version") != 1:
                raise PoolError("pool policy metadata is unavailable")
            if not isinstance(accounts, list) or not accounts:
                raise PoolError("cannot open admission without enrolled accounts")
        # `self.config` was read when this object was constructed, and a
        # dispatcher roll or a native approval may have committed since. Writing
        # that snapshot back would silently revert the pointer or an approved
        # entry point, so re-read under the lock and change only the one field
        # this call owns. The proxy checks above stay outside the lock: they are
        # network calls, and nothing else may be waiting on them.
        with pool_lock(self.root):
            config = read_json(self.root / "dispatcher.json")
            config["admission"] = state
            write_json(self.root / "dispatcher.json", config)
        self.config = config
        return {"admission": state}

    @property
    def admin(self):
        if self._admin is None:
            self._admin = Admin(self.config["endpoint"], self.config["admin_password"])
        return self._admin

    def session_path(self, session):
        if not re.fullmatch(r"[0-9a-f]{32}", session):
            raise PoolError("invalid pool session id")
        return private_path(self.root / "sessions" / session, directory=True)

    def interactive_mapping(self):
        """Orca pane handle -> pool session, read from disk on every call.

        A dispatcher process lives for one pane invocation while the pane itself
        outlives many of them, so this binding cannot be held in memory. Entries
        written by earlier generations carry no handle and are skipped rather
        than guessed at.
        """
        root = self.root / "interactive"
        if not root.is_dir():
            return {}
        mapping = {}
        for path in sorted(private_path(root, directory=True).glob("handle-*.json")):
            try:
                record = read_json(path)
            except (PoolError, ValueError):
                continue
            handle, session = record.get("handle"), record.get("session")
            if isinstance(handle, str) and isinstance(session, str):
                mapping[handle] = session
        return mapping

    def bind_interactive(self, handle, session):
        """Bind one Orca pane handle to one pool session, durably and only once.

        The handle identifies a terminal across dispatcher restarts, so a second
        session claiming a handle that already belongs to another one means two
        panes believe they own the same terminal. Refuse instead of repointing:
        moving it silently would strand whichever pane looked away first.
        """
        if not isinstance(handle, str) or not re.fullmatch(r"[A-Za-z0-9._:@+-]{1,160}", handle):
            raise PoolError("invalid interactive pane handle")
        home = self.session_path(session) / "home"
        root = self.root / "interactive"
        root.mkdir(mode=0o700, exist_ok=True)
        root = private_path(root, directory=True)
        lock = os.open(root / ".bind.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX)
            bound = self.interactive_mapping().get(handle)
            if bound is not None and bound != session:
                raise PoolError("interactive handle is already bound to " + bound)
            name = "handle-" + hashlib.sha256(handle.encode()).hexdigest()[:32] + ".json"
            write_json(root / name, {"handle": handle, "session": session, "home": str(home), "bound_at": time.time()})
        finally:
            os.close(lock)
        return {"handle": handle, "session": session}

    def native_binding(self, native):
        entry = str(Path(native).resolve())
        approved = self.config["native_binaries"].get(entry)
        if not approved:
            # New task worktrees have distinct package-manager paths. Admit their
            # actual payload only when its bytes match an explicitly installed
            # native binding; never execute their wrapper to discover it.
            candidate = pin_native(Path(entry))
            payload_sha = candidate["files"][candidate["executable"]]
            accepted = {
                binding["files"][binding["executable"]]
                for binding in self.config["native_binaries"].values()
                if isinstance(binding, dict)
            }
            if payload_sha not in accepted:
                raise PoolError("native binary is not a verified pool entry point")
            approved = candidate
        # Explicit bindings execute the pinned payload directly. Package-manager
        # shell/JS launchers are measured aliases, never an executable trust root.
        binding = approved if isinstance(approved, dict) else {"executable": entry, "files": {entry: approved}}
        executable = binding.get("executable")
        files = binding.get("files", {})
        if not isinstance(executable, str) or not isinstance(files, dict):
            raise PoolError("incomplete native executable binding")
        if not executable or entry not in files or executable not in files:
            raise PoolError("incomplete native executable binding")
        for filename, expected in files.items():
            if file_sha256(filename) != expected:
                raise PoolError("native binary changed; refresh its acceptance evidence first")
        return binding

    def metadata(self, profile, native):
        native = str(Path(native).resolve())
        binding = self.native_binding(native)
        approved = binding["files"][binding["executable"]]
        if profile not in ("review", "implementation", "interactive"):
            raise PoolError("unverified native/profile identity")
        proxy = self.admin.request("GET", "/api/pool/metadata")
        if (
            not isinstance(proxy, dict)
            or proxy.get("contract_version") != 1
            or not re.fullmatch(r"[0-9a-f]{64}", proxy.get("identity", ""))
        ):
            raise PoolError("proxy serving metadata is unavailable or incompatible")
        source = Path(__file__).resolve().parent
        files = {
            name: hashlib.sha256((source / name).read_bytes()).hexdigest() for name in ("pool.py", "pool_processes.py")
        }
        value = {
            "contract_version": 1,
            "dispatcher_files": files,
            "native": native,
            "native_sha256": approved,
            "profile": profile,
            "endpoint": self.config["endpoint"],
            "proxy_identity": proxy["identity"],
            "native_binding": binding,
        }
        launcher = source.parent / "codex-pool"
        value.update(
            dispatcherContractVersion="1",
            dispatcherPath=str(launcher),
            dispatcherSha256=hashlib.sha256(launcher.read_bytes()).hexdigest(),
            nativePath=native,
            nativeSha256=approved,
            nativeVersion=native_version(binding["executable"], approved),
            proxyEndpoint=self.config["endpoint"],
            proxyDeployment=proxy.get("build", proxy["identity"]),
            proxyPolicyGeneration=proxy["identity"],
            # The ceiling this profile admits, not what one pane got: identity is
            # re-derived from the profile alone in allocate/run/exec, so it must not
            # vary with argv. `interactive` admits the bypass flag, so it ceilings at
            # full access; the posture actually used is recorded in effective_posture.
            sandboxPolicy={"review": "read-only", "implementation": "workspace-write"}.get(
                profile, "danger-full-access"
            ),
        )
        value["identity"] = hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()
        value["identitySha"] = value["identity"]
        return value

    def allocate(self, profile, native, request_id=None, expected_identity=None):
        serving = None
        if expected_identity is not None or self.config.get("require_serving_identity"):
            serving = self.metadata(profile, native)
            if expected_identity != serving["identity"]:
                raise PoolError("pool serving identity changed before allocation")
        if request_id is None:
            return self._allocate(profile, native, serving=serving)
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,160}", request_id):
            raise PoolError("invalid allocation request id")
        session = hashlib.sha256(request_id.encode()).hexdigest()[:32]
        directory = self.session_path(session)
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(directory / "allocation.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            if (directory / "session.json").exists():
                record = read_json(directory / "session.json")
                if (
                    record.get("request_id") != request_id
                    or record["profile"] != profile
                    or record["native"] != str(Path(native).resolve())
                ):
                    raise PoolError("allocation request is already bound to another launch")
                if serving != record.get("serving"):
                    raise PoolError("allocation request is bound to a different serving identity")
                if record["state"] == "allocating":
                    raise PoolError("allocation outcome is uncertain; inspect session " + session)
                if record["state"] == "closed":
                    # A request id identifies ONE user operation. Handing back a
                    # revoked session would fail later with a confusing "not
                    # settled"; handing back a new one would be the duplicate pane
                    # this deduplication exists to prevent.
                    raise PoolError(
                        "this open operation already completed as session "
                        + session
                        + "; use a new request id to open again"
                    )
                return self.allocation_result(directory, record)
            return self._allocate(profile, native, session, request_id, serving)
        finally:
            os.close(fd)

    def _allocate(self, profile, native, session=None, request_id=None, serving=None):
        if self.config.get("admission") != "open":
            raise PoolError("pool admission is closed")
        if profile not in ("review", "implementation", "interactive"):
            raise PoolError("invalid pool profile")
        native = str(Path(native).resolve())
        binding = self.native_binding(native)
        approved = binding["files"][binding["executable"]]
        session = session or uuid.uuid4().hex
        directory = self.session_path(session)
        directory.mkdir(mode=0o700, parents=True, exist_ok=request_id is not None)
        (directory / "home").mkdir(mode=0o700)
        record = {
            "id": session,
            "profile": profile,
            "native": native,
            "native_sha256": approved,
            "native_binding": binding,
            "state": "allocating",
            "created_at": time.time(),
            "request_id": request_id,
            "serving": serving,
        }
        if profile == "interactive":
            mapping = self.root / "interactive"
            mapping.mkdir(mode=0o700, exist_ok=True)
            write_json(
                mapping / (session + ".json"),
                {
                    "session": session,
                    "home": str(directory / "home"),
                    "workspace": str(Path.cwd().resolve()),
                    "created_at": time.time(),
                },
            )
        write_json(directory / "session.json", record)
        # No per-account assignment: this key serves the entire policy-protected
        # pool, so newly enrolled capacity becomes available without rekeying.
        key = self.admin.request("POST", "/api/api-keys/", {"name": "pool-" + session})
        record.update(key_id=key["id"], key=key["key"], state="idle")
        write_json(directory / "session.json", record)
        return self.allocation_result(directory, record)

    @staticmethod
    def allocation_result(directory, record):
        result = {"session": record["id"], "home": str(directory / "home"), "profile": record["profile"]}
        if record.get("serving"):
            result["identity"] = record["serving"]["identity"]
        return result

    @staticmethod
    def settled_state(receipt, code, descendants=False):
        """`idle` or `failed` only on proof; `uncertain` otherwise.

        `failed` is settled -- every process is gone, so the key can be revoked
        and the caches freed -- but never runnable: a failed generation is not
        replayed. Proof is the supervisor's receipt for this launch, reporting a
        complete observation and a settled process tree, agreeing with the code
        the dispatcher saw, and no process group left behind.
        """
        proven = (
            receipt is not None
            and receipt.get("settled") is True
            and receipt.get("observation_complete") is True
            and receipt["native_exit"] == code
            and not descendants
        )
        if code == 0 and not descendants:
            return "idle"
        return "failed" if proven else "uncertain"

    @contextlib.contextmanager
    def locked_session(self, session):
        directory = self.session_path(session)
        fd = os.open(directory / "dispatch.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise PoolError("this logical session already has an active native process") from None
            yield directory, read_json(directory / "session.json")
        finally:
            os.close(fd)

    def run(self, session, args, expected_identity=None):
        if self.config.get("admission") != "open":
            raise PoolError("pool admission is closed")
        with self.locked_session(session) as (directory, record):
            if record["state"] != "idle":
                raise PoolError("session is not settled; inspect and reconcile it before resuming")
            serving = record.get("serving")
            if serving or self.config.get("require_serving_identity") or expected_identity:
                observed = self.metadata(record["profile"], record["native"])
                if not serving or expected_identity != serving["identity"] or observed != serving:
                    raise PoolError("pool serving identity changed before execution")
            args, narrowed = parse_native_args(args, record["profile"])
            if record["profile"] == "review" and "--ignore-user-config" not in args:
                args.insert(1, "--ignore-user-config")
            home = private_path(directory / "home", directory=True)
            if (home / "auth.json").exists() or (home / "auth.json").is_symlink():
                raise PoolError("upstream credentials are forbidden in a pool job home")
            binding = self.native_binding(record["native"])
            if binding != record.get("native_binding"):
                raise PoolError("native executable binding changed; revalidate the session")
            if narrowed:
                require_profile_native(binding)
            env = clean_environment(os.environ)
            env.update(CODEX_HOME=str(home), CODEX_POOL_API_KEY=record["key"], CODEX_POOL_SESSION=session)
            options = self.provider_options(serving, record["profile"], narrowed=narrowed)
            # These native releases do not propagate root-level -c overrides
            # into exec. Put routing at the same subcommand position proved by
            # the native canary, before any caller's positional prompt.
            offset = 2 if args[:2] == ["exec", "resume"] else 1
            command = [binding["executable"], *args[:offset], *options, *args[offset:]]
            record.update(state="starting", generation=uuid.uuid4().hex)
            write_json(directory / "session.json", record)
            child = None
            handlers = {}
            control_read, control_write = os.pipe()
            report_read, report_write = os.pipe()
            try:
                child = subprocess.Popen(
                    [
                        sys.executable,
                        str(Path(__file__).resolve()),
                        "_supervise",
                        str(control_read),
                        str(self.root),
                        session,
                        str(report_write),
                    ],
                    env=env,
                    start_new_session=True,
                    pass_fds=(control_read, report_write),
                )
                os.close(control_read)
                control_read = None
                os.close(report_write)
                report_write = None
                from pool_processes import identity as process_identity

                record.update(state="running", pid=child.pid, started_at=time.time())
                observed = process_identity(child.pid)
                if observed:
                    record["process_identity"] = list(observed)
                write_json(directory / "session.json", record)
                os.write(control_write, (json.dumps(command) + "\n").encode())

                def forward(signum, _frame):
                    if child.poll() is None:
                        # The supervisor relays SIGINT to the native itself, so the
                        # group -- native included -- would get it twice. The stop
                        # signals it only arms a deadline for, so they go to all.
                        if signum == signal.SIGINT:
                            os.kill(child.pid, signum)
                        else:
                            os.killpg(child.pid, signum)

                for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
                    handlers[signum] = signal.signal(signum, forward)
                code = child.wait()
                # A successful native exit is not enough if descendants are
                # still alive. Keep the key and mark uncertainty in that case.
                try:
                    os.killpg(child.pid, 0)
                    descendants = True
                except ProcessLookupError:
                    descendants = False
                if descendants:
                    os.killpg(child.pid, signal.SIGKILL)
                code = code if code >= 0 else 128 - code
                receipt, report_read = read_receipt(report_read), None
                record.update(
                    state=self.settled_state(receipt, code, descendants), exit_code=code, ended_at=time.time()
                )
                return code
            finally:
                os.close(control_write)
                for fd in (control_read, report_read, report_write):
                    if fd is not None:
                        os.close(fd)
                for signum, handler in handlers.items():
                    signal.signal(signum, handler)
                if record["state"] in ("running", "starting"):
                    record["state"] = "uncertain"
                write_json(directory / "session.json", record)

    def provider_options(self, serving, profile, bypass=False, narrowed=False):
        """The -c overrides that point a native child at this pool.

        Ordinary Codex provider configuration, not an exec-specific mechanism --
        which is why the same options serve an interactive pane. The pool owns
        provider, auth and home; a caller can override none of them.
        """
        overrides = {
            "model_provider": "non_desktop_pool",
            "model_providers.non_desktop_pool.name": "openai",
            "model_providers.non_desktop_pool.base_url": self.config["endpoint"] + "/backend-api/codex",
            "model_providers.non_desktop_pool.env_key": "CODEX_POOL_API_KEY",
            "model_providers.non_desktop_pool.wire_api": "responses",
            "model_providers.non_desktop_pool.requires_openai_auth": False,
            "model_providers.non_desktop_pool.supports_websockets": False,
            "model_providers.non_desktop_pool.stream_max_retries": 0,
        }
        if serving:
            headers = {"x-codex-pool-identity": serving["proxy_identity"]}
            terminal_handle = os.environ.get("ORCA_TERMINAL_HANDLE", "").strip()
            if terminal_handle:
                headers["x-orca-terminal-handle"] = terminal_handle
            overrides["model_providers.non_desktop_pool.http_headers"] = headers
        options = []
        for key, value in overrides.items():
            encoded = (
                ("{" + ", ".join(json.dumps(k) + "=" + json.dumps(v) for k, v in value.items()) + "}")
                if isinstance(value, dict)
                else json.dumps(value)
            )
            options += ["-c", key + "=" + encoded]
        # Pin a safe default even when the caller omitted its sandbox flag. A
        # validated narrowing profile replaces it: Codex documents sandbox_mode
        # and default_permissions as not to be combined.
        if not narrowed:
            options += [
                "-c",
                "sandbox_mode="
                + json.dumps(
                    {
                        "review": "read-only",
                        "implementation": "workspace-write",
                        "interactive": "danger-full-access" if bypass else "workspace-write",
                    }.get(profile, "workspace-write")
                ),
            ]
        if profile == "interactive":
            options += ["-c", "approval_policy=" + json.dumps("never" if bypass else "on-request")]
        # With plugins on and no Codex-backend login -- always the case for a pool
        # key -- the native clones the ~88 MB curated catalog into every private
        # home (core-plugins startup_sync.rs). Pool homes install no plugin.
        options += ["-c", "features.plugins=false"]
        return options

    def require_workspace_trust(self, workdir):
        """Refuse a directory the pane has no standing approval for.

        An approval covers its whole subtree, deliberately: approving a projects
        directory once is what stops every new worktree under it from blocking a
        pane on a trust prompt. `is_relative_to` compares whole path components,
        so a neighbour that merely shares a textual prefix is not covered --
        `/Users/jan` never approves `/Users/janplessow`. A non-string key cannot
        describe a directory and never matches.

        Every directory the pane may WRITE goes through here, not just its
        working root: `--add-dir` hands the sandbox another writable tree, and an
        unapproved one is exactly what this gate exists to stop.
        """
        approvals = (
            read_json(self.root / "workspace-trust.json") if (self.root / "workspace-trust.json").exists() else {}
        )
        approved_root = next(
            (
                root
                for root in approvals
                if isinstance(root, str) and (workdir == root or Path(workdir).is_relative_to(root))
            ),
            None,
        )
        if approved_root is None:
            approval_command = shlex.join(
                [
                    str(Path(__file__).resolve().parent.parent / "codex-pool"),
                    "--root",
                    str(self.root),
                    "trust-workspace",
                    workdir,
                ]
            )
            raise PoolError("workspace trust approval required: " + workdir + "; approve it with: " + approval_command)
        return approved_root

    def inherit_orca_hooks(self, home):
        """Carry existing hook decisions across CODEX_HOME isolation, not credentials.

        Keep the exact definitions/order and hashes. A changed command therefore
        remains untrusted in the native; this never grants a new trust decision.
        """
        source = os.environ.get("ORCA_CODEX_HOME")
        if not source or not os.environ.get("ORCA_PANE_KEY"):
            return ""
        source = Path(source).expanduser().resolve()
        hooks = source / "hooks.json"
        if not hooks.exists():
            return ""
        for path in (hooks, source / "config.toml"):
            if path.is_symlink() or not path.is_file() or path.stat().st_uid != os.getuid():
                raise PoolError("Orca hook source must be an owned regular file")
        data = hooks.read_bytes()
        json.loads(data)  # Fail before copying a damaged definition.
        decisions = orca_hook_decisions((source / "config.toml").read_text())
        prefix = str(hooks) + ":"
        lines = []
        for key, decision in decisions.items():
            if not key.startswith(prefix) or not isinstance(decision, dict):
                continue
            target_key = str(home / "hooks.json") + ":" + key[len(prefix) :]
            lines.append("[hooks.state." + json.dumps(target_key) + "]")
            if isinstance(decision.get("enabled"), bool):
                lines.append("enabled = " + str(decision["enabled"]).lower())
            digest = decision.get("trusted_hash")
            if isinstance(digest, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
                lines.append("trusted_hash = " + json.dumps(digest))
        self.write_private_copy(data, home / "hooks.json")
        return "\n" + "\n".join(lines) + "\n"

    @staticmethod
    def read_personal_file(path):
        """The bytes of an owned regular file, or None with a one-line warning.

        Checked on the opened descriptor, never on a resolved path: O_NOFOLLOW
        refuses a symlink at open, and fstat describes the very inode that is
        read, so nothing can be swapped in between the check and the read.
        O_NONBLOCK keeps a FIFO planted at the path from hanging the launch
        before fstat can refuse it. A missing or refused file never fails the
        pane; it launches as before.
        """
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            print("codex-pool: personal file absent, skipped: " + str(path), file=sys.stderr)
            return None
        except OSError as error:
            print("codex-pool: personal file refused (" + str(error.strerror) + "): " + str(path), file=sys.stderr)
            return None
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                print("codex-pool: personal file refused (not an owned regular file): " + str(path), file=sys.stderr)
                return None
            # Bounded by what is read, not only by fstat: the file can grow after it.
            data = stream.read(PERSONAL_FILE_MAX_BYTES + 1)
            if len(data) > PERSONAL_FILE_MAX_BYTES:
                print(
                    "codex-pool: personal file refused (larger than "
                    + str(PERSONAL_FILE_MAX_BYTES)
                    + " bytes): "
                    + str(path),
                    file=sys.stderr,
                )
                return None
            return data

    def install_personal_instructions(self, home):
        """Give an interactive pane Jan's working agreement and behaviour settings.

        A pane home is created empty, so without this every pane runs on stock
        instructions and settings. Two files from the personal directory:
        AGENTS.md is copied as the pane's global instructions, and codex.toml
        contributes only PERSONAL_SETTINGS -- never model, provider, auth,
        sandbox or approval, which the pool pins. Returns top-level TOML lines,
        which must precede every table in the pane config to stay top-level.
        """
        root = Path(os.environ.get("CODEX_POOL_PERSONAL_DIR") or "~/.config/agent-instructions").expanduser()
        instructions = self.read_personal_file(root / "AGENTS.md")
        if instructions is not None:
            self.write_private_copy(instructions, home / "AGENTS.md")
        settings = self.read_personal_file(root / "codex.toml")
        if settings is None:
            return ""
        try:
            settings = settings.decode("utf-8")
        except UnicodeDecodeError:
            print("codex-pool: personal file refused (not valid UTF-8): " + str(root / "codex.toml"), file=sys.stderr)
            return ""
        lines = []
        for line in settings.splitlines():
            if line.strip().startswith("["):
                break  # Only top-level keys; a table ends the admitted region.
            found = re.fullmatch(r'\s*([a-z_]+)\s*=\s*"([^"]*)"\s*(?:#.*)?', line)
            if not found or found.group(1) not in PERSONAL_SETTINGS:
                continue
            key, value = found.groups()
            if not re.fullmatch(PERSONAL_SETTINGS[key], value):
                print("codex-pool: personal setting refused: " + key, file=sys.stderr)
                continue
            lines.append(key + " = " + json.dumps(value))
        return "".join(line + "\n" for line in lines)

    def expose_live_history(self, session):
        """Read-only discovery links, separate from immutable resume authority.

        A unique path per incarnation lets Orca distinguish a resumed append
        from an old bridged inode. Never import these links for selected resume,
        replace collisions, or write through them. Only the native writes source.
        """
        directory = self.session_path(session)
        record = read_json(directory / "session.json")
        if record.get("profile") != "interactive":
            return 0
        source = directory / "home" / "sessions"
        target_root = self.history_root() / "sessions" / "live" / session
        linked = 0
        for path in source.rglob("rollout-*.jsonl"):
            conversation = conversation_of(path.name)
            if not conversation:
                continue
            for ancestor in (path, *path.parents):
                if ancestor.is_symlink():
                    raise PoolError("live transcript path contains a symlink")
            info = path.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise PoolError("live transcript is not an owned regular file")
            with path.open("rb") as stream:
                first = stream.readline(65537)
            try:
                meta = json.loads(first)
            except ValueError:
                continue  # Native may still be creating its first line.
            if (
                len(first) > 65536
                or not isinstance(meta, dict)
                or meta.get("type") != "session_meta"
                or not isinstance(meta.get("payload"), dict)
                or not isinstance(meta["payload"].get("id"), str)
                or meta["payload"]["id"].lower() != conversation
            ):
                continue
            private_path(target_root, directory=True)
            target_root.mkdir(parents=True, mode=0o700, exist_ok=True)
            target = target_root / path.name
            if target.is_symlink():
                raise PoolError("live transcript projection is a symlink")
            if target.exists():
                if not os.path.samefile(path, target):
                    raise PoolError("live transcript projection collision")
                continue
            try:
                os.link(path, target, follow_symlinks=False)
                linked += 1
            except FileExistsError:
                if target.is_symlink() or not os.path.samefile(path, target):
                    raise PoolError("live transcript projection collision")
        return linked

    @contextlib.contextmanager
    def live_history(self, session):
        stopped = threading.Event()

        def publish():
            reported = False
            while True:
                try:
                    self.expose_live_history(session)
                except (OSError, ValueError, PoolError) as error:
                    if not reported:
                        print("codex-pool: live history unavailable: " + str(error), file=sys.stderr)
                        reported = True
                if stopped.wait(1):
                    return

        worker = threading.Thread(target=publish, name="pool-live-history", daemon=True)
        worker.start()
        try:
            yield
        finally:
            stopped.set()
            worker.join(timeout=5)
            try:
                self.expose_live_history(session)
            except (OSError, ValueError, PoolError) as error:
                print("codex-pool: final live history unavailable: " + str(error), file=sys.stderr)

    def prepare_selected_resume(self, conversation):
        """Recover only this selected conversation, never kill a surviving owner.

        Read-only resume-info stays read-only. The explicit interactive resume
        operation may settle a dead prior launcher before allocating its successor.
        """
        for item in self.conversation_sources(conversation):
            if item["state"] not in ("idle", "failed", "closed", "closing"):
                self.reconcile(item["session"], terminate_descendants=False)
            if item["state"] != "closed":
                self.close(item["session"])
        self.history_backfill(conversation)
        info = self.resume_info(conversation)
        if info["status"] != "eligible":
            raise PoolError(
                "cannot resume " + conversation + ": " + info["status"] + "; " + str(info.get("detail", ""))
            )

    def exec_interactive(self, session, args, expected_identity=None):
        """Run the interactive TUI under the pool watchdog while inheriting tty fds."""
        if self.config.get("admission") != "open":
            raise PoolError("pool admission is closed")
        with self.locked_session(session) as (directory, record):
            if record["state"] != "idle":
                raise PoolError("session is not settled; inspect and reconcile it before resuming")
            serving = record.get("serving")
            if serving or self.config.get("require_serving_identity") or expected_identity:
                observed = self.metadata(record["profile"], record["native"])
                if not serving or expected_identity != serving["identity"] or observed != serving:
                    raise PoolError("pool serving identity changed before execution")
            args = validate_native_args(args, record["profile"])
            home = private_path(directory / "home", directory=True)
            if (home / "auth.json").exists() or (home / "auth.json").is_symlink():
                raise PoolError("upstream credentials are forbidden in a pool job home")
            binding = self.native_binding(record["native"])
            plan = interactive_plan(args)
            # The directory the native will really use, not the one this process
            # was launched from: `--cd` moves the working root, and every
            # `--add-dir` widens what the sandbox will let the pane write.
            workdir = str((Path.cwd() / plan["cd"]).resolve() if plan["cd"] else Path.cwd().resolve())
            writable = [str((Path.cwd() / extra).resolve()) for extra in plan["add_dirs"]]
            for directory_needing_trust in [workdir, *writable]:
                self.require_workspace_trust(directory_needing_trust)
            (home / "config.toml").write_text(
                "# Written by the pool dispatcher for this pane.\n"
                + self.install_personal_instructions(home)
                + "".join(
                    "[projects." + json.dumps(trusted) + ']\ntrust_level = "trusted"\n'
                    for trusted in dict.fromkeys([workdir, *writable])
                )
                + self.inherit_orca_hooks(home)
            )
            resumed = None
            if plan["resume"] is not None:
                # While the destination is still idle and nothing has spawned: a
                # refusal here must leave no running pane behind, only a fresh
                # key for the caller's `close` to revoke.
                resumed = self.import_selected_resume(
                    plan["resume"], session, directory, home, workdir, record.get("request_id")
                )
                # Committed before anything else can fail: the lease is released
                # by `close` reading this field back off disk, so an import that
                # is not durably recorded is a lease nothing will ever release.
                record["resume"] = resumed
                write_json(directory / "session.json", record)
            env = clean_environment(os.environ)
            env.update(CODEX_HOME=str(home), CODEX_POOL_API_KEY=record["key"], CODEX_POOL_SESSION=session)
            bypass = plan["bypass"]
            # Native resume has its own -c collection. Put pool configuration in
            # that scope, otherwise a resume-local -c discards global provider
            # overrides and the private home falls back to the login screen.
            offset = 2 if args[:1] == ["resume"] else 0
            command = (
                [binding["executable"]]
                + args[:offset]
                + self.provider_options(serving, record["profile"], bypass)
                + args[offset:]
            )
            # What the pane actually got. An explicit `-s`/`-a` is a command-line
            # override applied on top of the `-c` defaults `provider_options`
            # pins, so it -- not the default -- is what this record must claim.
            record["effective_posture"] = {
                "sandbox_mode": plan["sandbox"] or ("danger-full-access" if bypass else "workspace-write"),
                "approval_policy": plan["approval"] or ("never" if bypass else "on-request"),
                "workspace": workdir,
                "launch_directory": str(Path.cwd().resolve()),
                "additional_writable_roots": writable,
                "approve_for_me": plan["approve_for_me"],
                "bypass_requested": bypass,
            }
            record.update(state="running", started_at=time.time())
            write_json(directory / "session.json", record)
        if resumed is not None:
            print(
                "codex-pool: resumed conversation "
                + resumed["conversation"]
                + " at revision "
                + str(resumed["revision"])
                + (" (unarchived by copying into sessions/)" if resumed["unarchived"] else ""),
                file=sys.stderr,
            )
        control_read, control_write = os.pipe()
        report_read, report_write = os.pipe()
        child = subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "_supervise",
                str(control_read),
                str(self.root),
                session,
                str(report_write),
            ],
            env=env,
            pass_fds=(control_read, report_write),
            start_new_session=True,
        )
        os.close(control_read)
        os.close(report_write)
        from pool_processes import identity as process_identity

        try:
            with self.locked_session(session) as (directory, record):
                record.update(pid=child.pid, process_identity=list(process_identity(child.pid) or ()))
                write_json(directory / "session.json", record)
            os.write(control_write, (json.dumps(command) + "\n").encode())
            with self.live_history(session):
                code = child.wait()
        finally:
            # The supervisor reads EOF here as the dispatcher having died and
            # kills the pane's entire process group. This end must stay open for
            # the pane's whole life, not just long enough to deliver the command.
            os.close(control_write)
        with self.locked_session(session) as (directory, record):
            state = self.settled_state(read_receipt(report_read), code if code >= 0 else 128 - code)
            record.update(state=state, exit_code=code, ended_at=time.time())
            write_json(directory / "session.json", record)
        return code

    def history_root(self):
        """One home-shaped tree holding every finished pane's transcript.

        A pane writes into its own private home, which is right for isolation and
        useless for reading back: an importer would have to know fifty separate
        roots. Finished transcripts are hard-linked into this one tree, which has
        a home's `sessions/` layout so an ordinary Codex history importer can be
        pointed at it. Hard links, not copies: the pane has exited, so the file is
        immutable, and the bytes are not duplicated.

        Credentials never appear here -- only transcripts.
        """
        return self.root / "history"

    def adopt_history(self, home):
        """Link an existing Codex home's transcripts into the history root.

        For retiring a home that still holds readable history -- the ring's, say.
        Only `sessions/` is read, so no credential, configuration or database can
        follow. Hard links where the filesystem allows it and copies otherwise,
        because the point is that the original directory becomes deletable.
        """
        source = Path(home).expanduser().resolve() / "sessions"
        if not source.is_dir():
            raise PoolError("no session history at " + str(source))
        adopted = skipped = 0
        for path in sorted(source.rglob("rollout-*.jsonl")):
            if path.is_symlink() or not path.is_file():
                continue
            target = self.history_root() / "sessions" / path.relative_to(source)
            if target.exists():
                skipped += 1
                continue
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            try:
                os.link(path, target)
            except OSError:
                shutil.copyfile(path, target)
            adopted += 1
        return {"home": str(Path(home).expanduser().resolve()), "adopted": adopted, "already_present": skipped}

    # ---- conversation storage -------------------------------------------------
    #
    # Three things, deliberately separate:
    #
    #   `history/revisions/<uuid>/<digest>.jsonl`  immutable private copies. A
    #       resumed pane APPENDS to a file of the same name, so "the transcript"
    #       is a sequence of longer and longer files, not one file. Naming each by
    #       its own digest is what makes a revision impossible to overwrite.
    #   `history/sessions/...` and `history/archived_sessions/...`  a home-shaped
    #       LATEST VIEW. Replaceable, repairable, and the thing an ordinary Codex
    #       history importer can still be pointed at.
    #   `history/index/<uuid>.json`  the arbiter. Once it exists, no scan of the
    #       trees above may contradict it: the trees hold adopted ambient history
    #       too, and that history has no pool provenance at all.
    #
    # Copies, never hard links. A resumed pane appends in place, so a link would
    # let it write straight through into the published revision it was seeded from.

    def revision_path(self, conversation, digest):
        return self.history_root() / "revisions" / conversation / (digest + ".jsonl")

    def index_path(self, conversation, create=False):
        return self._history_file(self.history_root() / "index", conversation + ".json", create)

    def lease_path(self, conversation, create=False):
        return self._history_file(self.history_root() / "leases", conversation + ".json", create)

    @staticmethod
    def _history_file(parent, name, create):
        if create:
            parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        return parent / name

    DIGEST_PATTERN = re.compile(r"\A[0-9a-f]{64}\Z")

    @staticmethod
    def validate_index(conversation, index):
        """Every persisted field this code later builds a path or a decision from.

        Two reasons, and the second is the quieter one. An index is the arbiter of
        which revision a conversation is at, so a damaged one must not be able to
        pass for a fresh one. And `digest`, `name` and `pool_session` are read back
        off disk and turned into filesystem paths, so they are checked against the
        shapes that produced them rather than trusted because the pool wrote them.
        """

        def bad(field, value):
            raise PoolError(
                "the conversation index for "
                + conversation
                + " has an invalid "
                + field
                + " ("
                + repr(value)[:80]
                + "); it is not treated as "
                "absent -- inspect it by hand"
            )

        if not isinstance(index, dict):
            bad("shape", type(index).__name__)
        if index.get("conversation") != conversation:
            bad("conversation", index.get("conversation"))
        revision = index.get("revision")
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
            bad("revision", revision)
        if not isinstance(index.get("digest"), str) or not Pool.DIGEST_PATTERN.match(index["digest"]):
            bad("digest", index.get("digest"))
        size = index.get("size")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            bad("size", size)
        if conversation_of(index.get("name") or "") != conversation:
            bad("name", index.get("name"))
        for field in ("archived", "complete"):
            if not isinstance(index.get(field), bool):
                bad(field, index.get(field))
        session = index.get("pool_session")
        if session is not None and not (isinstance(session, str) and re.fullmatch(r"[0-9a-f]{32}", session)):
            bad("pool_session", session)
        if not isinstance(index.get("conflicts"), list):
            bad("conflicts", index.get("conflicts"))
        revisions = index.get("revisions")
        if not isinstance(revisions, list) or not revisions:
            bad("revisions", revisions)
        for entry in revisions:
            if (
                not isinstance(entry, dict)
                or not isinstance(entry.get("digest"), str)
                or not Pool.DIGEST_PATTERN.match(entry["digest"])
            ):
                bad("revisions entry", entry)
        return index

    def read_index(self, conversation):
        """The index, or None only when there genuinely is not one.

        A damaged index is not an absent index. Returning None for one would let
        the next publication write a fresh revision 1 over the arbiter, taking
        every recorded revision, conflict and provenance line with it -- the one
        failure mode this whole structure exists to prevent.
        """
        path = self.index_path(conversation)
        if not path.exists():
            return None
        try:
            index = read_json(path)
        except (PoolError, ValueError) as error:
            raise PoolError(
                "the conversation index for "
                + conversation
                + " is unreadable ("
                + str(error)
                + "); it is not treated as absent -- inspect "
                + str(path)
                + " by hand"
            ) from None
        return self.validate_index(conversation, index)

    @staticmethod
    def verify_transcript(path, conversation):
        """Read a transcript and say whether it is a complete, self-consistent one.

        Never raises on content: a pane that died mid-write still owns its bytes
        and they still get published. What an incomplete transcript does NOT get
        is eligibility -- `complete` is what the resume gate reads.
        """
        path = Path(path).expanduser().absolute()
        for parent in [path, *path.parents]:
            if parent.is_symlink():
                raise PoolError("transcript paths must not contain symlinks: " + str(parent))
        if not path.is_file():
            raise PoolError("transcript is not a regular file: " + str(path))
        if path.stat().st_uid != os.getuid():
            raise PoolError("transcript is not owned by you: " + str(path))
        # Deliberately NOT `private_path`. The native writes transcripts 0644 under
        # an ordinary umask -- only a pane inherits the dispatcher's 0o077 -- and
        # refusing a readable source would strand exactly the history the pool is
        # trying to take custody of. The published COPY is forced private instead.
        data = path.read_bytes()
        complete, reason = False, "transcript is empty"
        try:
            lines = [line for line in data.splitlines() if line.strip()]
            records = [json.loads(line) for line in lines]
            meta = records[0] if records else {}
            if meta.get("type") != "session_meta":
                reason = "transcript does not begin with session_meta"
            elif str(meta.get("payload", {}).get("id", "")).lower() != conversation.lower():
                reason = "transcript session_meta names a different conversation"
            else:
                complete, reason = True, None
        except (ValueError, IndexError, AttributeError, TypeError):
            reason = "transcript is malformed or truncated"
        # Refuse a source that changed while it was being read rather than take a
        # partial snapshot of a conversation something else is still writing.
        if path.read_bytes() != data:
            raise PoolError("source transcript changed while it was read: " + str(path))
        return {
            "data": data,
            "digest": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "complete": complete,
            "incomplete_reason": reason,
        }

    @staticmethod
    def write_private_copy(data, target):
        """An atomic private copy with a fresh inode, never a link to the source.

        The mode is set explicitly rather than inherited: the native writes 0644
        under an ordinary umask, and a transcript that reaches the pool from any
        context other than a pane would otherwise be published world-readable.
        """
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = target.with_name("." + target.name + "." + uuid.uuid4().hex + ".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
            # The rename itself has to reach disk. Without this a crash can leave
            # an index naming a revision whose directory entry never landed.
            directory_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if temporary.exists():
                temporary.unlink()
        return target

    def stage_revision(self, conversation, verified):
        """Materialise one immutable revision. Outside every lock, by design.

        Copying several megabytes is not something to do while holding the lock
        that `close-admission` -- the pool's stop button -- has to take.
        """
        target = self.revision_path(conversation, verified["digest"])
        # The name IS the digest, so anything already there either is these bytes
        # or is damaged. A size check cannot tell those apart; only the hash can,
        # and a revision is the thing every later append is measured against.
        if target.exists() and file_sha256(target) == verified["digest"]:
            return target
        return self.write_private_copy(verified["data"], target)

    def latest_view_path(self, conversation, name, archived):
        if archived:
            return self.history_root() / "archived_sessions" / name
        return self.history_root() / "sessions" / rollout_date(name) / name

    def refresh_latest_view(self, conversation, index=None):
        """Point the home-shaped trees at the index's CURRENT revision.

        *index* is advisory only and deliberately ignored for the decision: a
        caller holds whatever the index said when its own publication ran, and a
        newer publication may have advanced it since. Trusting the caller's copy
        is how a delayed older publication overwrites a newer view -- or unlinks
        the newer archived location on its way past. The file on disk decides.

        Idempotent and repairable: a crash between the index write and this call
        leaves a stale view, and the next publication, backfill or retry fixes it
        without needing to know a crash happened.
        """
        with pool_lock(self.root):
            current = self.read_index(conversation)
        if current is None:
            return None
        revision = self.revision_path(conversation, current["digest"])
        if not revision.exists():
            return None
        target = self.latest_view_path(conversation, current["name"], current.get("archived", False))
        if target.exists() and target.stat().st_size == current["size"] and file_sha256(target) == current["digest"]:
            return target
        # Read and copy outside the lock; only the swap is serialised.
        data = revision.read_bytes()
        with pool_lock(self.root):
            confirmed = self.read_index(conversation)
            if self.index_position(confirmed) != self.index_position(current):
                # It advanced while this copy was being made. The publication that
                # advanced it will place its own view; placing this one would
                # regress it.
                return None
            self.write_private_copy(data, target)
            # One conversation, one view. Archiving moves the transcript in the
            # pane's own home, so the tree it left must not keep answering for it.
            stale = self.latest_view_path(conversation, current["name"], not current.get("archived", False))
            if stale != target and stale.exists():
                stale.unlink()
        return target

    @staticmethod
    def index_position(index):
        """What an index was when it was read, for a compare-and-swap."""
        return None if index is None else (index["digest"], index["revision"])

    def classify_revision(self, conversation, index, verified):
        """Decide append / duplicate / older / conflict. Outside every lock.

        This is where the expensive work lives -- reading the accepted revision
        back off disk and comparing several megabytes of prefix -- and it is
        exactly the work that must NOT happen while `pool_lock` is held, because
        `close-admission`, the pool's stop button, queues behind that lock.
        """
        if index is None:
            return "indexed", None
        if verified["digest"] == index["digest"]:
            return "unchanged", None
        accepted = self.revision_path(conversation, index["digest"])
        if not accepted.exists():
            return "conflict", "the accepted revision is missing from the revision store"
        current = accepted.read_bytes()
        if verified["size"] < index["size"] and current.startswith(verified["data"]):
            # An older, shorter revision arriving after a newer one. Real, and
            # ordinary during backfill, which walks homes in no meaningful order.
            return "unchanged", None
        if not verified["data"].startswith(current):
            return "conflict", "the source does not extend the accepted revision"
        return "advanced", None

    def accept_revision(self, conversation, verified, name, archived, session, attempts=5):
        """Compare-and-swap one conversation's index. The only writer of record.

        Two phases. The classification above runs with no lock held; then
        `pool_lock` is taken for a handful of small-JSON operations and released.
        If the index moved between the two phases the whole thing is retried
        against the new predecessor, because a decision derived from a revision
        that is no longer current is not a decision about this conversation any
        more. Bounded, then refused rather than looped.

        Three outcomes, and the distinction is the whole point. An APPEND (the new
        bytes begin with exactly the accepted revision) advances the index; the
        native appends in place on resume, so this is the ordinary path. A
        same-digest or shorter-prefix arrival is a NO-OP -- a duplicate copy or an
        older revision showing up late, which backfill does constantly and which
        must not be mistaken for a fork. Anything else is a CONFLICT: two panes
        took the conversation in different directions. The staged revision is kept
        either way; what a conflict refuses is the right to be called current.
        """
        for _ in range(attempts):
            observed = self.read_index(conversation)
            outcome, reason = self.classify_revision(conversation, observed, verified)
            with pool_lock(self.root):
                index = self.read_index(conversation)
                if self.index_position(index) != self.index_position(observed):
                    continue  # it moved; re-decide against the new one
                now = time.time()
                if outcome == "indexed":
                    index = {
                        "conversation": conversation,
                        "revision": 1,
                        "digest": verified["digest"],
                        "size": verified["size"],
                        "name": name,
                        "archived": archived,
                        "complete": verified["complete"],
                        "pool_session": session,
                        "updated_at": now,
                        "revisions": [
                            {
                                "revision": 1,
                                "digest": verified["digest"],
                                "size": verified["size"],
                                "pool_session": session,
                                "published_at": now,
                            }
                        ],
                        "conflicts": [],
                    }
                    write_json(self.index_path(conversation, create=True), index)
                    return "indexed", index
                if outcome == "conflict":
                    return "conflict", self.record_conflict(index, conversation, verified, session, reason)
                if outcome == "unchanged":
                    if verified["digest"] == index["digest"]:
                        index.update(name=name, archived=archived, updated_at=now)
                        write_json(self.index_path(conversation, create=True), index)
                    return "unchanged", index
                index["revision"] += 1
                index.update(
                    digest=verified["digest"],
                    size=verified["size"],
                    name=name,
                    archived=archived,
                    complete=verified["complete"],
                    pool_session=session,
                    updated_at=now,
                )
                index["revisions"].append(
                    {
                        "revision": index["revision"],
                        "digest": verified["digest"],
                        "size": verified["size"],
                        "pool_session": session,
                        "published_at": now,
                    }
                )
                write_json(self.index_path(conversation, create=True), index)
                return "advanced", index
        raise PoolError(
            "the index for " + conversation + " changed under every attempt to "
            "publish; retry when fewer panes are settling at once"
        )

    def record_conflict(self, index, conversation, verified, session, reason):
        """Keep the divergent branch on record instead of discarding it."""
        entry = {
            "digest": verified["digest"],
            "size": verified["size"],
            "pool_session": session,
            "reason": reason,
            "observed_at": time.time(),
        }
        if not any(existing.get("digest") == verified["digest"] for existing in index.setdefault("conflicts", [])):
            index["conflicts"].append(entry)
            write_json(self.index_path(conversation, create=True), index)
        return index

    def publish_transcript(self, path, archived, session):
        """Stage, accept and re-view one transcript. Raises only on I/O it cannot do."""
        conversation = conversation_of(path.name)
        if conversation is None:
            raise PoolError("transcript filename does not name a conversation: " + path.name)
        verified = self.verify_transcript(path, conversation)
        self.stage_revision(conversation, verified)
        outcome, index = self.accept_revision(conversation, verified, path.name, archived, session)
        self.refresh_latest_view(conversation, index)
        return outcome, conversation, index

    def home_transcripts(self, home):
        """Every transcript a pane home holds, with whether it is archived.

        Both trees: `archive` MOVES a transcript into a flat `archived_sessions/`,
        so a home that archived its conversation has nothing under `sessions/`.
        """
        for archived, source in ((False, Path(home) / "sessions"), (True, Path(home) / "archived_sessions")):
            if not source.is_dir():
                continue
            for path in sorted(source.rglob("rollout-*.jsonl")):
                if path.is_symlink() or not path.is_file():
                    continue
                yield archived, path

    def publish_history(self, directory, record):
        """Publish a finished pane's transcripts. Never blocks settlement."""
        if record.get("profile") != "interactive":
            return 0
        published, pending = 0, []
        for archived, path in self.home_transcripts(directory / "home"):
            try:
                outcome, conversation, _ = self.publish_transcript(path, archived, record.get("id"))
                if outcome in ("indexed", "advanced"):
                    published += 1
                elif outcome == "conflict":
                    print(
                        "codex-pool: " + conversation + " diverged from the accepted "
                        "revision; kept as a conflicting branch",
                        file=sys.stderr,
                    )
            except (PoolError, OSError, ValueError) as error:
                # A full disk, a cross-device history root or an unreadable
                # transcript must not strand the pool key this session holds.
                # Record enough to finish the job later and carry on.
                pending.append({"path": str(path), "archived": archived, "error": str(error)})
                print("codex-pool: could not publish " + path.name + ": " + str(error), file=sys.stderr)
        self.record_pending_publication(directory, pending)
        return published

    @staticmethod
    def record_pending_publication(directory, pending):
        """The named recovery path for `history-retry`.

        `close` returns early once a record is closed, so a publication that
        failed during settlement can never be retried by closing again. Without
        this file the conversation is simply lost from the index.
        """
        path = directory / "publication-pending.json"
        if pending:
            write_json(path, {"pending": pending, "recorded_at": time.time()})
        elif path.exists():
            path.unlink()

    def closed_interactive_records(self):
        for path in sorted((self.root / "sessions").glob("*/session.json")):
            try:
                record = read_json(path)
            except (PoolError, ValueError, OSError):
                continue
            if record.get("profile") == "interactive" and record.get("state") == "closed":
                yield path.parent, record

    def history_backfill(self, conversation=None):
        """Index conversations from verified closed pool sources. Explicit only.

        Never reached implicitly: `resume-info` names this command as a remedy and
        stops there. It walks PRIVATE pane homes under closed records, so adopted
        ambient history in the shared tree can never be indexed by it -- that
        history has no pool record behind it and never becomes eligible here.
        """
        if conversation is not None and not UUID_PATTERN.match(conversation):
            raise PoolError("invalid conversation id")
        summary = {"indexed": 0, "unchanged": 0, "conflicts": [], "skipped": [], "conversations": []}
        for directory, record in self.closed_interactive_records():
            for archived, path in self.home_transcripts(directory / "home"):
                found = conversation_of(path.name)
                if found is None or (conversation is not None and found.lower() != conversation.lower()):
                    continue
                try:
                    outcome, found, _ = self.publish_transcript(path, archived, record["id"])
                except (PoolError, OSError, ValueError) as error:
                    summary["skipped"].append({"session": record["id"], "path": str(path), "reason": str(error)})
                    continue
                if outcome == "conflict":
                    summary["conflicts"].append({"conversation": found, "session": record["id"]})
                elif outcome == "unchanged":
                    summary["unchanged"] += 1
                else:
                    summary["indexed"] += 1
                if found not in summary["conversations"]:
                    summary["conversations"].append(found)
        return summary

    def history_retry(self, session=None):
        """Finish publications that failed during settlement, from closed records.

        Idempotent, and refuses to work from anything but a verified closed
        record: an unsettled session is still writing, and its transcript is not
        a revision of anything yet.
        """
        summary = {"retried": 0, "published": 0, "still_pending": 0, "skipped": []}
        directories = (
            [self.session_path(session)]
            if session
            else sorted(path.parent for path in (self.root / "sessions").glob("*/publication-pending.json"))
        )
        for directory in directories:
            pending_path = directory / "publication-pending.json"
            if not pending_path.exists():
                summary["skipped"].append({"session": directory.name, "reason": "nothing pending"})
                continue
            record = read_json(directory / "session.json")
            if record.get("state") != "closed":
                summary["skipped"].append(
                    {
                        "session": directory.name,
                        "reason": "source is " + str(record.get("state")) + "; only a closed record may publish",
                    }
                )
                continue
            summary["retried"] += 1
            remaining = []
            for item in read_json(pending_path).get("pending", []):
                path = Path(item["path"])
                if not path.exists():
                    continue
                try:
                    outcome, _, _ = self.publish_transcript(path, item.get("archived", False), record.get("id"))
                except (PoolError, OSError, ValueError) as error:
                    item["error"] = str(error)
                    remaining.append(item)
                    continue
                if outcome in ("indexed", "advanced"):
                    summary["published"] += 1
            self.record_pending_publication(directory, remaining)
            summary["still_pending"] += len(remaining)
        return summary

    # ---- conversation leases --------------------------------------------------

    def lease_holder(self, conversation):
        """Who holds this conversation, or None if genuinely nobody does.

        A lease file that cannot be parsed is NOT nobody. It is a lease whose
        owner cannot be identified, which is the one case where taking the
        conversation would silently run two panes against it. Refused, loudly,
        with the bytes left exactly where they are for a human to look at.
        """
        path = self.lease_path(conversation)
        if not path.exists():
            return None
        try:
            holder = read_json(path)
        except (PoolError, ValueError) as error:
            raise PoolError(
                "the lease for "
                + conversation
                + " is unreadable ("
                + str(error)
                + "); it is not treated as absent -- inspect "
                + str(path)
                + " by hand"
            ) from None
        if not isinstance(holder, dict) or not isinstance(holder.get("session"), str):
            raise PoolError(
                "the lease for " + conversation + " names no holder; it is not "
                "treated as absent -- inspect " + str(path) + " by hand"
            )
        return holder

    def holder_state(self, session):
        """The lease holder's settlement state, or None when it cannot be read.

        None is never "fine to proceed". A holder whose record is missing or
        unreadable is a holder whose exit has not been proved, and the whole
        point of preserving uncertain leases is that an unproved exit keeps the
        conversation.
        """
        try:
            return read_json(self.session_path(session) / "session.json").get("state")
        except (PoolError, ValueError, OSError):
            return None

    def claim_lease(self, conversation, session, request_id=None, expect=False):
        """One open at a time per conversation, durably.

        A lease is exclusivity, not liveness: it says another open owns this
        conversation, and only that holder reaching a verified `closed` releases
        it. A holder that is merely idle is still holding a live pool key, so the
        refusal names the command that settles it rather than taking it away.

        *expect* folds the index check into this same transition. The caller read
        an index to decide WHAT to import; between that read and this claim a
        concurrent close can publish a new revision, and importing the older one
        under a lease granted afterwards would fork the conversation with the
        lease's blessing. Passing the position the caller decided on makes the
        two facts one atomic step.
        """
        with pool_lock(self.root):
            holder = self.lease_holder(conversation)
            if holder is not None and holder.get("session") != session:
                other = holder["session"]
                state = self.holder_state(other)
                if state != "closed":
                    raise PoolError(
                        "conversation "
                        + conversation
                        + " is held by pool session "
                        + other
                        + " ("
                        + (state or "state unknown: its record is missing or unreadable")
                        + "); settle it first with: "
                        + self.settle_remedy(other, state)
                    )
            if expect is not False:
                position = self.index_position(self.read_index(conversation))
                if position != expect:
                    raise PoolError(
                        "conversation " + conversation + " advanced while this open was being "
                        "prepared; retry so the newest revision is the one imported"
                    )
            lease = {
                "conversation": conversation,
                "session": session,
                "request_id": request_id,
                "claimed_at": time.time(),
            }
            write_json(self.lease_path(conversation, create=True), lease)
            return lease

    def release_lease(self, conversation, session):
        """Release only a lease this session owns, and only once it is closed."""
        with pool_lock(self.root):
            try:
                holder = self.lease_holder(conversation)
            except PoolError:
                # Reached from `close`, after the key is already revoked. An
                # unreadable lease must not be deleted on a guess, and must not
                # turn settlement into a failure either.
                print("codex-pool: left the unreadable lease for " + conversation + " in place", file=sys.stderr)
                return False
            if holder is None or holder.get("session") != session:
                return False
            if self.holder_state(session) != "closed":
                return False
            self.lease_path(conversation).unlink()
            return True

    # ---- selected resume ------------------------------------------------------

    def resume_info(self, conversation):
        """Read-only eligibility for one explicitly selected conversation.

        Reads. Never backfills, never reconciles, never allocates. Every refusal
        is typed and carries the command that would fix it, so a caller learns
        what to do without this function quietly doing it.
        """
        if not UUID_PATTERN.match(str(conversation)):
            raise PoolError("invalid conversation id")
        conversation = conversation.lower()
        launcher = str(Path(__file__).resolve().parent.parent / "codex-pool")
        answer = {"conversation": conversation, "status": None, "remedy": None}
        try:
            index = self.read_index(conversation)
        except PoolError as error:
            # Read-only to the end: a damaged arbiter is reported, never rebuilt.
            return dict(
                answer,
                status="damaged-index",
                detail=str(error),
                remedy="inspect " + str(self.index_path(conversation)) + " by hand; "
                "the revision store still holds every published revision",
            )

        if index is None:
            sources = self.conversation_sources(conversation)
            if not sources:
                ambient = any(
                    conversation_of(path.name) == conversation
                    for tree in ("sessions", "archived_sessions")
                    for path in (self.history_root() / tree).rglob("rollout-*.jsonl")
                    if (self.history_root() / tree).is_dir()
                )
                answer.update(
                    status="ambient-only" if ambient else "unknown",
                    detail="this conversation has no pool session behind it; shared history "
                    "holds adopted transcripts that the pool never served"
                    if ambient
                    else "no pool session and no history holds this conversation",
                )
                return answer
            unsettled = [item for item in sources if item["state"] != "closed"]
            if unsettled:
                # Refused even when a CLOSED source also holds this conversation:
                # an unsettled pane may still be appending to it, and resuming
                # from the older closed copy would fork the conversation in two.
                holder = unsettled[0]
                settled_too = len(unsettled) < len(sources)
                answer.update(
                    status="unsettled-source",
                    pool_session=holder["session"],
                    source_state=holder["state"],
                    remedy=self.settle_remedy(holder["session"], holder["state"]),
                    detail="pool session " + holder["session"] + " still holds this "
                    "conversation and has not settled"
                    + (
                        "; a closed copy exists but resuming it while another "
                        "pane may still be appending would fork the conversation"
                        if settled_too
                        else ""
                    )
                    + ". It is never reconciled automatically to make a "
                    "resume succeed",
                )
                return answer
            answer.update(
                status="missing-index",
                pool_session=sources[0]["session"],
                remedy=shlex.join(
                    [launcher, "--root", str(self.root), "history-backfill", "--conversation", conversation]
                ),
                detail="a closed pool session holds this conversation but it has never been indexed",
            )
            return answer
        answer.update(
            revision=index["revision"],
            digest=index["digest"],
            size=index["size"],
            pool_session=index.get("pool_session"),
            archived=index.get("archived", False),
            conflicts=len(index.get("conflicts", [])),
        )
        if not index.get("complete", False):
            answer.update(
                status="incomplete-transcript",
                detail="the indexed transcript is truncated or malformed, so it cannot be replayed as a conversation",
            )
            return answer
        if not self.revision_path(conversation, index["digest"]).exists():
            answer.update(
                status="missing-revision",
                remedy=shlex.join(
                    [launcher, "--root", str(self.root), "history-backfill", "--conversation", conversation]
                ),
                detail="the index names a revision that is not in the revision store",
            )
            return answer
        holder = self.lease_holder(conversation)
        if holder is not None:
            state = self.holder_state(holder["session"])
            if state != "closed":
                answer.update(
                    status="leased",
                    pool_session=holder["session"],
                    source_state=state or "unknown",
                    remedy=self.settle_remedy(holder["session"], state),
                    detail="another open already holds this conversation"
                    + ("" if state else "; its record is missing or unreadable, so its exit is unproved"),
                )
                return answer
        # An index is not a licence to stop looking. A pane that STARTED this
        # conversation holds no lease at all, so the lease check above cannot see
        # it -- and a source that may still be appending is one that importing
        # underneath would fork. Narrower than the unindexed check above on
        # purpose: there, `idle` means "not a valid source yet"; here it means
        # "settled and no longer writing", which is exactly what makes it safe.
        writing = [
            item
            for item in self.conversation_sources(conversation)
            if item["state"] in ("running", "starting", "uncertain")
        ]
        if writing:
            live = writing[0]
            answer.update(
                status="unsettled-source",
                pool_session=live["session"],
                source_state=live["state"],
                remedy=self.settle_remedy(live["session"], live["state"]),
                detail="pool session " + live["session"] + " still holds this conversation and has not settled",
            )
            return answer
        source = self.conversation_record(index.get("pool_session"))
        answer.update(
            status="eligible", workspace=source.get("workspace"), unarchive_by_copy=bool(index.get("archived", False))
        )
        if index.get("archived"):
            answer["detail"] = (
                "this conversation is archived; resuming it copies the "
                "transcript back into sessions/, which unarchives it"
            )
        return answer

    def settle_remedy(self, session, state):
        """The command that actually settles a holder in *state*.

        `close` refuses anything that is not already settled, so handing an
        operator `close` for an `uncertain` pane sends them to a second refusal.
        Reconciliation comes first there -- and it is named, never run from here.
        """
        launcher = str(Path(__file__).resolve().parent.parent / "codex-pool")
        close = shlex.join([launcher, "--root", str(self.root), "close", session])
        if state in ("running", "uncertain", "starting", "allocating"):
            return shlex.join([launcher, "--root", str(self.root), "reconcile", session]) + " && " + close
        return close

    def conversation_record(self, session):
        if not session:
            return {}
        try:
            record = read_json(self.session_path(session) / "session.json")
        except (PoolError, ValueError, OSError):
            return {}
        return {"state": record.get("state"), "workspace": (record.get("effective_posture") or {}).get("workspace")}

    def conversation_sources(self, conversation):
        """Every pool session whose private home holds this conversation."""
        found = []
        for path in sorted((self.root / "sessions").glob("*/session.json")):
            try:
                record = read_json(path)
            except (PoolError, ValueError, OSError):
                continue
            if record.get("profile") != "interactive":
                continue
            for archived, transcript in self.home_transcripts(path.parent / "home"):
                if conversation_of(transcript.name) == conversation:
                    found.append(
                        {
                            "session": record["id"],
                            "state": record.get("state"),
                            "archived": archived,
                            "path": str(transcript),
                        }
                    )
        # Closed records first: an unsettled one is only interesting when nothing
        # settled holds the conversation.
        found.sort(key=lambda item: (item["state"] != "closed", item["session"]))
        return found

    def import_selected_resume(self, conversation, session, directory, home, workdir, request_id=None):
        """Seed an idle destination home with one explicitly selected conversation.

        Runs while the destination is still idle and nothing has spawned, so a
        refusal leaves no running pane -- only the fresh key the caller's `close`
        revokes. The copy happens under the destination's own dispatch lock and
        outside `pool_lock`, which is taken only for the lease transition.
        """
        info = self.resume_info(conversation)
        if info["status"] != "eligible":
            raise PoolError(
                "cannot resume "
                + conversation
                + ": "
                + info["status"]
                + " -- "
                + str(info.get("detail", ""))
                + (("; " + info["remedy"]) if info.get("remedy") else "")
            )
        index = self.read_index(conversation)
        # One transition: nobody else holds it AND it is still the revision the
        # eligibility check above was decided against.
        self.claim_lease(conversation, session, request_id, expect=self.index_position(index))
        revision = self.revision_path(conversation, index["digest"])
        # Always into `sessions/`, never back into `archived_sessions/`: the native
        # refuses to resume an archived transcript, and copying it here is exactly
        # the unarchive-by-relocation the caller is told about.
        target = home / "sessions" / rollout_date(index["name"]) / index["name"]
        if target.exists():
            raise PoolError("destination home already holds " + conversation + "; refusing to overwrite its progress")
        data = revision.read_bytes()
        if hashlib.sha256(data).hexdigest() != index["digest"]:
            raise PoolError("the stored revision for " + conversation + " does not match its digest")
        self.write_private_copy(data, target)
        if file_sha256(target) != index["digest"] or target.stat().st_ino == revision.stat().st_ino:
            raise PoolError("imported transcript is not an independent private copy")
        return {
            "conversation": conversation,
            "revision": index["revision"],
            "digest": index["digest"],
            "size": index["size"],
            "source_session": index.get("pool_session"),
            "source_workspace": info.get("workspace"),
            "workspace": workdir,
            "archived": bool(index.get("archived", False)),
            "unarchived": bool(index.get("archived", False)),
            "imported_at": time.time(),
            "path": str(target),
        }

    def reconcile(self, session, terminate_descendants=True):
        """Settle a session whose process is provably gone.

        A pane whose terminal died -- or any job whose launcher was killed --
        leaves its record in `running`, and `close` refuses an unsettled session,
        so its pool key can never be revoked. Proof of death is the recorded
        KERNEL identity being absent, never the pid alone. Settlement records
        that the outcome is unknown: it does not claim the work completed, and
        nothing here replays it.
        """
        from pool_processes import descendants, process_table, settle
        from pool_processes import identity as process_identity

        with self.locked_session(session) as (directory, record):
            if record["state"] in ("idle", "failed", "closed", "closing"):
                return {"session": session, "state": record["state"], "reconciled": False}
            recorded = record.get("process_identity")
            pid = record.get("pid")
            if record.get("profile") == "interactive" and not recorded:
                # A pane is not protected by its dispatch lock -- `exec_interactive`
                # releases it while the pane runs -- so the recorded kernel identity
                # is the ONLY evidence available here. Without it, settling would be
                # an assumption that the pane exited, and a resumed conversation
                # would then be imported from a transcript still being written.
                raise PoolError(
                    "pane session " + session + " recorded no process identity, so its "
                    "exit cannot be proved; settle it by hand after confirming no "
                    "native process remains"
                )
            if pid:
                try:
                    live = process_identity(pid)
                except OSError:
                    raise PoolError("process identity is not observable; refusing recovery") from None
                if live is not None and recorded and list(live) == list(recorded):
                    raise PoolError("session is still running; stop it before reconciling")
            if recorded:
                try:
                    table = process_table()
                    if any(info[0] == recorded[0] for info in table.values()):
                        raise PoolError("session root is still running; refusing recovery")
                    known = descendants(table, {recorded[0]})
                    if known != {recorded[0]} and not terminate_descendants:
                        raise PoolError("session descendants are still running; refusing recovery")
                    if known != {recorded[0]} and not settle(known):
                        raise PoolError("session descendants could not be settled; quarantine required")
                except (OSError, ValueError, subprocess.SubprocessError):
                    raise PoolError("process state is not observable; quarantine required") from None
            record.update(state="idle", outcome="unknown-settled-by-reconcile", reconciled_at=time.time())
            write_json(directory / "session.json", record)
            return {"session": session, "state": "idle", "reconciled": True}

    @staticmethod
    def discard_home_cache(directory):
        """Delete a closed home's `.tmp`: regenerable native caches, never history.

        A real delete, deliberately not the Trash: moving a cache there frees
        nothing. Safe only because a closed home never runs a native again --
        `.tmp` also holds the native's rollout-maintenance lock, which matters
        only while that home's process lives. The home's path must be free of
        symlinks and the cache a real directory we own, so this never reaches
        outside the home; its permission bits are the native's business.
        Failures are reported, never raised: the caller's key is already revoked.
        """
        cache = Path(directory) / "home" / ".tmp"
        try:
            cache = private_path(Path(directory) / "home", directory=True) / ".tmp"
            try:
                info = os.lstat(cache)
            except FileNotFoundError:
                return
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
                raise PoolError("not an owned cache directory")
            shutil.rmtree(cache)
        except (PoolError, OSError) as error:
            print("codex-pool: kept " + str(cache) + ": " + str(error), file=sys.stderr)

    @staticmethod
    def reconciled_and_untouched(record):
        """Settled by `reconcile` and never launched again since."""
        return (
            record.get("state") == "idle"
            and record.get("outcome") == "unknown-settled-by-reconcile"
            and record.get("started_at", 0) < record.get("reconciled_at", 0)
        )

    def reclaim(self, apply=False):
        """Free the caches sessions left behind before close cleaned up. Explicit only.

        Closed sessions lose `.tmp`. Panes that `reconcile` proved dead and left
        idle are closed through the ordinary `close` -- publishing their history
        and revoking their key -- unless an Orca terminal is still bound to them.
        Everything else is listed with its settle command and never touched:
        `reconcile` writes state and can kill processes, so it is never called here.
        A dry run (the default) writes nothing and counts what it would free.
        """
        bound = set(self.interactive_mapping().values())
        summary = {
            "applied": apply,
            "caches": 0,
            "bytes": 0,
            "would_close": [],
            "closed": [],
            "left_idle": 0,
            "unsettled": [],
            "errors": [],
        }
        for path in sorted((self.root / "sessions").glob("*/session.json")):
            try:
                record = read_json(path)
            except (PoolError, ValueError, OSError):
                continue
            session, directory = record.get("id"), path.parent
            closable = self.reconciled_and_untouched(record) and session not in bound
            if record.get("state") not in ("closed", "idle"):
                summary["unsettled"].append(
                    {
                        "session": session,
                        "state": record.get("state"),
                        "remedy": self.settle_remedy(session, record.get("state")),
                    }
                )
                continue
            if record.get("state") == "idle" and not closable:
                summary["left_idle"] += 1
                continue
            cache = directory / "home" / ".tmp"
            held = tree_bytes(cache) if cache.is_dir() and not cache.is_symlink() else 0
            if not apply:
                if closable:
                    summary["would_close"].append(session)
            else:
                try:
                    if closable:
                        # Rechecked under close's own lock: a pane relaunched since
                        # this scan is no longer ours to close.
                        if not self.close(session, only_if=self.reconciled_and_untouched):
                            continue
                        summary["closed"].append(session)  # close discarded the cache
                    else:
                        with self.locked_session(session) as (directory, record):
                            if record.get("state") == "closed":
                                self.discard_home_cache(directory)
                except (PoolError, OSError, ValueError) as error:
                    summary["errors"].append({"session": session, "error": str(error)})
                    continue
                if cache.exists():
                    continue
            if held:
                summary["caches"] += 1
                summary["bytes"] += held
        return summary

    def settle_stale(self, apply=False, limit=None, min_age=600):
        """Settle and close `uncertain` sessions whose processes are provably gone.

        Every failed launch used to keep its pool key forever: a native that
        exited non-zero, a pane whose Orca terminal closed, a consult killed
        outright. The proof is `reconcile`'s own -- for a pane, its recorded
        kernel identity and every descendant absent; for a job, its dispatch lock
        free (`run` holds it for the native's whole life) and its recorded
        identity absent -- and it is called with `terminate_descendants=False`,
        so nothing is ever killed here. A refusal leaves the session untouched.
        A dry run (the default) only counts candidates: proving death is itself
        a state transition, so it is never simulated.
        """
        summary = {"applied": apply, "candidates": 0, "settled": [], "refused": []}
        now = time.time()
        for path in sorted((self.root / "sessions").glob("*/session.json")):
            try:
                record = read_json(path)
            except (PoolError, ValueError, OSError):
                continue
            if record.get("state") != "uncertain":
                continue
            last = max(record.get(key) or 0 for key in ("ended_at", "started_at", "created_at"))
            if now - last < min_age:
                continue
            summary["candidates"] += 1
            if not apply:
                continue
            if limit is not None and len(summary["settled"]) + len(summary["refused"]) >= limit:
                break
            session = record.get("id")
            try:
                self.reconcile(session, terminate_descendants=False)
                self.close(session)
            except (PoolError, OSError, ValueError, KeyError) as error:
                summary["refused"].append({"session": session, "reason": str(error)})
                continue
            summary["settled"].append(session)
        return summary

    def maintain(self, interval=600, limit=20):
        """A bounded `settle_stale` at most once per *interval*, after a launch ends.

        Runs at the end of work, never before it, so no launch waits on it; any
        failure is swallowed, because a caller's own close already succeeded.
        """
        try:
            lock = os.open(self.root / "maintenance.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        except OSError:
            return None
        try:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return None
            stamp = self.root / "maintenance.stamp"
            if stamp.exists() and time.time() - stamp.stat().st_mtime < interval:
                return None
            stamp.touch(mode=0o600)
            summary = self.settle_stale(apply=True, limit=limit)
            if summary["settled"]:
                print("codex-pool: settled " + str(len(summary["settled"])) + " stale session(s)", file=sys.stderr)
            return summary
        except Exception:  # noqa: BLE001 -- maintenance must never fail a caller
            return None
        finally:
            os.close(lock)

    def close(self, session, only_if=None):
        with self.locked_session(session) as (directory, record):
            if only_if is not None and not only_if(record):
                return False
            if record["state"] == "closed":
                return
            if record["state"] not in ("idle", "failed", "closing"):
                raise PoolError("cannot revoke an unsettled session")
            if record["state"] in ("idle", "failed"):
                self.publish_history(directory, record)
            if record["state"] == "closing":
                keys = self.admin.request("GET", "/api/api-keys/")
                if not isinstance(keys, list) or any(not isinstance(key, dict) or "id" not in key for key in keys):
                    raise PoolError("cannot verify pending key revocation")
                present = any(key["id"] == record["key_id"] for key in keys)
            else:
                present = True
                record["state"] = "closing"
                write_json(directory / "session.json", record)
            if present:
                self.admin.request("DELETE", "/api/api-keys/" + urllib.parse.quote(record["key_id"], safe=""))
            record.pop("key", None)
            record["state"] = "closed"
            write_json(directory / "session.json", record)
        # Outside the dispatch lock and after the record is verifiably closed:
        # releasing is itself conditional on that state, so the lease outlives any
        # failure between publication and revocation rather than being dropped by
        # a session that never settled. Publication above ran while it was held.
        resumed = (record.get("resume") or {}).get("conversation")
        if resumed:
            self.release_lease(resumed, session)
        self.discard_home_cache(directory)
        return True

    def inspect(self, session):
        record = read_json(self.session_path(session) / "session.json")
        return {
            key: record[key]
            for key in ("id", "profile", "native_sha256", "state", "generation", "exit_code", "request_id")
            if key in record
        }


def refuse_misplaced_expected_identity(command, remainder, raw):
    """Refuse `--expected-identity` that argparse swallowed into the native remainder.

    Everything after `run <session>` (and every `interactive` positional) is the
    native Codex argv, so a trailing `--expected-identity X` reaches no pool
    option: the run is later refused as a changed serving identity, which names
    the wrong cause. Only the part before `--` is checked; after `--` the caller
    has said explicitly that the argv is native. argparse may consume a `--`
    that directly precedes the remainder, so that one is read from the raw argv.
    """
    start = len(raw) - len(remainder)
    if remainder and raw[start:] == remainder and raw[start - 1 : start] == ["--"]:
        return
    for token in remainder:
        if token == "--":
            return
        if token == "--expected-identity" or token.startswith("--expected-identity="):
            if command == "run":
                raise PoolError(
                    "--expected-identity must come before the session: "
                    "codex-pool run --expected-identity <identity> <session> -- <native args>"
                )
            raise PoolError(
                "interactive takes no --expected-identity (it pins the serving identity "
                "itself); put native arguments after --: "
                "codex-pool interactive --native <path> -- <native args>"
            )


def main(argv=None):
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status")
    allocate = sub.add_parser("new")
    allocate.add_argument("--profile", choices=["review", "implementation"], required=True)
    allocate.add_argument("--native", required=True)
    allocate.add_argument("--request-id")
    allocate.add_argument("--expected-identity")
    metadata = sub.add_parser("metadata")
    metadata.add_argument("--profile", choices=["review", "implementation"], required=True)
    metadata.add_argument("--native", required=True)
    execute = sub.add_parser("run")
    execute.add_argument("--expected-identity")
    execute.add_argument("--close-when-settled", action="store_true")
    execute.add_argument("session")
    execute.add_argument("args", nargs=argparse.REMAINDER)
    close = sub.add_parser("close")
    close.add_argument("session")
    inspect = sub.add_parser("inspect")
    inspect.add_argument("session")
    settle = sub.add_parser("reconcile")
    settle.add_argument("session")
    reclaim = sub.add_parser("reclaim")
    reclaim.add_argument("--apply", action="store_true")
    reclaim.add_argument("--settle-uncertain", action="store_true")
    for name in ("pause", "reactivate"):
        action = sub.add_parser(name)
        action.add_argument("account_id")
    tui = sub.add_parser("interactive")
    tui.add_argument("--native", required=True)
    # One token per user-visible open, generated and persisted by the caller, so a
    # retry after a lost response reaches the SAME pane instead of opening another.
    tui.add_argument("--request-id")
    tui.add_argument("args", nargs=argparse.REMAINDER)
    lookup = sub.add_parser("resume-info")
    lookup.add_argument("conversation")
    backfill = sub.add_parser("history-backfill")
    backfill.add_argument("--conversation")
    retry = sub.add_parser("history-retry")
    retry.add_argument("--session")
    live = sub.add_parser("history-live")
    live.add_argument("--session", required=True)
    sub.add_parser("open")
    sub.add_parser("close-admission")
    trust = sub.add_parser("trust-workspace")
    trust.add_argument("workspace", nargs="?")
    raw = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(raw)
    try:
        pool = Pool(args.root)
        if args.command == "status":
            print(json.dumps(pool.admin.request("GET", "/api/accounts"), indent=2))
        elif args.command == "new":
            print(json.dumps(pool.allocate(args.profile, args.native, args.request_id, args.expected_identity)))
        elif args.command == "metadata":
            print(json.dumps(pool.metadata(args.profile, args.native)))
        elif args.command == "interactive":
            refuse_misplaced_expected_identity("interactive", args.args, raw)
            native_args = args.args[1:] if args.args[:1] == ["--"] else args.args
            selected = interactive_plan(native_args)["resume"]
            if selected:
                pool.prepare_selected_resume(selected)
            serving = pool.metadata("interactive", args.native)
            allocated = pool.allocate(
                "interactive", args.native, args.request_id or ("pane-" + uuid.uuid4().hex), serving["identity"]
            )
            session = allocated["session"]
            print("codex-pool: pane session " + session, file=sys.stderr)
            try:
                code = pool.exec_interactive(session, native_args, serving["identity"])
            finally:
                try:
                    pool.close(session)
                except (PoolError, OSError):
                    print("codex-pool: pane ended; session retained for reconciliation: " + session, file=sys.stderr)
                pool.maintain()
            return code
        elif args.command == "history-live":
            print(json.dumps({"linked": pool.expose_live_history(args.session)}))
        elif args.command == "resume-info":
            print(json.dumps(pool.resume_info(args.conversation), indent=2))
        elif args.command == "history-backfill":
            print(json.dumps(pool.history_backfill(args.conversation), indent=2))
        elif args.command == "history-retry":
            print(json.dumps(pool.history_retry(args.session), indent=2))
        elif args.command == "reconcile":
            print(json.dumps(pool.reconcile(args.session)))
        elif args.command == "reclaim":
            summary = pool.reclaim(apply=args.apply)
            if args.settle_uncertain:
                summary["settle_uncertain"] = pool.settle_stale(apply=args.apply)
            print(json.dumps(dict(summary, unsettled=len(summary["unsettled"])), indent=2))
        elif args.command == "inspect":
            print(json.dumps(pool.inspect(args.session)))
        elif args.command == "run":
            refuse_misplaced_expected_identity("run", args.args, raw)
            native_args = args.args[1:] if args.args[:1] == ["--"] else args.args
            if not args.close_when_settled:
                return pool.run(args.session, native_args, args.expected_identity)
            # A consult hands this process its terminal and signals by exec, so
            # the launch is closed here: by its record, never its exit code --
            # `run` exits 2 for its own refusals too -- and the native's result
            # is returned whatever the cleanup does.
            try:
                code = pool.run(args.session, native_args, args.expected_identity)
            except PoolError as error:
                print("codex-pool: " + str(error), file=sys.stderr)
                code = 2
            try:
                if pool.inspect(args.session).get("state") in ("idle", "failed"):
                    pool.close(args.session)
                    pool.maintain()
                else:
                    print("codex-pool: uncertain session retained for inspection: " + args.session, file=sys.stderr)
            except (PoolError, OSError, ValueError) as error:
                print(
                    "codex-pool: completed; cleanup needs reconciliation for " + args.session + ": " + str(error),
                    file=sys.stderr,
                )
            return code
        elif args.command == "close":
            pool.close(args.session)
            print(json.dumps({"state": "closed", "revoked": True}))
            pool.maintain()
        elif args.command == "open":
            print(json.dumps(pool.set_admission("open")))
        elif args.command == "close-admission":
            print(json.dumps(pool.set_admission("closed")))
        elif args.command == "trust-workspace":
            workspace = str(Path(args.workspace or Path.cwd()).resolve())
            approvals = (
                read_json(pool.root / "workspace-trust.json") if (pool.root / "workspace-trust.json").exists() else {}
            )
            approvals[workspace] = {"approved_at": time.time()}
            write_json(pool.root / "workspace-trust.json", approvals)
            print(json.dumps({"workspace": workspace, "trusted": True}))
        else:
            pool.admin.request(
                "POST", "/api/accounts/" + urllib.parse.quote(args.account_id, safe="") + "/" + args.command, {}
            )
        return 0
    except (PoolError, OSError, ValueError) as error:
        print("codex-pool: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    if sys.argv[1:2] == ["_exec"]:
        with os.fdopen(int(sys.argv[2])) as gate:
            command = json.loads(gate.readline())
        os.execvpe(command[0], command, os.environ)
    if sys.argv[1:2] == ["_supervise"]:
        raise SystemExit(supervise(int(sys.argv[2]), *sys.argv[3:6]))
    raise SystemExit(main())

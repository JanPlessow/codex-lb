"""Dispatcher tests: execution positions, private state and independent jobs."""

import contextlib
import hashlib
import importlib
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "dispatcher/bin/codex-ring"))

pool = importlib.import_module("pool")
pool_processes = importlib.import_module("pool_processes")
assert pool.__file__ is not None
POOL_ENTRY = pool.__file__

# The canonical process identity implementation uses Darwin libproc.
pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="macOS dispatcher process identity")


class Admin:
    def __init__(self):
        self.requests = []

    def request(self, method, path, value=None):
        self.requests.append((method, path, value))
        if method == "GET" and path == "/api/pool/metadata":
            return {"contract_version": 1, "identity": "0" * 64}
        if method == "GET" and path == "/api/accounts":
            return [{"id": "worker"}]
        if method == "POST":
            return {"id": str(len(self.requests)), "key": "private-local-key"}


class PoolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        # An empty personal directory: no pane in a test reads the real one.
        (self.root / "personal").mkdir()
        personal = patch.dict(os.environ, {"CODEX_POOL_PERSONAL_DIR": str(self.root / "personal")})
        personal.start()
        self.addCleanup(personal.stop)
        self.native = self.root / "fake-native"
        self.native.write_text('#!/bin/sh\nif [ "$1" = "--version" ]; then echo "codex-cli test"; fi\nexit 0\n')
        self.native.chmod(0o700)
        pool.write_json(
            self.root / "dispatcher.json",
            {
                "endpoint": "http://127.0.0.1:12345",
                "admin_password": "private",
                "admission": "open",
                "native_binaries": {str(self.native): hashlib.sha256(self.native.read_bytes()).hexdigest()},
            },
        )
        self.admin = Admin()
        self.pool = pool.Pool(self.root, self.admin)

    def test_admission_controls_are_durable_and_open_requires_enrollment(self):
        self.pool.set_admission("closed")
        self.assertEqual(pool.read_json(self.root / "dispatcher.json")["admission"], "closed")
        self.pool.set_admission("open")
        self.assertEqual(pool.read_json(self.root / "dispatcher.json")["admission"], "open")
        empty = patch.object(
            self.admin,
            "request",
            side_effect=lambda method, path, value=None: [] if path == "/api/accounts" else {"contract_version": 1},
        )
        empty.start()
        self.addCleanup(empty.stop)
        with self.assertRaisesRegex(pool.PoolError, "without enrolled accounts"):
            self.pool.set_admission("open")

    def test_interactive_pane_mapping_survives_pool_reload(self):
        session = self.pool.allocate("interactive", str(self.native))["session"]
        self.pool.bind_interactive("orca-pane-1", session)
        restarted = pool.Pool(self.root, self.admin)
        self.assertEqual(restarted.interactive_mapping()["orca-pane-1"], session)
        with self.assertRaises(pool.PoolError):
            restarted.bind_interactive("orca-pane-1", "f" * 32)

    def test_identical_native_payload_in_new_worktree_is_admitted_by_bytes(self):
        first, second = self.root / "first-native", self.root / "second-native"
        for path in (first, second):
            path.write_bytes(Path("/usr/bin/true").read_bytes())
            path.chmod(0o700)
        self.pool.config["native_binaries"] = {str(first): pool.pin_native(first)}
        allocated = self.pool.allocate("review", str(second))
        self.assertEqual(self.pool.run(allocated["session"], ["exec", "test"]), 0)
        second.write_bytes(second.read_bytes() + b"changed")
        with self.assertRaisesRegex(pool.PoolError, "not a verified"):
            self.pool.allocate("review", str(second))
        with self.assertRaisesRegex(pool.PoolError, "unsupported native launcher"):
            self.pool.allocate("review", str(self.native))

    def test_pinned_payload_runs_without_launcher_and_payload_drift_is_refused(self):
        payload = self.root / "payload"
        payload.write_text("#!/bin/sh\nexit 0\n")
        payload.chmod(0o700)
        self.native.write_text("#!/bin/sh\nexit 91\n")
        self.pool.config["native_binaries"][str(self.native)] = {
            "executable": str(payload),
            "files": {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in (self.native, payload)},
        }
        allocated = self.pool.allocate("review", str(self.native))
        self.assertEqual(self.pool.run(allocated["session"], ["exec", "test"]), 0)
        payload.write_text("#!/bin/sh\nexit 92\n")
        with self.assertRaisesRegex(pool.PoolError, "native binary changed"):
            self.pool.run(allocated["session"], ["exec", "test"])
        self.assertEqual(self.pool.inspect(allocated["session"])["state"], "idle")

    def test_provider_words_inside_prompt_are_not_execution_overrides(self):
        args = [
            "exec",
            "-s",
            "read-only",
            "-c",
            'model_reasoning_effort="high"',
            'Explain --config model_provider="another" and app-server',
        ]
        self.assertEqual(pool.validate_native_args(args, "review"), args)

    def test_structural_overrides_refused_before_native_spawn(self):
        for args in [
            ["login"],
            ["app-server"],
            ["exec", '--config=model_provider="another"'],
            ["exec", '-cmodel_provider="another"'],
            ["exec", "--oss"],
            ["exec", "-s", "danger-full-access"],
            ["exec", "--profile", "foreign"],
            ["exec", "--dangerously-bypass-approvals-and-sandbox"],
            ["exec", "-c", 'model_providers.other.base_url="http://foreign"'],
        ]:
            with self.subTest(args=args), self.assertRaises(pool.PoolError):
                pool.validate_native_args(args, "review")

    def test_implementation_cannot_ignore_hook_configuration(self):
        with self.assertRaises(pool.PoolError):
            pool.validate_native_args(["exec", "--ignore-user-config"], "implementation")
        self.assertEqual(
            pool.validate_native_args(
                ["exec", "--dangerously-bypass-hook-trust", "-s", "workspace-write", "-"], "implementation"
            ),
            ["exec", "--dangerously-bypass-hook-trust", "-s", "workspace-write", "-"],
        )

    def test_ten_sessions_have_independent_locks_and_keys(self):
        sessions = [self.pool.allocate("review", str(self.native)) for _ in range(10)]
        with contextlib.ExitStack() as locks:
            for item in sessions:
                locks.enter_context(self.pool.locked_session(item["session"]))
            with self.assertRaises(pool.PoolError):
                with self.pool.locked_session(sessions[0]["session"]):
                    self.fail("same session admitted twice")
        self.assertEqual(len({item["session"] for item in sessions}), 10)
        self.assertEqual(len(self.admin.requests), 10)
        for item in sessions:
            self.assertFalse((Path(item["home"]) / "auth.json").exists())
            record = Path(item["home"]).parent / "session.json"
            self.assertEqual(record.stat().st_mode & 0o777, 0o600)

    def test_lost_allocation_response_recovers_original_session(self):
        first = self.pool.allocate("review", str(self.native), "run-one:review")
        restarted = pool.Pool(self.root, self.admin)
        self.assertEqual(restarted.allocate("review", str(self.native), "run-one:review"), first)
        self.assertEqual(len(self.admin.requests), 1)
        with self.assertRaises(pool.PoolError):
            restarted.allocate("implementation", str(self.native), "run-one:review")
        self.assertNotIn("key", restarted.inspect(first["session"]))

    def test_serving_change_between_authorization_and_run_refuses_native(self):
        original_request = self.admin.request
        proxy = {"contract_version": 1, "identity": "a" * 64}

        def request(method, path, value=None):
            if path == "/api/pool/metadata":
                return dict(proxy)
            return original_request(method, path, value)

        with patch.object(self.admin, "request", side_effect=request):
            measured = self.pool.metadata("review", str(self.native))
            item = self.pool.allocate("review", str(self.native), "bound-review", measured["identity"])
            proxy["identity"] = "b" * 64
            with patch("pool.subprocess.Popen") as spawn, self.assertRaises(pool.PoolError):
                self.pool.run(item["session"], ["exec", "-"], measured["identity"])
            spawn.assert_not_called()
            self.assertEqual(self.pool.inspect(item["session"])["state"], "idle")

    def test_uncertain_key_creation_does_not_allocate_replacement(self):
        with patch.object(self.admin, "request", side_effect=pool.PoolError("lost response")) as request:
            for _ in range(2):
                with self.assertRaises(pool.PoolError):
                    self.pool.allocate("review", str(self.native), "run-two:review")
            self.assertEqual(request.call_count, 1)

    def test_lost_close_response_reconciles_without_repeating_delete(self):
        item = self.pool.allocate("review", str(self.native))
        with patch.object(self.admin, "request", side_effect=pool.PoolError("lost response")):
            with self.assertRaises(pool.PoolError):
                self.pool.close(item["session"])
        self.assertEqual(self.pool.inspect(item["session"])["state"], "closing")
        with patch.object(self.admin, "request", return_value=[]) as request:
            self.pool.close(item["session"])
            self.pool.close(item["session"])
        request.assert_called_once_with("GET", "/api/api-keys/")
        self.assertEqual(self.pool.inspect(item["session"])["state"], "closed")

    def test_ambient_upstream_credentials_and_old_ring_identity_are_removed(self):
        env = pool.clean_environment(
            {
                "PATH": "/bin",
                "OPENAI_API_KEY": "secret",
                "CODEX_HOME": "/foreign",
                "CODEX_RING_CONSULT_ACCOUNT": "desktop",
                "HTTP_PROXY": "ordinary-tools-proxy",
                "NO_PROXY": "example.com",
            }
        )
        self.assertNotIn("OPENAI_API_KEY", env)
        self.assertNotIn("CODEX_HOME", env)
        self.assertNotIn("CODEX_RING_CONSULT_ACCOUNT", env)
        self.assertEqual(env["HTTP_PROXY"], "ordinary-tools-proxy")
        self.assertIn("127.0.0.1", env["NO_PROXY"])

    def test_successful_native_generation_settles_and_close_revokes_only_its_key(self):
        item = self.pool.allocate("review", str(self.native))
        self.assertEqual(self.pool.run(item["session"], ["exec", "-"]), 0)
        record = Path(item["home"]).parent / "session.json"
        self.assertEqual(pool.read_json(record)["state"], "idle")
        self.pool.close(item["session"])
        self.assertEqual(pool.read_json(record)["state"], "closed")
        self.assertNotIn("key", pool.read_json(record))
        self.assertEqual(self.admin.requests[-1], ("DELETE", "/api/api-keys/1", None))

    def test_every_launch_turns_off_the_curated_plugin_clone(self):
        """Each private home used to clone the ~88 MB plugin catalog on start.

        WHY. Codex syncs the curated catalog into CODEX_HOME/.tmp/plugins whenever
        plugins are on and no Codex-backend login is present -- always true for a
        pool key. Pool homes install no plugin, so the clone was pure disk growth.
        """
        for profile in ("review", "implementation", "interactive"):
            for bypass in (False, True):
                with self.subTest(profile=profile, bypass=bypass):
                    options = self.pool.provider_options(None, profile, bypass)
                    self.assertIn("features.plugins=false", options)
                    flag = options.index("features.plugins=false")
                    self.assertEqual(options[flag - 1], "-c")

    def test_exec_hands_the_plugin_switch_to_the_native_before_the_prompt(self):
        witness = self.root / "argv.json"
        self.native.write_text(
            '#!%s\nimport json, sys\njson.dump(sys.argv[1:], open(%r, "w"))\n' % (sys.executable, str(witness))
        )
        self.pool.config["native_binaries"][str(self.native)] = hashlib.sha256(self.native.read_bytes()).hexdigest()
        item = self.pool.allocate("review", str(self.native))
        self.assertEqual(self.pool.run(item["session"], ["exec", "-"]), 0)
        argv = json.loads(witness.read_text())
        self.assertEqual(argv[0], "exec")
        self.assertLess(argv.index("features.plugins=false"), argv.index("-"))

    def test_close_discards_the_home_cache_and_keeps_transcripts(self):
        item = self.pool.allocate("review", str(self.native))
        home = Path(item["home"])
        (home / ".tmp/plugins/.git").mkdir(parents=True)
        (home / ".tmp/plugins/.git/HEAD").write_text("ref")
        (home / ".tmp/plugins.sync.lock").write_text("")
        transcript = home / "sessions/2026/09/26/rollout-x.jsonl"
        transcript.parent.mkdir(parents=True)
        transcript.write_text("{}\n")
        self.pool.close(item["session"])
        self.assertFalse((home / ".tmp").exists())
        self.assertEqual(transcript.read_text(), "{}\n")
        self.assertTrue((home.parent / "session.json").exists())
        self.assertEqual(self.pool.inspect(item["session"])["state"], "closed")

    def test_a_symlinked_home_cache_is_never_followed_on_close(self):
        item = self.pool.allocate("review", str(self.native))
        outside = self.root / "not-a-cache"
        outside.mkdir()
        (outside / "keep").write_text("keep")
        (Path(item["home"]) / ".tmp").symlink_to(outside)
        self.pool.close(item["session"])
        self.assertEqual((outside / "keep").read_text(), "keep")
        self.assertEqual(self.pool.inspect(item["session"])["state"], "closed")

    def test_a_failed_cache_delete_never_fails_close(self):
        item = self.pool.allocate("review", str(self.native))
        (Path(item["home"]) / ".tmp/plugins").mkdir(parents=True)
        with patch("pool.shutil.rmtree", side_effect=OSError("busy")):
            self.pool.close(item["session"])
        record = pool.read_json(Path(item["home"]).parent / "session.json")
        self.assertEqual(record["state"], "closed")
        self.assertNotIn("key", record)

    def test_the_cli_serves_every_step_a_consult_sends(self):
        """`consult.run_pooled` drives the published dispatcher through these exact
        argument shapes; a generation that stops accepting one strands consults."""
        mocked = MagicMock()
        mocked.metadata.return_value = {"identity": "i"}
        mocked.allocate.return_value = {"session": "s"}
        mocked.run.return_value = 3
        mocked.inspect.return_value = {"state": "failed"}
        root = ["--root", str(self.root)]
        with patch("pool.Pool", return_value=mocked), patch("sys.stdout", new=io.StringIO()) as out:
            self.assertEqual(pool.main(root + ["metadata", "--profile", "review", "--native", str(self.native)]), 0)
            self.assertEqual(
                pool.main(
                    root
                    + [
                        "new",
                        "--profile",
                        "review",
                        "--native",
                        str(self.native),
                        "--request-id",
                        "consult-x",
                        "--expected-identity",
                        "i",
                    ]
                ),
                0,
            )
            self.assertEqual(
                pool.main(root + ["run", "--expected-identity", "i", "--close-when-settled", "s", "--", "exec", "-"]), 3
            )
        replies = [json.loads(line) for line in out.getvalue().splitlines()]
        self.assertEqual([reply.get("identity") or reply.get("session") for reply in replies], ["i", "s"])
        mocked.allocate.assert_called_once_with("review", str(self.native), "consult-x", "i")
        mocked.run.assert_called_once_with("s", ["exec", "-"], "i")
        mocked.close.assert_called_once_with("s")  # proven failure: closed
        mocked.maintain.assert_called_once_with()

    def test_close_when_settled_keeps_an_unproven_run_and_its_exit_code(self):
        mocked = MagicMock()
        mocked.run.return_value = 7
        mocked.inspect.return_value = {"state": "uncertain"}
        with patch("pool.Pool", return_value=mocked):
            self.assertEqual(
                pool.main(["--root", str(self.root), "run", "--close-when-settled", "s", "--", "exec", "-"]), 7
            )
        mocked.close.assert_not_called()
        mocked.run.side_effect = pool.PoolError("refused before spawn")
        mocked.inspect.return_value = {"state": "idle"}
        with patch("pool.Pool", return_value=mocked):
            self.assertEqual(
                pool.main(["--root", str(self.root), "run", "--close-when-settled", "s", "--", "exec", "-"]), 2
            )
        mocked.close.assert_called_once_with("s")  # a refusal left it idle

    def test_upstream_auth_copy_refused_without_fallback(self):
        item = self.pool.allocate("review", str(self.native))
        (Path(item["home"]) / "auth.json").write_text("{}")
        with patch("pool.subprocess.Popen") as spawn, self.assertRaises(pool.PoolError):
            self.pool.run(item["session"], ["exec", "-"])
        spawn.assert_not_called()

    def test_failed_native_generation_is_not_automatically_replayed(self):
        self.native.write_text("#!/bin/sh\nexit 17\n")
        config = self.pool.config
        config["native_binaries"][str(self.native)] = hashlib.sha256(self.native.read_bytes()).hexdigest()
        item = self.pool.allocate("review", str(self.native))
        self.assertEqual(self.pool.run(item["session"], ["exec", "-"]), 17)
        record = Path(item["home"]).parent / "session.json"
        # Settled, because the supervisor proved every process gone -- but never
        # runnable again: a failed generation is not replayed.
        self.assertEqual(pool.read_json(record)["state"], "failed")
        self.assertEqual(pool.read_json(record)["exit_code"], 17)
        with self.assertRaises(pool.PoolError):
            self.pool.run(item["session"], ["exec", "resume", "thread-id", "-"])
        self.pool.close(item["session"])  # and its key is revocable
        self.assertEqual(pool.read_json(record)["state"], "closed")
        self.assertNotIn("key", pool.read_json(record))

    def test_a_run_without_a_completion_receipt_stays_uncertain(self):
        """Exit code alone never settles a run: the supervisor's 125 and a native's
        125 look the same. Only the supervisor's receipt proves settlement."""
        self.native.write_text("#!/bin/sh\nkill -9 $PPID\nexit 3\n")  # takes the supervisor down
        self.pool.config["native_binaries"][str(self.native)] = hashlib.sha256(self.native.read_bytes()).hexdigest()
        item = self.pool.allocate("review", str(self.native))
        self.pool.run(item["session"], ["exec", "-"])
        record = pool.read_json(Path(item["home"]).parent / "session.json")
        self.assertEqual(record["state"], "uncertain")
        with self.assertRaises(pool.PoolError):
            self.pool.close(item["session"])

    def test_only_a_complete_matching_receipt_settles_a_failed_run(self):
        proof = {"native_exit": 3, "settled": True, "observation_complete": True}
        state = pool.Pool.settled_state
        self.assertEqual(state(proof, 3), "failed")
        self.assertEqual(state(None, 3), "uncertain")
        self.assertEqual(state(dict(proof, settled=False), 3), "uncertain")
        self.assertEqual(state(dict(proof, observation_complete=False), 3), "uncertain")
        self.assertEqual(state(proof, 4), "uncertain")  # disagrees with the dispatcher
        self.assertEqual(state(proof, 3, descendants=True), "uncertain")
        self.assertEqual(state(None, 0), "idle")

    def test_a_malformed_receipt_is_no_receipt(self):
        for data in (b"", b"not json\n", b"[]\n", b'{"native_exit": "3"}\n'):
            read, write = os.pipe()
            os.write(write, data)
            os.close(write)
            with self.subTest(data=data):
                self.assertIsNone(pool.read_receipt(read))

    def test_a_run_records_its_supervisors_kernel_identity(self):
        item = self.pool.allocate("review", str(self.native))
        self.pool.run(item["session"], ["exec", "-"])
        record = pool.read_json(Path(item["home"]).parent / "session.json")
        self.assertTrue(record.get("process_identity"))

    def test_symlinked_job_state_is_rejected(self):
        item = self.pool.allocate("review", str(self.native))
        record = Path(item["home"]).parent / "session.json"
        saved = record.with_suffix(".saved")
        record.rename(saved)
        record.symlink_to(saved)
        with self.assertRaises(pool.PoolError):
            self.pool.run(item["session"], ["exec", "-"])

    def test_dispatcher_sigkill_settles_native_and_its_descendants(self):
        witness = self.root / "native-pids.json"
        self.native.write_text(
            "#!"
            + sys.executable
            + "\n"
            + "import os,subprocess,time,json\n"
            + 'child=subprocess.Popen(["/bin/sleep","60"], start_new_session=True)\n'
            +
            # Written atomically: `exists()` turning true before the bytes land
            # made this test read an empty file and fail for the wrong reason.
            "open("
            + repr(str(witness))
            + '+".tmp","w").write(json.dumps([os.getpid(),child.pid]))\n'
            + "os.replace("
            + repr(str(witness))
            + '+".tmp", '
            + repr(str(witness))
            + ")\n"
            + "time.sleep(60)\n"
        )
        self.pool.config["native_binaries"][str(self.native)] = hashlib.sha256(self.native.read_bytes()).hexdigest()
        pool.write_json(self.root / "dispatcher.json", self.pool.config)
        item = self.pool.allocate("review", str(self.native))
        dispatcher = subprocess.Popen(
            [sys.executable, POOL_ENTRY, "--root", str(self.root), "run", item["session"], "--", "exec", "-"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        try:
            deadline = time.monotonic() + 5
            while not witness.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(witness.exists(), "native did not start")
            native_pids = json.loads(witness.read_text())
            dispatcher.kill()
            dispatcher.wait(timeout=3)
            for pid in native_pids:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    state = subprocess.run(
                        ["ps", "-p", str(pid), "-o", "stat="], capture_output=True, text=True
                    ).stdout.strip()
                    if not state or state.startswith("Z"):
                        break
                    time.sleep(0.05)
                self.assertTrue(not state or state.startswith("Z"), "native descendant survived parent death")
            record = pool.read_json(Path(item["home"]).parent / "session.json")
            # The supervisor knows its session, so parent death is recorded as such.
            self.assertEqual((record["state"], record.get("outcome")), ("uncertain", "supervisor-parent-death"))
            # The durable non-idle record prevents replay despite parent death.
            with self.assertRaises(pool.PoolError):
                self.pool.run(item["session"], ["exec", "-"])
        finally:
            if dispatcher.poll() is None:
                dispatcher.terminate()
                dispatcher.wait(timeout=5)
            assert dispatcher.stderr is not None
            dispatcher.stderr.close()

    def test_one_interrupt_reaches_the_native_exactly_once(self):
        """The dispatcher signalled the supervisor's whole group -- native included
        -- and the supervisor relayed SIGINT to the native again: one Ctrl-C, two
        interrupts, which a TUI or exec treats as "quit now"."""
        witness = self.root / "interrupts.json"
        ready = self.root / "ready"
        self.native.write_text(
            "#!"
            + sys.executable
            + "\n"
            + "import json, signal, time\n"
            + "count = []\n"
            + 'def seen(*_): count.append(1); open(%r, "w").write(json.dumps(len(count)))\n' % str(witness)
            + "signal.signal(signal.SIGINT, seen)\n"
            + 'open(%r, "w").write("1")\n' % str(ready)
            + "deadline = time.time() + 3\n"
            + "while time.time() < deadline: time.sleep(.05)\n"
        )
        self.pool.config["native_binaries"][str(self.native)] = hashlib.sha256(self.native.read_bytes()).hexdigest()
        pool.write_json(self.root / "dispatcher.json", self.pool.config)
        item = self.pool.allocate("review", str(self.native))
        dispatcher = subprocess.Popen(
            [sys.executable, POOL_ENTRY, "--root", str(self.root), "run", item["session"], "--", "exec", "-"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            deadline = time.monotonic() + 5
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(ready.exists(), "native did not start")
            time.sleep(0.2)
            dispatcher.send_signal(signal.SIGINT)
            dispatcher.wait(timeout=10)
            self.assertEqual(json.loads(witness.read_text()), 1)
        finally:
            if dispatcher.poll() is None:
                dispatcher.kill()
                dispatcher.wait(timeout=5)

    def test_successful_native_cannot_leave_an_inherited_detached_child_running(self):
        witness = self.root / "detached-pid"
        self.native.write_text(
            "#!"
            + sys.executable
            + "\n"
            + "import subprocess\n"
            + 'child=subprocess.Popen(["/bin/sleep","60"],start_new_session=True)\n'
            + "open("
            + repr(str(witness))
            + ',"w").write(str(child.pid))\n'
        )
        self.pool.config["native_binaries"][str(self.native)] = hashlib.sha256(self.native.read_bytes()).hexdigest()
        item = self.pool.allocate("review", str(self.native))
        self.assertEqual(self.pool.run(item["session"], ["exec", "-"]), 0)
        state = subprocess.run(
            ["ps", "-p", witness.read_text(), "-o", "stat="], capture_output=True, text=True
        ).stdout.strip()
        self.assertTrue(not state or state.startswith("Z"))

    def test_drain_follows_new_children_of_previously_observed_processes(self):
        with (
            patch("pool_processes.process_table", side_effect=[{100001: (11, 10)}, {100002: (12, 11)}, {}]),
            patch("pool_processes.identity", side_effect=[(11, 10), (12, 11)]),
            patch("pool_processes.os.kill") as kill,
        ):
            self.assertTrue(pool_processes.settle({10}))
        self.assertEqual([item.args[0] for item in kill.call_args_list], [100001, 100002])

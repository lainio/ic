"""Socket-free unit tests; PW_DEMO_LIVE=1 enables the separate live smoke."""

import contextlib
import io
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import pw_demo as demo


def public(byte):
    return "a5010203262001215820" + (byte * 32) + "225820" + ("44" * 32)


KEYS = {name: public(byte) for name, byte in
        zip(demo.NAMES, ("11", "22", "33"))}


def record(run, label, pid=12345):
    return {"pid": pid, "start": 123, "boot": "1" * 8 + "-" + "1" * 27,
            "uid": os.getuid(), "exe": demo.identity_stat(run.path / "bin/tdc"),
            "argv_hash": demo.argv_hash(demo.server_args(run, label))}


def owner_node(run, name, port):
    directory = run.path / "tmp" / ("node-owner-status-" + str(port))
    directory.mkdir(mode=0o700)
    header = directory / "owner.header"
    demo.create_file(header, ("Authorization: Bearer " +
                             ("a" if name == "alice" else "b") * 64 + "\n").encode())
    node = {"public_key_hex": KEYS[name],
            "owner_url": f"http://127.0.0.1:{port}/owner/status",
            "peer_url": f"http://127.0.0.1:{port + 1}/peer/introduction",
            "header_file": str(header)}
    demo.create_file(run.path / "logs" / (name + ".stdout"),
                     startup_output(node).encode())
    return node


def startup_output(node):
    return ("node public key (hex): " + node["public_key_hex"] + "\n"
            "owner status URL: " + node["owner_url"] + "\n"
            "authorization header file: " + node["header_file"] + "\n"
            "peer introduction URL: " + node["peer_url"] + "\n")


class PrivateTest(unittest.TestCase):
    def setUp(self):
        old = os.umask(0o077)
        self.addCleanup(os.umask, old)
        temporary = tempfile.TemporaryDirectory(prefix="pw-demo-unit-")
        self.addCleanup(temporary.cleanup)
        self.parent = Path(temporary.name)
        self.base = demo.Base(self.parent / "private", create=True)
        self.addCleanup(self.base.close)
        self.run = self.base.allocate()

    def binary(self):
        path = self.run.path / "bin/tdc"
        demo.create_file(path, b"fake executable, never launched")
        path.chmod(0o700)
        self.run.manifest["nodes"]["root"] = {"public_key_hex": KEYS["root"]}


class PathTests(PrivateTest):
    def test_private_unique_runs_and_latest(self):
        other = self.base.allocate()
        self.assertNotEqual(other.path, self.run.path)
        self.assertEqual(self.base.select().path, other.path)
        self.assertEqual(self.run.path.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.run.path / "manifest.json").stat().st_mode & 0o777, 0o600)

    def test_unknown_existing_base_and_arbitrary_paths_refused(self):
        existing = self.parent / "old-alice"
        existing.mkdir(mode=0o700)
        sentinel = existing / "vault"
        sentinel.write_text("untouched")
        with self.assertRaises((demo.DemoError, FileNotFoundError)):
            demo.Base(existing, create=True)
        for value in ("..", "/", str(demo.REPO), "run-" + "0" * 32):
            with self.subTest(value=value), self.assertRaises((demo.DemoError, OSError)):
                self.base.select(value)
        self.assertEqual(sentinel.read_text(), "untouched")

    def test_base_ancestors_repo_home_and_storage_refused(self):
        for path in (demo.REPO, demo.REPO.parent, demo.REPO / "demo",
                     Path.home(), Path("/"), self.parent / "storage"):
            with self.subTest(path=path), self.assertRaises(demo.DemoError):
                demo.Base(path, create=True)

    def test_symlink_ancestor_and_run_refused(self):
        link = self.parent / "alias"
        link.symlink_to(self.base.path, target_is_directory=True)
        with self.assertRaises(demo.DemoError):
            demo.Base(link / "new", create=True)
        fake_id = "run-" + "0" * 32
        (self.base.path / fake_id).symlink_to(self.run.path, target_is_directory=True)
        with self.assertRaises(demo.DemoError):
            self.base.select(fake_id)

    def test_marker_manifest_permissions_and_confirmation(self):
        identifier = self.run.path.name
        with self.assertRaises(demo.DemoError):
            demo.destroy(self.run, "run-" + "0" * 32)
        path = self.run.path / "run.json"
        original = path.read_bytes()
        for mutation in (b"{}", original.replace(identifier.encode(), b"other")):
            path.write_bytes(mutation)
            with self.assertRaises(demo.DemoError):
                demo.destroy(self.run, identifier)
        path.write_bytes(original)
        manifest = self.run.path / "manifest.json"
        manifest.chmod(0o644)
        with self.assertRaises(demo.DemoError):
            self.base.select(identifier)
        manifest.chmod(0o600)
        self.run.manifest["surprise"] = True
        self.run.save()
        with self.assertRaises(demo.DemoError):
            demo.destroy(self.run, identifier)
        self.assertTrue(self.run.path.exists())

    def test_owner_and_hardlink_checks(self):
        info = (self.run.path / "manifest.json").stat()
        wrong = mock.Mock(st_mode=info.st_mode, st_uid=os.getuid() + 1, st_nlink=1)
        with self.assertRaises(demo.DemoError):
            demo.private_stat(wrong)
        os.link(self.run.path / "manifest.json", self.parent / "linked")
        with self.assertRaises(demo.DemoError):
            self.base.select(self.run.path.name)

    def test_destroy_rejects_nested_symlink_and_unknown_top_level(self):
        external = self.parent / "old-bob-vault"
        external.write_text("old data")
        link = self.run.path / "logs/link"
        link.symlink_to(external)
        with self.assertRaises(demo.DemoError):
            demo.destroy(self.run, self.run.path.name)
        self.assertEqual(external.read_text(), "old data")
        self.assertTrue((self.run.path / "run.json").exists())
        link.unlink()
        (self.run.path / "unexpected").write_text("do not delete")
        with self.assertRaises(demo.DemoError):
            demo.destroy(self.run, self.run.path.name)
        self.assertTrue((self.run.path / "unexpected").exists())

    def test_destroy_only_selected_run(self):
        other = self.base.allocate()
        identifier = self.run.path.name
        demo.destroy(self.run, identifier)
        self.assertFalse(self.run.path.exists())
        self.assertTrue(other.path.exists())
        self.assertEqual(self.base.select().path, other.path)

    def test_lock_refuses_concurrent_lifecycle(self):
        with self.assertRaises(BlockingIOError):
            demo.Base(self.base.path)


class ParsingTests(unittest.TestCase):
    def test_cose_exact_full_bytes_and_short_coordinates(self):
        self.assertEqual(demo.public_output("node public key (hex): " + KEYS["alice"]),
                         KEYS["alice"])
        short = "a50102032620012141ff2241ee"
        self.assertEqual(demo.cose_hex(short), short)
        invalid = (KEYS["alice"].upper(), KEYS["alice"][:-2], KEYS["alice"] + "00",
                   KEYS["alice"].encode().hex(), "a5010203262001215801ff2241ee",
                   "ff", "", "ab" * 129)
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(demo.DemoError):
                demo.cose_hex(value)
        with self.assertRaises(demo.DemoError):
            demo.public_output("node public key (hex): " + KEYS["alice"] +
                               "\nnode public key (hex): " + KEYS["alice"])

    def test_local_exact_urls_only(self):
        self.assertEqual(demo.loopback_url("http://127.0.0.1:123/owner/status",
                                          "/owner/status"), 123)
        for value in ("http://localhost:1/owner/status", "https://127.0.0.1:1/owner/status",
                      "http://127.0.0.1/owner/status", "http://127.0.0.1:0/owner/status",
                      "http://127.0.0.1:65536/owner/status", "http://127.0.0.1:01/owner/status",
                      "http://127.0.0.1:1/owner/status?", "http://user@127.0.0.1:1/owner/status",
                      "http://127.0.0.1:1/peer/ad", "http://192.0.2.1:1/owner/status",
                      "http://127.0.0.1:1/owner/status#", "http://127.0.0.1:1/%6fwner/status"):
            with self.subTest(value=value), self.assertRaises(demo.DemoError):
                demo.loopback_url(value, "/owner/status")

    def test_strict_bounded_json(self):
        for value in (b'{"choice":1,"choice":2}', b'{"x":NaN}', b'{}{}',
                      b'\xff', b' ' * (demo.LIMIT + 1)):
            with self.subTest(value=value[:30]), self.assertRaises(demo.DemoError):
                demo.decode_json(value)
        with self.assertRaises(demo.DemoError):
            demo.same({"authorized": 1}, {"authorized": True})


class ProcessTests(PrivateTest):
    def setUp(self):
        super().setUp()
        self.binary()
        self.record = record(self.run, "alice")
        self.run.manifest["processes"]["alice"] = self.record
        self.run.save()

    def test_pid_reuse_never_signaled_or_destroyed(self):
        reused = dict(self.record, start=456)
        with mock.patch.object(demo.os, "pidfd_open", return_value=90), \
                mock.patch.object(demo.os, "close"), \
                mock.patch.object(demo, "process_identity", return_value=reused), \
                mock.patch.object(demo.signal, "pidfd_send_signal") as send:
            self.assertEqual(demo.stop_process(self.record), "identity-mismatch")
            with self.assertRaises(demo.DemoError):
                demo.destroy(self.run, self.run.path.name)
            send.assert_not_called()
        self.assertTrue(self.run.path.exists())

    def test_pidfd_open_precedes_identity_check_and_wait_is_bounded(self):
        events = []
        poller = mock.Mock()
        poller.poll.return_value = []
        with mock.patch.object(demo.os, "pidfd_open", side_effect=lambda pid:
                               events.append("pidfd") or 90), \
                mock.patch.object(demo.os, "close"), \
                mock.patch.object(demo, "process_identity", side_effect=lambda pid:
                                  events.append("identity") or self.record), \
                mock.patch.object(demo.signal, "pidfd_send_signal") as send, \
                mock.patch.object(demo.select, "poll", return_value=poller):
            self.assertEqual(demo.stop_process(self.record, timeout=3), "shutdown-timeout")
            self.assertEqual(events, ["pidfd", "identity"])
            send.assert_called_once_with(90, signal.SIGINT)
            poller.poll.assert_called_once_with(3000)
            send.reset_mock()
            self.assertEqual(demo.stop_process(self.record, timeout=3, force=True),
                             "shutdown-timeout")
            self.assertEqual([call.args[1] for call in send.call_args_list],
                             [signal.SIGINT, signal.SIGTERM, signal.SIGKILL])

    def test_down_is_idempotent_and_retains_files(self):
        with mock.patch.object(demo.os, "pidfd_open", side_effect=ProcessLookupError):
            for _ in range(2):
                self.assertEqual(demo.down(self.run), {"alice": "stopped"})
        self.assertEqual(self.base.select(self.run.path.name).manifest["state"], "down")
        self.assertTrue((self.run.path / "bin/tdc").exists())

    def test_tampered_process_manifest_refused_before_signal(self):
        self.run.manifest["processes"]["alice"]["argv_hash"] = "0" * 64
        self.run.save()
        with mock.patch.object(demo.signal, "pidfd_send_signal") as send:
            with self.assertRaises(demo.DemoError):
                demo.destroy(self.run, self.run.path.name)
            send.assert_not_called()

    def test_premature_exit_and_startup_deadline(self):
        harness = demo.Harness(self.run)
        output = self.run.path / "logs/fake.stdout"
        demo.create_file(output, b"")
        child = mock.Mock()
        child.poll.return_value = 1
        with mock.patch.object(harness, "launch", return_value=(child, output)):
            with self.assertRaisesRegex(demo.DemoError, "server-exited"):
                harness.start("alice", ("ready",))
            child.poll.return_value = None
            with mock.patch.object(demo.time, "monotonic", side_effect=[0, 0, 21]), \
                    mock.patch.object(demo.time, "sleep"):
                with self.assertRaisesRegex(demo.DemoError, "startup-timeout"):
                    harness.start("alice", ("ready",))

    def test_interrupted_up_cleans_children_and_preserves_partial_evidence(self):
        fake = mock.Mock()
        fake.setup.side_effect = KeyboardInterrupt
        fake.cleanup.return_value = {}
        with mock.patch.object(demo, "Harness", return_value=fake):
            with self.assertRaises(KeyboardInterrupt):
                demo.up(self.run)
        fake.cleanup.assert_called_once()
        self.assertEqual(self.base.select(self.run.path.name).manifest["state"], "failed")
        self.assertTrue(self.run.path.exists())

    def test_partial_startup_cleanup_attempts_all_owned_children(self):
        harness = demo.Harness(self.run)
        server = mock.Mock(pid=self.record["pid"])
        command = mock.Mock(pid=12346)
        server.poll.return_value = command.poll.return_value = None
        harness.children = [server, command]
        transient = dict(self.record, pid=12346)
        harness.child_identities = {server.pid: self.record, command.pid: transient}
        with mock.patch.object(demo, "stop_process", return_value="stopped") as stop:
            self.assertEqual(harness.cleanup(),
                             {"alice": "stopped", "command-12346": "stopped"})
            self.assertEqual(stop.call_args_list, [mock.call(self.record, force=True),
                                                   mock.call(transient, force=True)])
        self.assertTrue((self.run.path / "manifest.json").exists())

    def test_launch_is_argv_only_private_and_ignores_environment_configuration(self):
        with mock.patch.dict(os.environ, {"TDC_CONFIG": "/unrelated/config",
                                         "HTTPS_PROXY": "http://remote.invalid"}):
            harness = demo.Harness(self.run)
        child = mock.Mock(pid=self.record["pid"])
        args = demo.server_args(self.run, "alice")
        with mock.patch.object(demo.subprocess, "Popen", return_value=child) as popen, \
                mock.patch.object(demo, "process_identity", return_value=self.record):
            harness.launch("alice", args, server=True)
        self.assertEqual(popen.call_args.args, (args,))
        kwargs = popen.call_args.kwargs
        self.assertFalse(kwargs.get("shell", False))
        self.assertTrue(kwargs["start_new_session"])
        self.assertNotIn("TDC_CONFIG", kwargs["env"])
        self.assertNotIn("HTTPS_PROXY", kwargs["env"])
        self.assertEqual(kwargs["env"]["GOPROXY"], "off")
        self.assertEqual((self.run.path / "logs/alice.stderr").stat().st_mode & 0o777,
                         0o600)
        self.assertNotEqual(kwargs["stdout"].name, kwargs["stderr"].name)

    def test_output_failure_after_setup_stops_servers(self):
        real_print = print

        def fail_ready(*args, **kwargs):
            if args and args[0] == "READY_FOR_INVITATION":
                raise BrokenPipeError
            real_print(*args, **kwargs)

        def setup(run):
            demo.create_file(run.path / "bin/tdc", b"fake")
            (run.path / "bin/tdc").chmod(0o700)
            run.manifest["nodes"]["root"] = {"public_key_hex": KEYS["root"]}
            run.manifest["processes"]["alice"] = record(run, "alice")
            run.manifest["state"] = "ready"

        previous = signal.getsignal(signal.SIGTERM)
        self.addCleanup(signal.signal, signal.SIGTERM, previous)
        with mock.patch.object(demo, "up", side_effect=setup), \
                mock.patch("builtins.print", side_effect=fail_ready), \
                mock.patch.object(demo, "stop_process", return_value="stopped") as stop, \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(demo.main(["up", "--base-dir", str(self.parent / "output-test")]), 1)
            stop.assert_called_once()
            self.assertTrue(stop.call_args.kwargs["force"])


class HTTPTests(PrivateTest):
    def setUp(self):
        super().setUp()
        self.binary()
        for name, port in (("alice", 10001), ("bob", 10003)):
            self.run.manifest["nodes"][name] = owner_node(self.run, name, port)
            self.run.manifest["processes"][name] = record(self.run, name, pid=port)
        self.run.save()

    def test_owner_token_stays_on_corresponding_origin_no_proxy_or_redirect(self):
        connection = mock.Mock()
        response = connection.getresponse.return_value
        response.status = 200
        response.getheader.side_effect = lambda key: (
            "application/json" if key == "Content-Type" else None)
        response.read.return_value = b'{"choice":"completed"}'
        with mock.patch.dict(os.environ, {"HTTP_PROXY": "http://remote.invalid:123"}), \
                mock.patch.object(demo, "process_state", return_value="running"), \
                mock.patch.object(demo.http.client, "HTTPConnection",
                                  return_value=connection) as constructor:
            for name, port, token in (("alice", 10001, "a"), ("bob", 10003, "b")):
                owner = demo.Owner(self.run, name)
                owner.json("GET", "/owner/status")
                self.assertEqual(constructor.call_args.args, ("127.0.0.1", port))
                self.assertEqual(connection.request.call_args.kwargs["headers"]["Authorization"],
                                 "Bearer " + token * 64)
                for route in ("/peer/ad", "/owner/pw/invitations/issue",
                              "/owner/pw/invitations/redeem", "/owner/pw/first-use",
                              "/owner/policy/deny", "/owner/pw/holding/delete",
                              "http://127.0.0.1:10003/owner/status"):
                    with self.assertRaises(demo.DemoError):
                        owner.json("POST", route, {})
            response.status = 302
            before = connection.request.call_count
            with self.assertRaises(demo.DemoError):
                owner.json("GET", "/owner/status")
            self.assertEqual(connection.request.call_count, before + 1)

    def test_header_files_and_readiness_fail_closed(self):
        node = self.run.manifest["nodes"]["alice"]
        header = Path(node["header_file"])
        header.write_text("Authorization: Bearer secret\nInjected: true\n")
        with self.assertRaises(demo.DemoError):
            demo.Owner(self.run, "alice")
        node["header_file"] = str(self.parent / "owner.header")
        with self.assertRaises((demo.DemoError, ValueError)):
            demo.Owner(self.run, "alice")
        fake = mock.Mock()
        fake.json.return_value = {"choice": "pending"}
        with mock.patch.object(demo, "Owner", return_value=fake):
            with self.assertRaises(demo.DemoError):
                demo.Harness(self.run).ready("alice")

    def test_manifest_cannot_swap_owner_header_or_url(self):
        nodes = self.run.manifest["nodes"]
        for field in ("header_file", "owner_url", "public_key_hex", "peer_url"):
            original = nodes["alice"][field]
            nodes["alice"][field] = nodes["bob"][field]
            with self.subTest(field=field), self.assertRaises(demo.DemoError):
                demo.Owner(self.run, "alice")
            nodes["alice"][field] = original

    def test_http_size_shape_and_operation_deadline(self):
        connection = mock.Mock()
        response = connection.getresponse.return_value
        response.status = 200
        response.getheader.side_effect = lambda key: (
            "application/json" if key == "Content-Type" else None)
        timer = mock.Mock()
        with mock.patch.object(demo, "process_state", return_value="running"), \
                mock.patch.object(demo.http.client, "HTTPConnection", return_value=connection), \
                mock.patch.object(demo.time, "monotonic", return_value=100), \
                mock.patch.object(demo.threading, "Timer", return_value=timer) as create_timer:
            owner = demo.Owner(self.run, "alice")
            for body in (b"x" * (demo.LIMIT + 1), b"[]", b'{"choice":1,"choice":2}'):
                response.read.return_value = body
                with self.assertRaises(demo.DemoError):
                    owner.json("GET", "/owner/status", timeout=2)
                self.assertLessEqual(create_timer.call_args.args[0], 2)
                response.read.assert_called_with(demo.LIMIT + 1)
            create_timer.call_args.args[1]()
            connection.sock.shutdown.assert_called_with(socket.SHUT_RDWR)
            self.assertEqual(timer.cancel.call_count, 3)
            self.assertEqual(timer.join.call_count, 3)
            self.assertEqual(connection.close.call_count, 3)

    def test_console_has_no_bearer_and_receipts_are_historical(self):
        output = io.StringIO()
        with mock.patch.object(demo, "process_state", return_value="running"), \
                contextlib.redirect_stdout(output):
            demo.status(self.run)
        text = output.getvalue()
        self.assertIn("historical", text)
        self.assertIn(KEYS["alice"], text)
        self.assertIn("Alice diagnostics:", text)
        self.assertNotIn("Bearer", text)
        self.assertNotIn("a" * 64, text)


class FakeOwner:
    def __init__(self, harness, name):
        self.harness = harness
        self.name = name

    def request(self, method, path, body=None, timeout=8):
        result = self.json(method, path, body, timeout)
        return result, json.dumps(result).encode()

    def json(self, method, path, body=None, timeout=8):
        h, name = self.harness, self.name
        h.calls.append((name, method, path, body))
        peer = "bob" if name == "alice" else "alice"
        if path == "/owner/status":
            result = {"choice": "completed"}
        elif path == "/owner/introduction":
            result = {"version": 1, "proposal": "YQ==", "acceptance": "Yg=="}
        elif path == "/owner/introductions":
            if json.loads(body) != {"version": 1, "proposal": "YQ==", "acceptance": "Yg=="}:
                raise AssertionError("must save exact self introduction")
            result = {"subject_public_key_hex": KEYS[name], "is_self": True, "created": True}
        elif path == "/owner/introductions/fetch":
            if body != {"peer_url": h.run.manifest["nodes"][peer]["peer_url"]}:
                raise AssertionError("wrong peer URL")
            result = {"subject_public_key_hex": KEYS[peer], "is_self": False, "created": True}
        elif path == "/owner/introductions/verify":
            result = {"newly_known": 2, "known_subjects": [KEYS["alice"], KEYS["bob"]]}
        elif path == "/owner/device/bootstrap":
            result = {"authorized": True, "usable": True}
        elif path == "/owner/ads/publish":
            result = {"published": True, "slot": 1, "epoch": 0,
                      "expires_unix_nano": demo.time.time_ns() + demo.TTL_NS,
                      "peer_introduction_url": h.run.manifest["nodes"]["bob"]["peer_url"]}
        elif path == "/owner/ads/fetch":
            if body != {"peer_url": "http://127.0.0.1:10004/peer/ad"}:
                raise AssertionError("must fetch peer ad URL")
            result = {"subject_public_key_hex": KEYS["bob"],
                      "introduction_created": False, "ad_changed": True}
        elif path == "/owner/ads/verify":
            if body != {"subject_public_key_hex": KEYS["bob"]}:
                raise AssertionError("must verify Bob's actual subject")
            result = {"subject_public_key_hex": KEYS["bob"], "verified": True, "changed": True}
        else:
            raise AssertionError("unexpected route")
        if h.mutate:
            return h.mutate(name, path, result)
        return result


class FakeHarness(demo.Harness):
    def __init__(self, run, mutate=None):
        super().__init__(run)
        self.calls = []
        self.mutate = mutate

    def command(self, label, args, timeout=30):
        self.calls.append((label, args))
        self.run.stage(label)
        if label == "build":
            demo.create_file(self.run.path / "bin/tdc", b"fake")
            return ""
        name = label.split("-")[0]
        if label.endswith("-accept"):
            return ("choice and acceptance saved: true\nlocal acceptance verifies: true\n"
                    "issuer returned HTTP 204: true\nnode public key (hex): legacy-text\n")
        result = "node public key (hex): " + KEYS[name] + "\n"
        if label.endswith("-init-state"):
            result += "local state initialized: true\n"
        return result

    def start(self, label, prefixes):
        self.calls.append((label, demo.server_args(self.run, label)))
        self.run.stage(label)
        self.run.manifest["processes"][label] = record(self.run, label)
        if label.startswith("root-"):
            return ("root public key (hex): " + KEYS["root"] + "\n"
                    "HTTP endpoint: http://127.0.0.1:10000\n")
        node = owner_node(self.run, label, 10001 if label == "alice" else 10003)
        return startup_output(node)

    def stop_root(self, label):
        self.calls.append(("stop", label))

    def ready(self, name):
        self.owners[name] = FakeOwner(self, name)
        self.run.receipt(self.owners[name].json("GET", "/owner/status"))


class SequenceTests(PrivateTest):
    def execute(self, mutate=None):
        harness = FakeHarness(self.run, mutate)
        with mock.patch.object(demo, "process_state", return_value="running"), \
                mock.patch.object(demo, "Harness", return_value=harness), \
                mock.patch.object(demo, "stop_process", return_value="stopped"), \
                mock.patch.object(demo.time, "time_ns", return_value=1_800_000_000_000_000_000):
            demo.up(self.run)
        return harness

    def test_config_pair_exact_independent_private_and_down_retention(self):
        self.execute()
        directory = self.run.path / "config"
        self.assertEqual(directory.stat().st_mode & 0o7777, 0o700)
        self.assertEqual({p.name for p in directory.iterdir()},
                         {"alice.json", "bob.json"})
        before = {}
        for name, port in (("alice", 10001), ("bob", 10003)):
            path = directory / (name + ".json")
            before[name] = path.read_bytes()
            self.assertEqual(path.stat().st_mode & 0o7777, 0o600)
            self.assertEqual(path.stat().st_nlink, 1)
            value = demo.decode_json(before[name])
            self.assertEqual(value, {
                "version": 1, "role": name,
                "node_public_key_hex": KEYS[name],
                "owner_status_url": f"http://127.0.0.1:{port}/owner/status",
                "owner_header_file": str(self.run.path / "tmp" /
                                         f"node-owner-status-{port}/owner.header"),
            })
            self.assertTrue(Path(value["owner_header_file"]).is_absolute())
            self.assertTrue(Path(value["owner_header_file"]).is_relative_to(self.run.path))
            self.assertNotIn(b"Bearer", before[name])

        with mock.patch.object(demo, "stop_process", return_value="stopped"):
            demo.down(self.run)
        for name in demo.CONFIG_NAMES:
            header = Path(self.run.manifest["nodes"][name]["header_file"])
            header.unlink()  # A stopped service may remove its credential.
            self.assertEqual((directory / (name + ".json")).read_bytes(), before[name])
        self.assertTrue(demo.validate_configs(self.base.select(self.run.path.name)))

        other = self.base.allocate()
        with mock.patch.object(demo, "stop_process", return_value="stopped"):
            demo.destroy(self.run, self.run.path.name)
        self.assertFalse(directory.exists())
        self.assertTrue(other.path.exists())

    def test_status_prints_absolute_config_paths_without_mutation_or_http(self):
        self.execute()
        files = {p: p.read_bytes() for p in self.run.path.rglob("*") if p.is_file()}
        output = io.StringIO()
        with mock.patch.object(demo, "Owner", side_effect=AssertionError("no HTTP")), \
                mock.patch.object(demo, "process_state", return_value="stopped"), \
                contextlib.redirect_stdout(output):
            demo.status(self.base.select(self.run.path.name))
        for name in demo.CONFIG_NAMES:
            self.assertIn(str(self.run.path / "config" / (name + ".json")),
                          output.getvalue())
        self.assertIn("Alice = requester; Bob = invitation issuer/acceptor.",
                      output.getvalue())
        self.assertIn("Launch snapshots only", output.getvalue())
        self.assertNotIn("Bearer", output.getvalue())
        self.assertEqual(files, {p: p.read_bytes() for p in files})

    def test_config_publication_requires_recorded_ready_and_refuses_rewrite(self):
        with self.assertRaises(demo.DemoError):
            demo.write_configs(self.run)
        self.execute()
        before = (self.run.path / "config/alice.json").read_bytes()
        with self.assertRaisesRegex(demo.DemoError, "config-already-exists"):
            demo.write_configs(self.run)
        self.assertEqual((self.run.path / "config/alice.json").read_bytes(), before)
        self.run = self.base.allocate()
        self.execute()
        self.assertNotEqual(self.run.path / "config/alice.json",
                            next(p for p in self.base.path.glob("*/config/alice.json")
                                 if p.read_bytes() == before))

    def test_config_write_failure_or_interrupt_leaves_no_pair_or_staging(self):
        for failure in (OSError("write failed"), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__):
                self.run = self.base.allocate()
                real_write = demo.write_json

                def write(path, value, new=False):
                    if path.name == "bob.json":
                        self.assertFalse((self.run.path / "config").exists())
                        self.assertTrue((path.parent / "alice.json").exists())
                        demo.create_file(path, b"partial")
                        raise failure
                    return real_write(path, value, new=new)

                with mock.patch.object(demo, "write_json", side_effect=write):
                    with self.assertRaises(type(failure)):
                        self.execute()
                self.assertEqual(self.base.select().manifest["state"], "failed")
                self.assertFalse((self.run.path / "config").exists())
                self.assertEqual(list((self.run.path / "tmp").glob(".config-*")), [])

    def test_interrupt_after_config_publication_removes_pair(self):
        publish = demo.write_configs

        def interrupt(run):
            publish(run)
            raise KeyboardInterrupt

        with mock.patch.object(demo, "write_configs", side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.execute()
        self.assertFalse((self.run.path / "config").exists())
        self.assertEqual(self.base.select().manifest["state"], "failed")

    def test_config_generation_rechecks_independent_recorded_serve_identity(self):
        self.execute()
        demo.discard_configs(self.run)
        self.run.manifest["nodes"]["bob"]["public_key_hex"] = KEYS["alice"]
        self.run.save()
        with self.assertRaises(demo.DemoError):
            demo.write_configs(self.run)
        self.assertFalse((self.run.path / "config").exists())

    def test_failed_up_does_not_remove_preexisting_config(self):
        directory = self.run.path / "config"
        directory.mkdir(mode=0o700)
        demo.create_file(directory / "alice.json", b"unrelated")
        with self.assertRaisesRegex(demo.DemoError, "config-already-exists"):
            self.execute()
        self.assertEqual((directory / "alice.json").read_bytes(), b"unrelated")

    def test_destroy_refuses_unsafe_or_unexpected_config(self):
        for change in ("extra", "missing", "contents", "duplicate", "swapped",
                       "directory", "fifo", "symlink", "hardlink", "parent-link",
                       "file-mode", "execute-mode", "directory-mode"):
            with self.subTest(change=change):
                self.run = self.base.allocate()
                self.execute()
                directory = self.run.path / "config"
                path = directory / "alice.json"
                if change == "extra":
                    demo.create_file(directory / "carol.json", b"{}")
                elif change == "missing":
                    path.unlink()
                elif change == "contents":
                    path.write_text('{"version": 1}')
                elif change == "duplicate":
                    path.write_bytes(path.read_bytes().replace(b'{', b'{"version":1,', 1))
                elif change == "swapped":
                    path.write_bytes((directory / "bob.json").read_bytes())
                elif change == "directory":
                    path.unlink()
                    path.mkdir(mode=0o700)
                elif change == "fifo":
                    path.unlink()
                    os.mkfifo(path, 0o600)
                elif change == "symlink":
                    path.unlink()
                    path.symlink_to(directory / "bob.json")
                elif change == "hardlink":
                    os.link(path, self.parent / ("link-" + self.run.path.name))
                elif change == "parent-link":
                    moved = self.run.path / "tmp/config"
                    directory.rename(moved)
                    directory.symlink_to(moved, target_is_directory=True)
                elif change == "file-mode":
                    path.chmod(0o644)
                elif change == "execute-mode":
                    path.chmod(0o700)
                else:
                    directory.chmod(0o755)
                with mock.patch.object(demo, "stop_process", return_value="stopped"):
                    with self.assertRaises((demo.DemoError, OSError)):
                        demo.destroy(self.run, self.run.path.name)
                self.assertTrue((self.run.path / "run.json").exists())

    def test_console_failure_after_publication_removes_configs(self):
        real_print = print

        def fail_ready(*args, **kwargs):
            if args and args[0] == "READY_FOR_INVITATION":
                raise BrokenPipeError
            real_print(*args, **kwargs)

        path = self.parent / "console-failure"
        previous = signal.getsignal(signal.SIGTERM)
        self.addCleanup(signal.signal, signal.SIGTERM, previous)
        with mock.patch.object(demo, "Harness", FakeHarness), \
                mock.patch.object(demo, "process_state", return_value="running"), \
                mock.patch.object(demo, "stop_process", return_value="stopped"), \
                mock.patch("builtins.print", side_effect=fail_ready), \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(demo.main(["up", "--base-dir", str(path)]), 1)
        base = demo.Base(path)
        self.addCleanup(base.close)
        run = base.select()
        self.assertEqual(run.manifest["state"], "failed")
        self.assertFalse((run.path / "config").exists())

    def test_exact_command_and_http_order_no_invitation_or_first_use(self):
        h = self.execute()
        commands = [c[0] for c in h.calls if len(c) == 2]
        self.assertEqual(commands, [
            "build", "root-init", "root-info", "alice-init", "alice-init-state",
            "alice-info", "bob-init", "bob-init-state", "bob-info", "root-alice",
            "alice-accept", "alice-accepted-info", "stop", "root-bob", "bob-accept",
            "bob-accepted-info", "stop", "alice", "bob"])
        self.assertEqual(h.calls[0][1], ["go", "build", "-mod=readonly", "-o",
                                       str(self.run.path / "bin/tdc"), "./cmd/tdc"])
        commands = dict(c for c in h.calls if len(c) == 2)
        self.assertEqual(commands["root-alice"], commands["root-bob"])
        for name in ("alice", "bob"):
            self.assertEqual(commands[name][1:4], ["--v=1", "node", "serve"])
            for suffix in ("-init-state", "-accept", ""):
                args = commands[name + suffix]
                self.assertEqual(args[args.index("--root") + 1], KEYS["root"])
            self.assertNotIn("--owner-listen", commands[name + "-accept"])
        http = [(c[0], c[1], c[2]) for c in h.calls if len(c) == 4]
        self.assertEqual(http, [
            ("alice", "GET", "/owner/status"), ("bob", "GET", "/owner/status"),
            ("alice", "GET", "/owner/introduction"),
            ("alice", "POST", "/owner/introductions"),
            ("bob", "GET", "/owner/introduction"), ("bob", "POST", "/owner/introductions"),
            ("alice", "POST", "/owner/introductions/fetch"),
            ("bob", "POST", "/owner/introductions/fetch"),
            ("alice", "POST", "/owner/introductions/verify"),
            ("bob", "POST", "/owner/introductions/verify"),
            ("alice", "POST", "/owner/device/bootstrap"),
            ("bob", "POST", "/owner/device/bootstrap"),
            ("bob", "POST", "/owner/ads/publish"),
            ("alice", "POST", "/owner/ads/fetch"),
            ("alice", "POST", "/owner/ads/verify")])
        self.assertEqual(self.base.select(self.run.path.name).manifest["state"], "ready")
        self.assertEqual([r["stage"] for r in self.run.manifest["receipts"]], demo.RECEIPT_ORDER)
        self.assertFalse((self.run.path / "root/state").exists())

    def test_bad_known_stops_before_bootstrap(self):
        def mutate(name, path, result):
            if path == "/owner/introductions/verify":
                result["known_subjects"] = [KEYS["alice"]]
            return result
        with self.assertRaises(demo.DemoError):
            self.execute(mutate)
        self.assertEqual(self.run.manifest["stage"], "alice-known")
        self.assertFalse(any(r["stage"].endswith("-device")
                             for r in self.run.manifest["receipts"]))
        self.assertFalse((self.run.path / "config").exists())

    def test_device_failure_is_mandatory(self):
        def mutate(name, path, result):
            if name == "bob" and path == "/owner/device/bootstrap":
                result["usable"] = False
            return result
        with self.assertRaises(demo.DemoError):
            self.execute(mutate)
        self.assertEqual(self.run.manifest["stage"], "bob-device")
        self.assertFalse(any(r["stage"] == "bob-publish"
                             for r in self.run.manifest["receipts"]))
        self.assertFalse((self.run.path / "config").exists())

    def test_serve_formatter_regression_and_remote_url_stop_setup(self):
        for field, replacement in (("public_key_hex", KEYS["alice"].encode().hex()),
                                   ("owner_url", "http://192.0.2.1:123/owner/status")):
            self.run = self.base.allocate()
            harness = FakeHarness(self.run)
            original = harness.start
            def start(label, prefixes):
                text = original(label, prefixes)
                if label == "alice":
                    key = ("node public key (hex): " if field == "public_key_hex"
                           else "owner status URL: ")
                    before = demo.output_field(text, key)
                    return text.replace(before, replacement)
                return text
            with self.subTest(field=field), mock.patch.object(harness, "start", side_effect=start):
                with self.assertRaises(demo.DemoError):
                    harness.setup()
            # A malformed node stanza must never make the partial manifest
            # unreadable and thereby prevent later down/destroy.
            self.base.select(self.run.path.name)

    def test_bad_ad_binding_expiry_and_verification_never_ready(self):
        for path, field, value in (
                ("/owner/ads/publish", "peer_introduction_url",
                 "http://127.0.0.1:123/peer/introduction"),
                ("/owner/ads/publish", "expires_unix_nano", 1),
                ("/owner/ads/publish", "expires_unix_nano", 2 ** 63 - 1),
                ("/owner/ads/verify", "subject_public_key_hex", KEYS["alice"]),
                ("/owner/ads/verify", "verified", False),
                ("/owner/ads/verify", "verified", 1)):
            with self.subTest(field=field, value=value):
                self.run = self.base.allocate()
                def mutate(name, route, result):
                    if route == path:
                        result[field] = value
                    return result
                with self.assertRaises(demo.DemoError):
                    self.execute(mutate)
                self.assertNotEqual(self.run.manifest["state"], "ready")
                self.assertFalse((self.run.path / "config").exists())


@unittest.skipUnless(os.environ.get("PW_DEMO_LIVE") == "1",
                     "NOT RUN: opt in with PW_DEMO_LIVE=1")
class LiveSmoke(unittest.TestCase):
    def test_current_checkout_up_status_receipts_down(self):
        # This permission probe does not relax the sandbox. Failure is a skip,
        # never evidence that the actual CLI demo passed.
        try:
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
        except PermissionError:
            self.skipTest("NOT RUN / BLOCKED BY SANDBOX: loopback binding denied")
        parent = Path(tempfile.mkdtemp(prefix="ic-pw-demo-smoke-"))
        base_path = parent / "runs"
        command = [sys.executable, str(demo.REPO / "scripts/pw_demo.py")]
        print("\nLive smoke retained evidence parent:", parent, flush=True)
        try:
            up = subprocess.run([*command, "up", "--base-dir", str(base_path)],
                                capture_output=True, timeout=240)
            # Keep sanitized console output privately as well; no raw errors in
            # test assertion output. Actual node diagnostics remain per node.
            demo.create_file(parent / "up.stdout", up.stdout)
            demo.create_file(parent / "up.stderr", up.stderr)
            self.assertEqual(up.returncode, 0, "up failed; inspect private evidence")
            self.assertIn(b"READY_FOR_INVITATION", up.stdout)
            base = demo.Base(base_path)
            try:
                run = base.select()
                self.assertEqual(run.manifest["state"], "ready")
                self.assertTrue(demo.validate_configs(run))
                for name in ("alice", "bob"):
                    self.assertIn(str(run.path / "config" / (name + ".json")).encode(),
                                  up.stdout)
                    self.assertEqual(demo.Owner(run, name).json("GET", "/owner/status"),
                                     {"choice": "completed"})
                receipts = {r["stage"]: r["result"] for r in run.manifest["receipts"]}
                self.assertEqual(list(receipts), demo.RECEIPT_ORDER)
                for name in ("alice", "bob"):
                    self.assertEqual(set(receipts[name + "-known"]["known_subjects"]),
                                     {run.manifest["nodes"][n]["public_key_hex"]
                                      for n in ("alice", "bob")})
                    self.assertEqual(receipts[name + "-device"],
                                     {"authorized": True, "usable": True})
                self.assertIs(receipts["alice-ad-verified"]["verified"], True)
                self.assertGreater(receipts["bob-publish"]["expires_unix_nano"],
                                   demo.time.time_ns())
            finally:
                base.close()
        finally:
            stopped = subprocess.run([*command, "down", "--base-dir", str(base_path)],
                                     capture_output=True, timeout=45)
            demo.create_file(parent / "down.stdout", stopped.stdout)
            demo.create_file(parent / "down.stderr", stopped.stderr)
            self.assertEqual(stopped.returncode, 0, "down failed; inspect retained evidence")
        base = demo.Base(base_path)
        try:
            run = base.select()
            self.assertEqual(run.manifest["state"], "down")
            self.assertTrue(demo.validate_configs(run))
            for process in run.manifest["processes"].values():
                self.assertEqual(demo.process_state(process), "stopped")
        finally:
            base.close()


if __name__ == "__main__":
    unittest.main()

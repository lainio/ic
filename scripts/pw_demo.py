#!/usr/bin/env python3
"""Disposable Linux two-node demo. Only the existing CLI and owner APIs mutate Vaults."""

import argparse
import base64
import contextlib
import datetime
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import uuid


REPO = Path(__file__).resolve().parent.parent
FORMAT = "ic-pw-demo-v1"
RUN_ID = re.compile(r"run-[0-9a-f]{32}\Z")
LABEL = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
NAMES = ("root", "alice", "bob")
SERVERS = ("root-alice", "root-bob", "alice", "bob")
LIMIT = 128 * 1024
CONFIG_LIMIT = 8192
CONFIG_NAMES = ("alice", "bob")
START_TIMEOUT = 20
STOP_TIMEOUT = 8
TTL_NS = 900 * 1_000_000_000
NOFOLLOW = os.O_NOFOLLOW | os.O_CLOEXEC
DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW
ROUTES = {
    ("GET", "/owner/status"), ("GET", "/owner/introduction"),
    ("POST", "/owner/introductions"),
    ("POST", "/owner/introductions/fetch"),
    ("POST", "/owner/introductions/verify"),
    ("POST", "/owner/device/bootstrap"),
    ("POST", "/owner/ads/publish"), ("POST", "/owner/ads/fetch"),
    ("POST", "/owner/ads/verify"),
    ("POST", "/owner/pw/invitations/issue"),
    ("POST", "/owner/pw/invitations/redeem"),
    ("POST", "/owner/pw/first-use"),
    ("GET", "/owner/pw/message/inbox?version=2"),
}


class DemoError(Exception):
    """Only fixed, non-sensitive reason codes may cross the console boundary."""


def require(condition, reason="unexpected-response"):
    if not condition:
        raise DemoError(reason)


def exact(value, fields):
    require(type(value) is dict and set(value) == set(fields))


def same(value, expected):
    # Python considers 1 == True. Receipts must retain JSON's type distinction.
    require(json.dumps(value, sort_keys=True) ==
            json.dumps(expected, sort_keys=True))


def decode_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate-json-field")
            result[key] = value
        return result

    require(len(data) <= LIMIT, "response-too-large")
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=pairs,
                          parse_constant=lambda _: require(False))
    except (ValueError, UnicodeError, RecursionError):
        raise DemoError("invalid-json") from None


def cose_hex(value):
    """Check the current signer's canonical COSE EC2 shape, not signatures.

    Go remains the validity/authority boundary. Coordinates can omit leading
    zero octets; never pad, re-encode, or substitute these identity bytes.
    """
    require(type(value) is str and
            re.fullmatch(r"[0-9a-f]{2,256}", value), "invalid-cose-hex")
    try:
        data = bytes.fromhex(value)
    except ValueError:
        raise DemoError("invalid-cose-hex") from None
    require(data.startswith(bytes.fromhex("a501020326200121")),
            "invalid-cose-shape")
    offset = 8
    for index in range(2):
        if index:
            require(data[offset:offset + 1] == b"\x22", "invalid-cose-shape")
            offset += 1
        require(offset < len(data), "invalid-cose-shape")
        size = data[offset] - 0x40
        offset += 1
        if size == 24:
            require(offset < len(data), "invalid-cose-shape")
            size = data[offset]
            offset += 1
            require(24 <= size <= 32, "noncanonical-cose")
        else:
            require(1 <= size <= 23, "invalid-cose-shape")
        require(offset + size <= len(data), "invalid-cose-shape")
        offset += size
    require(offset == len(data), "invalid-cose-shape")
    return value


def loopback_url(value, path):
    # All our listeners explicitly bind IPv4. No DNS, URL normalization,
    # userinfo, redirects, encoded paths, implicit ports, or proxy dispatch.
    require(type(value) is str, "invalid-url")
    match = re.fullmatch(r"http://127\.0\.0\.1:([1-9][0-9]{0,4})" +
                         re.escape(path), value)
    require(match is not None, "invalid-url")
    port = int(match[1])
    require(port <= 65535, "invalid-port")
    return port


def output_field(output, prefix):
    lines = [line[len(prefix):] for line in output.splitlines()
             if line.startswith(prefix)]
    require(len(lines) == 1, "missing-or-duplicate-output")
    return lines[0]


def public_output(output, role="node"):
    return cose_hex(output_field(output, role + " public key (hex): "))


def private_stat(info, directory=False, executable=False):
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    require(kind(info.st_mode) and info.st_uid == os.getuid(),
            "unexpected-file-owner-or-type")
    mode = 0o700 if directory or executable else 0o600
    require(stat.S_IMODE(info.st_mode) == mode, "unexpected-file-mode")
    if not directory:
        require(info.st_nlink == 1, "hardlink-refused")


def checked_path(value):
    path = Path(value)
    require(path.is_absolute() and str(path) == str(value) and
            ".." not in path.parts and
            all(ord(c) >= 32 and ord(c) != 127 for c in str(path)),
            "unsafe-path")
    # Check every existing component, including parents of a new base.
    for part in reversed((path, *path.parents)):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        require(not stat.S_ISLNK(info.st_mode), "symlink-refused")
        if part != path:
            require(stat.S_ISDIR(info.st_mode), "unsafe-ancestor")
            writable = info.st_mode & 0o022
            # A user namespace can expose the system owner's UID as overflow
            # UID (e.g. 65534). Compare to /, rather than assuming numeric zero.
            sticky_root = (info.st_uid == Path("/").stat().st_uid and
                           info.st_mode & stat.S_ISVTX)
            require(not writable or sticky_root, "unsafe-ancestor")
    return path


def read_private(path, limit=LIMIT):
    checked_path(path)
    with os.fdopen(os.open(path, os.O_RDONLY | NOFOLLOW), "rb") as stream:
        private_stat(os.fstat(stream.fileno()))
        data = stream.read(limit + 1)
    require(len(data) <= limit, "file-too-large")
    return data


def create_file(path, data):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                          NOFOLLOW, 0o600), "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def write_json(path, value, new=False):
    data = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    if new:
        create_file(path, data)
        return
    read_private(path)  # Refuse unexpected replacement targets.
    temporary = path.parent / (".write-" + uuid.uuid4().hex)
    create_file(temporary, data)
    os.replace(temporary, path)


def identity_stat(path):
    info = path.stat(follow_symlinks=False)
    return [info.st_dev, info.st_ino]


class Base:
    """A marked private parent, locked for each entire lifecycle operation."""

    def __init__(self, path, create=False):
        self.path = checked_path(path)
        require(self.path != Path.home() and self.path != Path("/") and
                not self.path.is_relative_to(REPO) and
                not REPO.is_relative_to(self.path) and
                "storage" not in self.path.parts, "unsafe-base")
        if not self.path.exists():
            require(create, "base-not-found")
            self.path.mkdir(mode=0o700)  # Parent must already exist.
            marker = {"format": FORMAT, "id": uuid.uuid4().hex,
                      "uid": os.getuid(), "repo": str(REPO),
                      "identity": identity_stat(self.path)}
            write_json(self.path / "base.json", marker, new=True)
            create_file(self.path / "lock", b"")
        private_stat(self.path.lstat(), directory=True)
        self.marker = decode_json(read_private(self.path / "base.json"))
        exact(self.marker, ("format", "id", "uid", "repo", "identity"))
        require(self.marker["format"] == FORMAT and
                self.marker["uid"] == os.getuid() and
                self.marker["repo"] == str(REPO) and
                re.fullmatch(r"[0-9a-f]{32}", self.marker["id"]) and
                self.marker["identity"] == identity_stat(self.path),
                "invalid-base-marker")
        self.lock = os.open(self.path / "lock", os.O_RDWR | NOFOLLOW)
        try:
            private_stat(os.fstat(self.lock))
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            os.close(self.lock)
            raise

    def close(self):
        os.close(self.lock)

    def latest_run_id(self):
        latest = decode_json(read_private(self.path / "latest.json"))
        exact(latest, ("run_id",))
        run_id = latest["run_id"]
        require(type(run_id) is str and RUN_ID.fullmatch(run_id),
                "invalid-run-id")
        return run_id

    def select(self, run_id=None):
        if run_id is None:
            run_id = self.latest_run_id()
        require(type(run_id) is str and RUN_ID.fullmatch(run_id),
                "invalid-run-id")
        return Run(self, run_id)

    def allocate(self):
        run_id = "run-" + uuid.uuid4().hex
        path = self.path / run_id
        path.mkdir(mode=0o700)
        marker = {"format": FORMAT, "run_id": run_id,
                  "uid": os.getuid(), "repo": str(REPO),
                  "base_id": self.marker["id"], "identity": identity_stat(path)}
        write_json(path / "run.json", marker, new=True)
        manifest = {"marker": marker, "stage": "allocated", "state": "partial",
                    "nodes": {name: {} for name in NAMES}, "processes": {},
                    "receipts": [], "last_log": None}
        write_json(path / "manifest.json", manifest, new=True)
        for directory in ("bin", "logs", "tmp"):
            (path / directory).mkdir(mode=0o700)
        latest = self.path / "latest.json"
        write_json(latest, {"run_id": run_id}, new=not latest.exists())
        return Run(self, run_id)


def flags(run, name, saved=False, state=False):
    result = ["--identity-dir" if saved else "--dir", str(run.path / name),
              "--unlock-file", str(run.path / (name + ".unlock"))]
    if state:
        result += ["--storage-key-file", str(run.path / (name + ".storage-key")),
                   "--root", run.manifest["nodes"]["root"]["public_key_hex"]]
    return result


def server_args(run, label):
    binary = str(run.path / "bin/tdc")
    if label.startswith("root-"):
        return [binary, "intro", "http-demo", "root", *flags(run, "root", True),
                "--listen", "127.0.0.1:0"]
    return [binary, "--v=1", "node", "serve", *flags(run, label, state=True),
            "--listen", "127.0.0.1:0", "--peer-listen", "127.0.0.1:0"]


class Run:
    def __init__(self, base, run_id):
        self.config_identity = None  # Only this invocation may undo publication.
        self.base = base
        self.path = checked_path(base.path / run_id)
        private_stat(self.path.lstat(), directory=True)
        marker = decode_json(read_private(self.path / "run.json"))
        exact(marker, ("format", "run_id", "uid", "repo", "base_id", "identity"))
        require(marker == {"format": FORMAT, "run_id": run_id,
                           "uid": os.getuid(), "repo": str(REPO),
                           "base_id": base.marker["id"],
                           "identity": identity_stat(self.path)},
                "invalid-run-marker")
        self.manifest = decode_json(read_private(self.path / "manifest.json"))
        m = self.manifest
        exact(m, ("marker", "stage", "state", "nodes", "processes",
                  "receipts", "last_log"))
        require(m["marker"] == marker and LABEL.fullmatch(m["stage"]) and
                m["state"] in ("partial", "ready", "failed", "down"),
                "invalid-manifest")
        require(m["last_log"] is None or
                re.fullmatch(r"logs/[a-z0-9-]+\.stderr", m["last_log"]),
                "invalid-manifest")
        exact(m["nodes"], NAMES)
        for name, node in m["nodes"].items():
            require(type(node) is dict and set(node) <= {
                "public_key_hex", "owner_url", "header_file", "peer_url"},
                "invalid-node-manifest")
            if "public_key_hex" in node:
                cose_hex(node["public_key_hex"])
            if "owner_url" in node:
                require(name != "root" and len(node) == 4,
                        "invalid-node-manifest")
                loopback_url(node["owner_url"], "/owner/status")
                loopback_url(node["peer_url"], "/peer/introduction")
                header_path(self, node["header_file"])
                validate_startup(self, name, node)
        keys = [n["public_key_hex"] for n in m["nodes"].values()
                if "public_key_hex" in n]
        require(len(set(keys)) == len(keys), "identities-not-independent")
        ports = [loopback_url(n[field], path)
                 for n in m["nodes"].values() if "owner_url" in n
                 for field, path in (("owner_url", "/owner/status"),
                                     ("peer_url", "/peer/introduction"))]
        require(len(set(ports)) == len(ports), "duplicate-listener-port")
        require(type(m["processes"]) is dict and
                set(m["processes"]) <= set(SERVERS), "invalid-process-manifest")
        if m["processes"]:
            private_stat((self.path / "bin/tdc").lstat(), executable=True)
        for label, record in m["processes"].items():
            exact(record, ("pid", "start", "boot", "uid", "exe", "argv_hash"))
            require(type(record["pid"]) is int and record["pid"] > 1 and
                    type(record["start"]) is int and record["start"] > 0 and
                    record["uid"] == os.getuid() and
                    re.fullmatch(r"[0-9a-f-]{36}", record["boot"]) and
                    record["exe"] == identity_stat(self.path / "bin/tdc") and
                    record["argv_hash"] == argv_hash(server_args(self, label)),
                    "invalid-process-manifest")
        require(type(m["receipts"]) is list and len(m["receipts"]) <= 32,
                "invalid-receipts")
        for receipt in m["receipts"]:
            exact(receipt, ("stage", "observed_ns", "result"))
            require(LABEL.fullmatch(receipt["stage"]) and
                    type(receipt["observed_ns"]) is int and
                    0 < receipt["observed_ns"] < 2 ** 63 and
                    type(receipt["result"]) is dict, "invalid-receipts")
            validate_receipt(self, receipt["stage"], receipt["result"])
        stages = [receipt["stage"] for receipt in m["receipts"]]
        require(stages == CHAT_RECEIPT_ORDER[:len(stages)],
                "invalid-receipt-order")
        final_orders = {"ready-for-invitation": RECEIPT_ORDER,
                        "ready-for-chat": CHAT_RECEIPT_ORDER}
        if m["state"] == "ready":
            require(m["stage"] in final_orders,
                    "incomplete-ready-manifest")
        if m["stage"] in final_orders:
            require(stages == final_orders[m["stage"]] and
                    m["state"] != "partial", "incomplete-ready-manifest")
        elif m["stage"] in CHAT_STAGES:
            # A stage is saved before dispatch; its receipt only after a
            # validated response. Failed/down runs retain either boundary.
            index = CHAT_RECEIPT_ORDER.index(m["stage"])
            require(len(stages) in (index, index + 1),
                    "inconsistent-chat-stage")
        else:
            require(len(stages) <= len(RECEIPT_ORDER),
                    "inconsistent-chat-stage")

    def save(self):
        write_json(self.path / "manifest.json", self.manifest)

    def stage(self, name, log=None):
        self.manifest["stage"] = name
        self.manifest["last_log"] = log
        self.save()

    def receipt(self, result):
        validate_receipt(self, self.manifest["stage"], result)
        self.manifest["receipts"].append({"stage": self.manifest["stage"],
                                          "observed_ns": time.time_ns(),
                                          "result": result})
        self.save()


RECEIPT_ORDER = [
    "alice-accepted-info", "bob-accepted-info", "alice", "bob",
    "alice-self-received", "bob-self-received",
    "alice-peer-received", "bob-peer-received", "alice-known", "bob-known",
    "alice-device", "bob-device", "bob-publish", "alice-ad-received",
    "alice-ad-verified",
]
CHAT_STAGES = [
    "bob-invitation", "alice-v2-acceptance", "alice-v2-first-use",
    "alice-v2-inbox", "bob-v2-inbox",
]
CHAT_RECEIPT_ORDER = RECEIPT_ORDER + CHAT_STAGES


def validate_receipt(run, stage, result):
    require(stage in CHAT_RECEIPT_ORDER, "invalid-receipt-stage")
    nodes = run.manifest["nodes"]
    name = stage.split("-")[0]
    peer = "bob" if name == "alice" else "alice"
    if stage.endswith("-accepted-info"):
        same(result, {"acceptance_saved": True, "identity_checked": True})
    elif stage in ("alice", "bob"):
        same(result, {"choice": "completed"})
    elif stage.endswith("-self-received") or stage.endswith("-peer-received"):
        own = stage.endswith("-self-received")
        same(result, {"subject_public_key_hex": nodes[name if own else peer]["public_key_hex"],
                      "is_self": own, "created": True})
    elif stage.endswith("-known"):
        exact(result, ("newly_known", "known_subjects"))
        require(type(result["newly_known"]) is int and result["newly_known"] == 2 and
                type(result["known_subjects"]) is list and
                len(result["known_subjects"]) == 2 and
                set(result["known_subjects"]) == {
                    nodes[n]["public_key_hex"] for n in ("alice", "bob")},
                "both-subjects-not-known")
    elif stage.endswith("-device"):
        same(result, {"authorized": True, "usable": True})
    elif stage == "bob-publish":
        exact(result, ("published", "slot", "epoch", "expires_unix_nano",
                       "peer_introduction_url"))
        expiry = result["expires_unix_nano"]
        require(type(expiry) is int and 0 < expiry < 2 ** 63,
                "invalid-publication-expiry")
        same(result, {"published": True, "slot": 1, "epoch": 0,
                      "expires_unix_nano": expiry,
                      "peer_introduction_url": nodes["bob"]["peer_url"]})
    elif stage == "alice-ad-received":
        same(result, {"subject_public_key_hex": nodes["bob"]["public_key_hex"],
                      "introduction_created": False, "ad_changed": True})
    elif stage == "alice-ad-verified":
        same(result, {"subject_public_key_hex": nodes["bob"]["public_key_hex"],
                      "verified": True, "changed": True})
    elif stage == "bob-invitation":
        exact(result, ("issued", "audience", "recipient_public_key_hex",
                       "expires_unix_nano"))
        expiry = result["expires_unix_nano"]
        require(type(expiry) is int and 0 < expiry < 2 ** 63,
                "invalid-invitation-expiry")
        same(result, {"issued": True, "audience": "Directed",
                      "recipient_public_key_hex": nodes["alice"]["public_key_hex"],
                      "expires_unix_nano": expiry})
    elif stage == "alice-v2-acceptance":
        same(result, {"acceptance_saved": True, "local_held": True})
    elif stage == "alice-v2-first-use":
        same(result, {"local_ready": True})
    else:
        same(result, {"present": False})


def argv_hash(args):
    return hashlib.sha256(b"\0".join(os.fsencode(a) for a in args) + b"\0").hexdigest()


def process_identity(pid):
    """Snapshot Linux identity; callers open a pidfd BEFORE checking it."""
    try:
        path = Path("/proc") / str(pid)
        fields = (path / "stat").read_text().rsplit(")", 1)[1].split()
        if fields[0] == "Z":
            return None
        executable = (path / "exe").stat()
        return {"pid": pid, "start": int(fields[19]),
                "boot": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                "uid": path.stat().st_uid,
                "exe": [executable.st_dev, executable.st_ino],
                "argv_hash": hashlib.sha256((path / "cmdline").read_bytes()).hexdigest()}
    except (FileNotFoundError, ProcessLookupError):
        return None


def process_state(record):
    current = process_identity(record["pid"])
    if current is None or current["boot"] != record["boot"]:
        return "stopped"
    return "running" if current == record else "identity-mismatch"


def stop_process(record, timeout=STOP_TIMEOUT, force=False):
    try:
        descriptor = os.pidfd_open(record["pid"])
    except ProcessLookupError:
        return "stopped"
    try:
        state = process_state(record)
        if state != "running":
            return state
        poller = select.poll()
        poller.register(descriptor, select.POLLIN)
        signals = [(signal.SIGINT, timeout)]
        if force:
            signals += [(signal.SIGTERM, 2), (signal.SIGKILL, 2)]
        for sig, seconds in signals:
            try:
                signal.pidfd_send_signal(descriptor, sig)
            except ProcessLookupError:
                return "stopped"
            if poller.poll(int(seconds * 1000)):
                return "stopped"
        return "shutdown-timeout"
    finally:
        os.close(descriptor)


def down(run, force=False):
    results = {}
    for label, record in run.manifest["processes"].items():
        try:
            results[label] = stop_process(record, force=force)
        except OSError:
            results[label] = "shutdown-unavailable"
    if all(value == "stopped" for value in results.values()):
        run.manifest["state"] = "down"
        run.save()
    return results


def header_path(run, value):
    path = checked_path(value)
    require(path.is_relative_to(run.path / "tmp"), "invalid-header-path")
    relative = path.relative_to(run.path / "tmp")
    require(len(relative.parts) == 2 and relative.name == "owner.header" and
            re.fullmatch(r"node-owner-status-[0-9]+", relative.parts[0]),
            "invalid-header-path")
    return path


def validate_startup(run, name, node):
    output = read_private(run.path / "logs" / (name + ".stdout")).decode("utf-8")
    same(node, {"public_key_hex": public_output(output),
                "owner_url": output_field(output, "owner status URL: "),
                "peer_url": output_field(output, "peer introduction URL: "),
                "header_file": output_field(output, "authorization header file: ")})


class Owner:
    def __init__(self, run, name):
        self.run = run
        self.name = name
        node = run.manifest["nodes"][name]
        validate_startup(run, name, node)
        self.port = loopback_url(node["owner_url"], "/owner/status")
        self.header = header_path(run, node["header_file"])
        private_stat(self.header.parent.lstat(), directory=True)
        value = read_private(self.header, 256)
        require(re.fullmatch(rb"Authorization: Bearer [0-9a-f]{64}\n", value),
                "invalid-owner-header")
        self.authorization = value.decode().strip().removeprefix("Authorization: ")

    def request(self, method, path, body=None, timeout=8):
        require((method, path) in ROUTES, "route-not-allowed")
        require(process_state(self.run.manifest["processes"][self.name]) ==
                "running", "owner-process-not-running")
        if body is not None and not isinstance(body, bytes):
            body = json.dumps(body, separators=(",", ":")).encode()
        require(body is None or len(body) <= LIMIT, "request-too-large")
        # HTTPConnection uses no proxy variables and never follows redirects.
        connection = http.client.HTTPConnection("127.0.0.1", self.port,
                                                timeout=timeout)
        timer = None
        try:
            deadline = time.monotonic() + timeout
            connection.connect()
            connected_socket = connection.sock

            def expire():
                try:
                    connected_socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

            # A socket timeout alone is per read, not a whole-operation bound.
            # Bound headers and slow body delivery as well as individual reads.
            remaining = deadline - time.monotonic()
            require(remaining > 0, "http-deadline")
            timer = threading.Timer(remaining, expire)
            timer.daemon = True
            timer.start()
            connection.request(method, path, body=body, headers={
                "Authorization": self.authorization,
                "Content-Type": "application/json", "Connection": "close"})
            response = connection.getresponse()
            require(response.status == 200, "unexpected-http-status")
            require(response.getheader("Content-Type") == "application/json" and
                    response.getheader("Content-Encoding") is None,
                    "unexpected-http-headers")
            data = response.read(LIMIT + 1)
            require(len(data) <= LIMIT, "response-too-large")
            value = decode_json(data)
            require(type(value) is dict)
            return value, data
        finally:
            if timer:
                timer.cancel()
                timer.join()
            connection.close()

    def json(self, method, path, body=None, timeout=8):
        return self.request(method, path, body, timeout)[0]


class Harness:
    def __init__(self, run):
        self.run = run
        self.children = []
        self.child_identities = {}
        self.owners = {}
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith("TDC_") and "proxy" not in k.lower()}
        self.env.update(TMPDIR=str(run.path / "tmp"), GOPROXY="off",
                        GOSUMDB="off", GOTOOLCHAIN="local", GOENV="off",
                        GOFLAGS="", GOWORK="off")

    def launch(self, label, args, server=False):
        self.run.stage(label, "logs/" + label + ".stderr")
        output = self.run.path / "logs" / (label + ".stdout")
        error = self.run.path / "logs" / (label + ".stderr")
        create_file(output, b"")
        create_file(error, b"")
        # Delay interrupts through child registration, so cleanup cannot miss
        # a successfully spawned process. Children receive their own session.
        with defer_interrupts():
            with output.open("ab") as stdout, error.open("ab") as stderr:
                child = subprocess.Popen(args, cwd=REPO if label == "build"
                                         else self.run.path, env=self.env,
                                         stdin=subprocess.DEVNULL, stdout=stdout,
                                         stderr=stderr, start_new_session=True)
            self.children.append(child)
            record = process_identity(child.pid)
            self.child_identities[child.pid] = record
            if server:
                require(record is not None and
                        record["argv_hash"] == argv_hash(args) and
                        record["exe"] == identity_stat(self.run.path / "bin/tdc"),
                        "child-exited-before-registration")
                self.run.manifest["processes"][label] = record
                self.run.save()
        return child, output

    def command(self, label, args, timeout=30):
        child, output = self.launch(label, args)
        try:
            code = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            raise DemoError("command-timeout") from None
        require(code == 0, "command-failed")
        return read_private(output).decode("utf-8")

    def cli(self, label, args):
        return self.command(label, [str(self.run.path / "bin/tdc"), *args])

    def start(self, label, prefixes):
        child, output = self.launch(label, server_args(self.run, label), True)
        deadline = time.monotonic() + START_TIMEOUT
        while time.monotonic() < deadline:
            require(child.poll() is None, "server-exited")
            text = read_private(output).decode("utf-8")
            if all(any(line.startswith(prefix) for line in text.splitlines())
                   for prefix in prefixes):
                return text
            time.sleep(0.05)  # Poll condition, bounded by the deadline.
        raise DemoError("startup-timeout")

    def stop_root(self, label):
        require(stop_process(self.run.manifest["processes"][label]) == "stopped",
                "root-shutdown-failed")
        for child in self.children:
            child.poll()

    def cleanup(self):
        # Retain every file. On a failed/interrupted up only, escalate for our
        # still-owned children if graceful SIGINT cannot stop them in time.
        results = down(self.run, force=True)
        server_pids = {r["pid"] for r in self.run.manifest["processes"].values()}
        for child in self.children:
            if child.poll() is None and child.pid not in server_pids:
                record = self.child_identities[child.pid]
                if record is not None:
                    results["command-" + str(child.pid)] = stop_process(record, force=True)
            child.poll()
        return results

    def ready(self, name):
        owner = Owner(self.run, name)
        deadline = time.monotonic() + START_TIMEOUT
        while True:
            remaining = deadline - time.monotonic()
            require(remaining > 0, "readiness-timeout")
            try:
                result = owner.json("GET", "/owner/status",
                                    timeout=min(1, remaining))
            except (ConnectionRefusedError, TimeoutError):
                time.sleep(min(0.05, max(0, deadline - time.monotonic())))
                continue
            require(result == {"choice": "completed"})
            self.run.receipt(result)
            self.owners[name] = owner
            return

    def post(self, name, stage, path, body):
        self.run.stage(stage, "logs/" + name + ".stderr")
        return self.owners[name].json("POST", path, body)

    def setup(self, chat_ready=False):
        run = self.run
        nodes = run.manifest["nodes"]
        self.command("build", ["go", "build", "-mod=readonly", "-o",
                               str(run.path / "bin/tdc"), "./cmd/tdc"], 180)
        os.chmod(run.path / "bin/tdc", 0o700)
        for name in NAMES:
            initial = self.cli(name + "-init", ["node", "init", *flags(run, name)])
            public = public_output(initial)
            if name != "root":
                initialized = self.cli(name + "-init-state", [
                    "node", "init-state", *flags(run, name, state=True)])
                require(public_output(initialized) == public and
                        "local state initialized: true" in initialized.splitlines())
            info = self.cli(name + "-info", ["node", "info", *flags(run, name)])
            require(public_output(info) == public, "identity-mismatch")
            require(public not in [n.get("public_key_hex") for n in nodes.values()],
                    "identities-not-independent")
            nodes[name]["public_key_hex"] = public
            run.save()

        for name in ("alice", "bob"):
            label = "root-" + name
            output = self.start(label, ("root public key (hex): ", "HTTP endpoint: "))
            require(public_output(output, "root") == nodes["root"]["public_key_hex"],
                    "root-identity-mismatch")
            endpoint = output_field(output, "HTTP endpoint: ")
            loopback_url(endpoint, "")
            accepted = self.cli(name + "-accept", [
                "intro", "http-demo", "accept", *flags(run, name, True, True),
                "--url", endpoint, "--timeout", "20s"])
            for line in ("choice and acceptance saved: true",
                         "local acceptance verifies: true",
                         "issuer returned HTTP 204: true"):
                require(line in accepted.splitlines(), "acceptance-not-confirmed")
            # Saved accept currently formats key.Public through String(). Read
            # the actual saved key using node info; never decode that legacy text.
            info = self.cli(name + "-accepted-info", [
                "node", "info", *flags(run, name)])
            require(public_output(info) == nodes[name]["public_key_hex"],
                    "accepted-identity-mismatch")
            run.receipt({"acceptance_saved": True, "identity_checked": True})
            self.stop_root(label)

        ports = set()
        for name in ("alice", "bob"):
            output = self.start(name, ("node public key (hex): ",
                                      "owner status URL: ",
                                      "authorization header file: ",
                                      "peer introduction URL: "))
            require(public_output(output) == nodes[name]["public_key_hex"],
                    "serve-identity-mismatch")
            node = dict(nodes[name])
            node["owner_url"] = output_field(output, "owner status URL: ")
            node["peer_url"] = output_field(output, "peer introduction URL: ")
            node["header_file"] = output_field(output, "authorization header file: ")
            header_path(run, node["header_file"])
            for field, path in (("owner_url", "/owner/status"),
                                ("peer_url", "/peer/introduction")):
                port = loopback_url(node[field], path)
                require(port not in ports, "duplicate-listener-port")
                ports.add(port)
            nodes[name] = node
            run.save()
            self.ready(name)

        for name in ("alice", "bob"):
            run.stage(name + "-self-received", "logs/" + name + ".stderr")
            document, raw = self.owners[name].request("GET", "/owner/introduction")
            exact(document, ("version", "proposal", "acceptance"))
            require(type(document["version"]) is int and document["version"] == 1)
            for field in ("proposal", "acceptance"):
                value = document[field]
                require(type(value) is str and value)
                decoded = base64.b64decode(value, validate=True)
                require(base64.b64encode(decoded).decode() == value)
            result = self.owners[name].json("POST", "/owner/introductions", raw)
            require(result == {"subject_public_key_hex": nodes[name]["public_key_hex"],
                               "is_self": True, "created": True})
            run.receipt(result)

        for name, peer in (("alice", "bob"), ("bob", "alice")):
            result = self.post(name, name + "-peer-received",
                               "/owner/introductions/fetch",
                               {"peer_url": nodes[peer]["peer_url"]})
            require(result == {"subject_public_key_hex": nodes[peer]["public_key_hex"],
                               "is_self": False, "created": True})
            run.receipt(result)
        for name in ("alice", "bob"):
            result = self.post(name, name + "-known", "/owner/introductions/verify", {})
            exact(result, ("newly_known", "known_subjects"))
            subjects = result["known_subjects"]
            require(type(result["newly_known"]) is int and result["newly_known"] == 2 and
                    type(subjects) is list and len(subjects) == 2 and
                    set(subjects) == {nodes[n]["public_key_hex"] for n in ("alice", "bob")},
                    "both-subjects-not-known")
            run.receipt(result)
        for name in ("alice", "bob"):
            result = self.post(name, name + "-device", "/owner/device/bootstrap", {})
            require(result == {"authorized": True, "usable": True} and
                    all(type(v) is bool for v in result.values()),
                    "device-authorization-or-probe-failed")
            run.receipt(result)

        before = time.time_ns()
        result = self.post("bob", "bob-publish", "/owner/ads/publish", {})
        exact(result, ("published", "slot", "epoch", "expires_unix_nano",
                       "peer_introduction_url"))
        expiry = result["expires_unix_nano"]
        require(result["published"] is True and type(result["slot"]) is int and
                result["slot"] == 1 and type(result["epoch"]) is int and
                result["epoch"] == 0 and type(expiry) is int and
                max(time.time_ns(), before + TTL_NS) <= expiry <= time.time_ns() + TTL_NS and
                result["peer_introduction_url"] == nodes["bob"]["peer_url"],
                "invalid-publication-receipt")
        run.receipt(result)
        result = self.post("alice", "alice-ad-received", "/owner/ads/fetch",
                           {"peer_url": nodes["bob"]["peer_url"].removesuffix(
                               "/peer/introduction") + "/peer/ad"})
        require(result == {"subject_public_key_hex": nodes["bob"]["public_key_hex"],
                           "introduction_created": False, "ad_changed": True})
        run.receipt(result)
        result = self.post("alice", "alice-ad-verified", "/owner/ads/verify",
                           {"subject_public_key_hex": nodes["bob"]["public_key_hex"]})
        require(result == {"subject_public_key_hex": nodes["bob"]["public_key_hex"],
                           "verified": True, "changed": True})
        run.receipt(result)
        require(time.time_ns() < expiry, "ad-expired-before-ready")
        for name in ("alice", "bob"):
            require(process_state(run.manifest["processes"][name]) == "running",
                    "server-exited-before-ready")
        if chat_ready:
            self.prepare_chat()
        run.manifest["state"] = "ready"
        run.stage("ready-for-chat" if chat_ready else "ready-for-invitation")

    def prepare_chat(self):
        run = self.run
        # Revalidate the recorded independent keys and their startup bindings
        # before any invitation operation. No caller-supplied key or contact.
        recorded = run.base.select(run.path.name)
        nodes = recorded.manifest["nodes"]
        result = self.post("bob", "bob-invitation",
                           "/owner/pw/invitations/issue",
                           {"recipient_public_key_hex":
                            nodes["alice"]["public_key_hex"]})
        exact(result, ("invitation_id_hex", "audience",
                       "recipient_public_key_hex", "expires_unix_nano"))
        invitation_id = result["invitation_id_hex"]
        require(type(invitation_id) is str and
                re.fullmatch(r"[0-9a-f]{64}", invitation_id),
                "invalid-invitation-id")
        # The ID is transient. Persist only bounded non-secret observations.
        receipt = {k: v for k, v in result.items() if k != "invitation_id_hex"}
        receipt["issued"] = True
        validate_receipt(run, "bob-invitation", receipt)
        require(receipt["expires_unix_nano"] > time.time_ns(),
                "invitation-expired-before-redemption")
        run.receipt(receipt)

        result = self.post("alice", "alice-v2-acceptance",
                           "/owner/pw/invitations/redeem", {
                               "version": 2,
                               "target_public_key_hex": nodes["bob"]["public_key_hex"],
                               "invitation_id_hex": invitation_id,
                               "audience": "Directed"})
        run.receipt(result)
        result = self.post("alice", "alice-v2-first-use",
                           "/owner/pw/first-use", {"version": 2})
        run.receipt(result)

        for name in ("alice", "bob"):
            run.stage(name + "-v2-inbox", "logs/" + name + ".stderr")
            result = self.owners[name].json(
                "GET", "/owner/pw/message/inbox?version=2")
            run.receipt(result)
        for name in ("alice", "bob"):
            require(process_state(run.manifest["processes"][name]) == "running",
                    "server-exited-before-ready")


@contextlib.contextmanager
def defer_interrupts():
    pending = []
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        for sig in previous:
            signal.signal(sig, lambda *_: pending.append(True))
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    if pending:
        raise KeyboardInterrupt


def up(run, chat_ready=False):
    harness = Harness(run)
    try:
        harness.setup(chat_ready=chat_ready)
        write_configs(run)
    except BaseException:
        with defer_interrupts():
            try:
                results = harness.cleanup()
                require(all(value == "stopped" for value in results.values()),
                        "setup-failed-cleanup-incomplete")
            finally:
                discard_configs(run)
                run.manifest["state"] = "failed"
                run.save()
        raise


def config_snapshot(run, name):
    node = run.manifest["nodes"][name]
    return {"version": 1, "role": name,
            "node_public_key_hex": node["public_key_hex"],
            "owner_status_url": node["owner_url"],
            "owner_header_file": node["header_file"]}


def remove_config_directory(path, identity):
    checked_path(path)
    descriptor = os.open(path, DIRECTORY)
    try:
        info = os.fstat(descriptor)
        private_stat(info, directory=True)
        require([info.st_dev, info.st_ino] == identity, "config-directory-changed")
        require(set(os.listdir(descriptor)) <= {n + ".json" for n in CONFIG_NAMES},
                "unexpected-config-entry")
        for name in os.listdir(descriptor):
            private_stat(os.stat(name, dir_fd=descriptor, follow_symlinks=False))
        remove_contents(descriptor, info.st_dev)
        require(identity_stat(path) == identity, "config-directory-changed")
        path.rmdir()
    finally:
        os.close(descriptor)


def write_configs(run):
    # Reload already recorded evidence, including independent keys/ports and
    # exact serve output. No HTTP, credential reads or node operations here.
    recorded = run.base.select(run.path.name)
    require(recorded.manifest["state"] == "ready", "config-before-ready")
    destination = run.path / "config"
    require(not os.path.lexists(destination), "config-already-exists")
    staging = run.path / "tmp" / (".config-" + uuid.uuid4().hex)
    with defer_interrupts():
        staging.mkdir(mode=0o700)
        identity = identity_stat(staging)
        try:
            for name in CONFIG_NAMES:
                value = config_snapshot(recorded, name)
                require(len((json.dumps(value, sort_keys=True, indent=2) + "\n").encode())
                        <= CONFIG_LIMIT,
                        "config-too-large")
                write_json(staging / (name + ".json"), value, new=True)
            # Publish the pair together; never expose just one role's config.
            os.rename(staging, destination)
            run.config_identity = identity
        except BaseException:
            remove_config_directory(staging, identity)
            raise


def discard_configs(run):
    if run.config_identity is not None:
        remove_config_directory(run.path / "config", run.config_identity)
        run.config_identity = None


def validate_configs(run):
    path = run.path / "config"
    if not os.path.lexists(path):
        return False  # Older and partial runs need no config directory.
    checked_path(path)
    private_stat(path.lstat(), directory=True)
    require(set(os.listdir(path)) == {n + ".json" for n in CONFIG_NAMES},
            "unexpected-config-entry")
    for name in CONFIG_NAMES:
        file = path / (name + ".json")
        private_stat(file.lstat())  # Refuse FIFOs/devices before opening.
        value = decode_json(read_private(file, CONFIG_LIMIT))
        same(value, config_snapshot(run, name))
    return True


def utc(nanoseconds):
    return datetime.datetime.fromtimestamp(nanoseconds / 1e9,
                                          datetime.timezone.utc).isoformat()


def list_runs(base):
    latest = (base.latest_run_id()
              if os.path.lexists(base.path / "latest.json") else None)
    rows = []
    for run_id in os.listdir(base.path):
        if not RUN_ID.fullmatch(run_id):
            continue
        try:
            path = checked_path(base.path / run_id)
            private_stat(path.lstat(), directory=True)
            # Refuse special files before the existing readers open them.
            for name in ("run.json", "manifest.json"):
                private_stat((path / name).lstat())
            run = base.select(run_id)
            validate_configs(run)
            modified = (path / "run.json").lstat().st_mtime_ns
            rows.append((modified, run_id, run.manifest["state"],
                         run.manifest["stage"]))
        except (DemoError, OSError, ValueError, TypeError, KeyError):
            # Never display unvalidated manifest fields or exception contents.
            rows.append((0, run_id, "INVALID", "-"))
    if not rows:
        print("No runs exist.")
        return
    print(f"  {'RUN ID':36}  {'LIFECYCLE':9}  CHECKPOINT")
    # The immutable marker has no creation timestamp. Its mtime is only an
    # ordering hint; invalid candidates follow validated runs.
    rows.sort(key=lambda row: (row[2] != "INVALID", row[0], row[1]), reverse=True)
    for _, run_id, lifecycle, checkpoint in rows:
        mark = "*" if run_id == latest else " "
        print(f"{mark} {run_id}  {lifecycle:9}  {checkpoint}")
    print("* latest; lifecycle/checkpoint are recorded history, not current health.")


def status(run):
    m = run.manifest
    print("Run:", m["marker"]["run_id"])
    print("Evidence directory:", run.path)
    print("Last setup stage:", m["stage"], "| lifecycle:", m["state"])
    for name in NAMES:
        node = m["nodes"][name]
        if "public_key_hex" in node:
            print(name.title() + " actual COSE public-key hex:", node["public_key_hex"])
        if "owner_url" in node:
            print(name.title() + " Flutter owner status URL:", node["owner_url"])
            print(name.title() + " Flutter owner.header file:", node["header_file"])
            print(name.title() + " peer introduction URL:", node["peer_url"])
            print(name.title() + " diagnostics:", run.path / "logs" / (name + ".stderr"),
                  "| stdout:", run.path / "logs" / (name + ".stdout"))
    for label, record in m["processes"].items():
        print(label + " process:", process_state(record))
    for receipt in m["receipts"]:
        print("Historical receipt:", receipt["stage"], "at", utc(receipt["observed_ns"]))
        stage = receipt["stage"]
        if stage.endswith("-known"):
            print("  Observed both actual Alice and Bob subjects in this owner's Known.")
        elif stage.endswith("-device"):
            print("  Observed authorized=true, usable=true at this bootstrap invocation.")
        elif stage == "alice-ad-verified":
            print("  Observed verified=true for Bob's actual subject on Alice.")
        elif stage in ("alice", "bob"):
            print("  Observed authenticated owner status: completed.")
        elif stage == "bob-invitation":
            print("  Observed Bob's Directed invitation issuance for Alice.")
        elif stage == "alice-v2-acceptance":
            print("  Observed Alice's saved v2 acceptance and local holding.")
        elif stage == "alice-v2-first-use":
            print("  Observed Alice's local historical v2 first-use Ready.")
        elif stage in ("alice-v2-inbox", "bob-v2-inbox"):
            print("  Observed this node's authenticated historical v2 inbox: empty.")
        if receipt["stage"] == "bob-publish":
            expiry = receipt["result"].get("expires_unix_nano")
            require(type(expiry) is int and 0 < expiry < 2 ** 63, "invalid-receipt")
            print("Bob published ad expiry (server-issued):", utc(expiry))
    print("Stored receipts are historical; they do not prove ongoing reachability, "
          "authorization or current readiness.")
    print("Alice = requester; Bob = invitation issuer/acceptor.")
    if validate_configs(run):
        for name in CONFIG_NAMES:
            print(name.title() + " Flutter config:",
                  run.path / "config" / (name + ".json"))
        print("Launch snapshots only; not proof of current identity, availability, "
              "invitation state or credential validity. Node restart makes them stale.")
    else:
        print("No Flutter config snapshots in this run.")


def validate_tree(descriptor, device):
    """Preflight every entry without following links, before deleting anything."""
    for name in os.listdir(descriptor):
        info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        directory = stat.S_ISDIR(info.st_mode)
        require(info.st_dev == device, "cross-device-tree-refused")
        private_stat(info, directory, executable=bool(info.st_mode & 0o100))
        if directory:
            child = os.open(name, DIRECTORY, dir_fd=descriptor)
            try:
                require(os.fstat(child).st_ino == info.st_ino, "tree-changed")
                validate_tree(child, device)
            finally:
                os.close(child)


def remove_contents(descriptor, device):
    for name in os.listdir(descriptor):
        info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        directory = stat.S_ISDIR(info.st_mode)
        require(info.st_dev == device, "cross-device-tree-refused")
        private_stat(info, directory, executable=bool(info.st_mode & 0o100))
        if directory:
            child = os.open(name, DIRECTORY, dir_fd=descriptor)
            try:
                require(os.fstat(child).st_ino == info.st_ino, "tree-changed")
                remove_contents(child, device)
            finally:
                os.close(child)
            os.rmdir(name, dir_fd=descriptor)
        else:
            os.unlink(name, dir_fd=descriptor)


def destroy(run, confirm):
    require(confirm == run.manifest["marker"]["run_id"] and RUN_ID.fullmatch(confirm),
            "confirmation-mismatch")
    # Reload both markers and manifest before signals or deletion. No arbitrary
    # path argument ever reaches removal; deletion is anchored to open dirfds.
    run = run.base.select(confirm)
    results = down(run)
    require(all(value == "stopped" for value in results.values()),
            "unsafe-to-destroy-processes")
    parent = os.open(run.base.path, DIRECTORY)
    try:
        base_info = os.fstat(parent)
        require([base_info.st_dev, base_info.st_ino] == run.base.marker["identity"],
                "base-directory-changed")
        descriptor = os.open(confirm, DIRECTORY, dir_fd=parent)
    except BaseException:
        os.close(parent)
        raise
    try:
        info = os.fstat(descriptor)
        require([info.st_dev, info.st_ino] == run.manifest["marker"]["identity"],
                "run-directory-changed")
        allowed = {"run.json", "manifest.json", "bin", "logs", "tmp", "config",
                   *NAMES, *(name + ".unlock" for name in NAMES),
                   "alice.storage-key", "bob.storage-key"}
        require(set(os.listdir(descriptor)) <= allowed, "unexpected-run-entry")
        validate_configs(run)
        validate_tree(descriptor, info.st_dev)
        remove_contents(descriptor, info.st_dev)
        require(identity_stat(run.path) == [info.st_dev, info.st_ino],
                "run-directory-changed")
        os.rmdir(confirm, dir_fd=parent)
    finally:
        os.close(descriptor)
        os.close(parent)
    latest = run.base.path / "latest.json"
    if latest.exists() and decode_json(read_private(latest)) == {"run_id": confirm}:
        latest.unlink()


def platform_check():
    require(sys.platform == "linux" and hasattr(os, "pidfd_open") and
            hasattr(signal, "pidfd_send_signal"), "linux-pidfd-required")
    descriptor = os.pidfd_open(os.getpid())
    os.close(descriptor)


def interrupted(*_):
    raise KeyboardInterrupt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    for name in ("up", "list", "status", "down", "destroy"):
        command = subcommands.add_parser(name)
        command.add_argument("--base-dir", default=str(Path.home() / ".ic-pw-demo"),
                             help="new or marked private absolute parent outside the repo")
        if name == "up":
            command.add_argument("--chat-ready", action="store_true",
                                 help="prepare v2 invitation and first-use history")
            command.add_argument("--json", action="store_true",
                                 help="print successful run metadata as JSON")
        if name in ("status", "down"):
            command.add_argument("--run-id", help="default: most recently allocated run")
        if name == "destroy":
            command.add_argument("--confirm", required=True, metavar="RUN_ID")
    args = parser.parse_args(argv)
    os.umask(0o077)
    signal.signal(signal.SIGTERM, interrupted)
    base = run = None
    try:
        if args.command != "list":
            platform_check()
        base = Base(args.base_dir, create=args.command == "up")
        if args.command == "up":
            with defer_interrupts():
                run = base.allocate()
            up(run, chat_ready=args.chat_ready)
            checkpoint = ("READY_FOR_CHAT" if args.chat_ready
                          else "READY_FOR_INVITATION")
            logs = {name: str(run.path / "logs" / (name + ".stderr"))
                    for name in ("alice", "bob")}
            if args.json:
                result = json.dumps({"status": "ok", "run_id": run.path.name,
                                     "checkpoint": checkpoint, "logs": logs})
            else:
                result = (f"OK {run.path.name} {checkpoint}\n"
                          f"ALICE_LOG {logs['alice']}\n"
                          f"BOB_LOG {logs['bob']}")
            print(result, flush=True)
        elif args.command == "list":
            list_runs(base)
        elif args.command == "destroy":
            run = base.select(args.confirm)
            destroy(run, args.confirm)
            print("DESTROYED", args.confirm, "(verified disposable tree only)")
        else:
            run = base.select(args.run_id)
            if args.command == "status":
                status(run)
            else:
                results = down(run)
                for label, result in results.items():
                    print(label + ":", result)
                require(all(value == "stopped" for value in results.values()),
                        "shutdown-incomplete")
                print("DOWN; evidence retained:", run.path)
        return 0
    except (Exception, KeyboardInterrupt) as error:
        stage = run.manifest["stage"] if run else "ownership-preflight"
        reason = str(error) if isinstance(error, DemoError) else "operation-failed"
        # Output/interrupt failure after setup is still a failed up. Keep the
        # recorded servers alive only after all success output has completed.
        if args.command == "up" and run and run.manifest["state"] != "failed":
            try:
                with defer_interrupts():
                    try:
                        results = down(run, force=True)
                    finally:
                        discard_configs(run)
                        run.manifest["state"] = "failed"
                        run.save()
                    require(all(value == "stopped" for value in results.values()),
                            "cleanup-incomplete")
            except (Exception, KeyboardInterrupt):
                reason = "setup-failed-cleanup-incomplete"
        identifier = " run=" + run.path.name if run else ""
        print("FAILED" + identifier + " stage=" + stage + " reason=" + reason,
              file=sys.stderr)
        if run:
            print("Private evidence:", run.path, file=sys.stderr)
            log = run.manifest["last_log"]
            if log:
                print("Private diagnostic file:", run.path / log, file=sys.stderr)
        return 1
    finally:
        if base:
            base.close()


if __name__ == "__main__":
    sys.exit(main())

# Disposable pairwise demo

From the Go checkout, on a trusted Linux host with Python 3.9+ and Linux
pidfd support, run:

~~~sh
python3 scripts/pw_demo.py up
python3 scripts/pw_demo.py list
python3 scripts/pw_demo.py status
python3 scripts/pw_demo.py down
python3 scripts/pw_demo.py destroy --confirm RUN_ID
~~~

`up` creates a new `~/.ic-pw-demo/run-<random-id>` every time. It builds this
checkout's `tdc` once with `go build -mod=readonly`, using the installed Go
toolchain and cached dependencies. It disables module/toolchain downloads,
inherited `TDC_*` configuration and proxy settings. It never uses a PATH `tdc`.
Install the repository's Go prerequisites before running; this harness does
not install anything. The default parent is outside the repository and all
old `../storage` trees. Root gets an identity only; Alice and Bob each get
independent identities, unlock files, storage secrets and Vaults.

For a restricted environment, append `--base-dir /absolute/new/private-parent`
to **every** command. Its parent must already exist. An existing base is
accepted only with this harness's valid ownership marker, private permissions
and matching checkout path. Ordinary existing directories, symlinks, repository
paths, ancestors of the checkout and paths containing a `storage` component
are refused. No previous identities or Vaults are reused.

`list` discovers runs without a run ID and marks the `latest.json` selection
with `*`. It shows recorded lifecycle and checkpoint, not current process or
network health. Valid runs appear newest first using the immutable run marker's
filesystem modification time; invalid candidates appear as `INVALID` without
untrusted details. Listing reads local evidence under the base lock, makes no
HTTP or process calls, and changes no stored state. An empty valid base reports
`No runs exist.`

`status` and `down` default to the most recently allocated run, including a
failed partial run. Use `--run-id RUN_ID` to select an older one. A new `up`
does not stop an older run. `destroy --confirm RUN_ID` selects that exact run,
independently of the latest pointer; it does not accept a deletion path.
Copy a full run ID from `list` into `destroy --confirm RUN_ID`; listing does not
relax destruction's validation. `mysys` may be the presenter's shell alias for
`python3 scripts/pw_demo.py`; no alias is required.

## Presenter workflow

Terminal 1, from the Go checkout:

~~~sh
python3 scripts/pw_demo.py up --chat-ready
~~~

Successful `up` prints exactly three lines with the full allocated run ID and
both actual absolute node log paths, after setup and config publication succeed:

~~~text
OK run-0123456789abcdef0123456789abcdef READY_FOR_CHAT
ALICE_LOG /home/user/.ic-pw-demo/run-0123456789abcdef0123456789abcdef/logs/alice.stderr
BOB_LOG /home/user/.ic-pw-demo/run-0123456789abcdef0123456789abcdef/logs/bob.stderr
~~~

In two separate tmux panes, use the paths printed after `ALICE_LOG` and
`BOB_LOG` (replace these example paths):

~~~sh
tail -n 0 -F -- /absolute/RUN/logs/alice.stderr
tail -n 0 -F -- /absolute/RUN/logs/bob.stderr
~~~

Run one command per pane. `-n 0` shows only new events; `-F` follows the file.
The panes show genuine Go events as messages are exchanged. The controller
does not start or manage tmux.

For Alice's message, Alice's log shows:

~~~text
intro_pw op=message_send version=2 stage=prepare result=authorized
intro_pw op=message_send version=2 stage=ack result=observed
~~~

Bob's log shows:

~~~text
intro_pw op=message_receive version=2 stage=receipt result=prepared
~~~

Roles reverse for Bob's reply. The existing glog severity/timestamp prefix may
precede each line. `authorized` means local preparation, including durable
sent-attempt authorization, completed; it does not claim HTTP dispatch.
`prepared` means the receiver authenticated the message, admitted the inbox
and signed a receipt; it does not claim the sender observed that receipt.
`observed` means the sender authenticated the receiver's signed assertion and
saved or retained its ACK. It proves neither delivery, current permission,
a live channel nor honest remote storage. Permitted exact retries may log
again without another durable write. The events contain no message contents,
lengths or identifiers; successful inbox polling and historical reads stay quiet.

Optional `up --json` emits exactly one UTF-8 JSON object plus a newline, with
the same setup and actual run metadata. These are its exact fields and types:

~~~json
{"status":"ok","run_id":"run-0123456789abcdef0123456789abcdef","checkpoint":"READY_FOR_CHAT","logs":{"alice":"/home/user/.ic-pw-demo/run-0123456789abcdef0123456789abcdef/logs/alice.stderr","bob":"/home/user/.ic-pw-demo/run-0123456789abcdef0123456789abcdef/logs/bob.stderr"}}
~~~

For future shell/tmux automation with `jq`, using the optional `mysys` alias:

~~~sh
result=$(mysys up --chat-ready --json) || exit 1
printf '%s\n' "$result" | jq -r '.logs.alice, .logs.bob'
~~~

Ordinary `up --json` reports `READY_FOR_INVITATION`. Text remains the default;
`status`, `list`, `down` and `destroy` have no JSON mode. Setup failure returns
nonzero, keeps stdout empty, and retains sanitized stderr diagnostics and
private evidence paths. An output write/flush failure may leave partial output;
it still triggers existing failure cleanup, without retrying setup.

Alice and Bob's Go nodes remain running after the command returns. Use `status`
for the detailed report, including both actual absolute Flutter config paths:

~~~sh
python3 scripts/pw_demo.py list
python3 scripts/pw_demo.py status
~~~

Use the config paths from `status` in the following commands.

Terminal 2, from `apps/node_ui`, with cached dependencies on ARM64 Linux:

~~~sh
flutter build linux --debug --no-pub
./build/linux/arm64/debug/bundle/ic_node_ui \
    --config /absolute/RUN/config/alice.json
~~~

Terminal 3, also from `apps/node_ui`:

~~~sh
./build/linux/arm64/debug/bundle/ic_node_ui \
    --config /absolute/RUN/config/bob.json
~~~

Use `build/linux/x64/debug/bundle/ic_node_ui` on x64 Linux. These are bundle
executable arguments; the controller does not launch Flutter or manage tmux.

1. In each window, open `Wallet demo`.
2. Select the configured counterpart (Bob in Alice's window, Alice in Bob's).
3. Click `Open live conversation` in each window.
4. Send Alice's one message.
5. Observe it in Bob's window.
6. Send Bob's one reply.
7. Observe it in Alice's window.

The graph is illustrative; these messages use real authenticated Go state.
The bound remains one outgoing and one incoming message per node. Transport
is trusted same-machine loopback plaintext. This demonstration provides no
Tor, E2EE, anonymity, shared `PWOpen`, Trust or production transport security.
Keep both nodes at their original listener addresses throughout the trial.

After the demonstration, from the Go checkout:

~~~sh
python3 scripts/pw_demo.py down
~~~

## Setup checkpoints

Plain `python3 scripts/pw_demo.py up` still stops at `READY_FOR_INVITATION`,
with no invitation, redemption or first use. Both modes use the same initial
setup. The controller uses two successive in-memory Root offers, restarting
the same saved Root between Alice and Bob, then stops Root. It starts each
operational node with `--v=1`, separate owner/peer loopback
ports, and separate stdout/stderr files. The CLI's generic `Alice` onboarding
label is not an identity. Saved accept currently has a legacy key formatter;
the harness checks each saved child's actual `node info` key afterward and
requires `node serve` to print those exact canonical COSE bytes.

Each owner explicitly saves its own introduction, fetches the other's,
verifies **both** subjects into its local Known, and bootstraps its own device.
Both bootstrap responses must report `authorized=true, usable=true`.
Only then does Bob publish an ad. Alice fetches Bob's `/peer/ad` and explicitly
verifies the ad for Bob's actual public key. Fetch alone is never Known or
VerifiedAd. The harness records validated owner receipts in `manifest.json`;
it does not inspect or modify encrypted Vault records.

Only `up --chat-ready` then performs, once and in order:

| Recorded stage | Authenticated owner operation and observed result |
| --- | --- |
| `bob-invitation` | Bob issues a Directed invitation for Alice's validated full COSE key |
| `alice-v2-acceptance` | Alice redeems with `version:2`, Bob's validated key and that exact issued ID; `acceptance_saved:true, local_held:true` |
| `alice-v2-first-use` | Alice requests `{"version":2}` first use; `local_ready:true` |
| `alice-v2-inbox` | Alice reads `/owner/pw/message/inbox?version=2`; exactly `{"present":false}` |
| `bob-v2-inbox` | Bob independently reads that same owner route; exactly `{"present":false}` |

Go owns signed establishment, immutable service-contact binding and each
node's independent Vault commits. Alice's Ready is her local historical
observation; Bob retains his own signed first-use receipt. The inbox reads
authenticate each node's accepted v2 history and first-use evidence. They do
not show current remote availability or permission. Setup sends no message.

Only after all five steps does the controller commit `ready-for-chat`.
The manifest keeps bounded non-secret receipts, never the invitation ID,
signed messages or bearer tokens. The issued ID exists only in transient setup
memory. `status` reports recorded history without HTTP or state changes.

After successful setup, `up` publishes `RUN/config/alice.json` and
`RUN/config/bob.json` together by an atomic directory rename. Both snapshots
come only from the already checked manifest and startup output; generating
them makes no additional HTTP, Vault, signing or device calls. `config` is
0700 and both files are 0600. A failed or interrupted `up`, including failure
while printing success, removes its new snapshots. Old runs are never rewritten.
For chat-ready mode, both historical checks precede publication and
`OK ... READY_FOR_CHAT` is printed only after publication succeeds. Read-only
`status` retains the full run ID, lifecycle/checkpoint, all node keys and
endpoints, both config paths, historical receipts, process observations and
diagnostic log locations.

Each file has exactly these five fields (Bob uses his own checked values):

~~~json
{
  "version": 1,
  "role": "alice",
  "node_public_key_hex": "<full actual COSE key from node info / serve>",
  "owner_status_url": "http://127.0.0.1:<port>/owner/status",
  "owner_header_file": "<absolute RUN/tmp/.../owner.header path>"
}
~~~

`version:1` is the Flutter launch-config format, not the pairwise protocol
version. Snapshots contain no bearer token, unlock/storage key, invitation ID
or signed bytes. Paths themselves are not credentials. Flutter prefills `My node` and
displays the selectable role and full key with **Configuration supplied by demo
harness; not independently authenticated by Flutter.** Editing either owner
field hides that identity association. Startup sends no owner requests and
does not read the credential. Launch snapshots are not proof of current
identity, availability, invitation state or credential validity. The graph and
sample chat remain fixtures; explicit live conversation activation uses Go.

Bob is the invitation **issuer/acceptor**; Alice is the **requester**.
With plain `up`, Bob's invitation slot is unused when setup finishes. The
existing `Live pairing` UI can still issue, redeem and perform first use
manually using v1. Use `up --chat-ready` for the v2 conversation above; the
legacy v1 controls do not prepare v2 history. The controller never calls
invitation revoke, Deny, Delete or message send.

The ad and invitation have **distinct 15-minute TTLs**. For manual setup,
issue/redeem shortly afterward. READY is a checkpoint at setup time, not a
permanent promise. There is no refresh loop, republish or invitation renewal. Use a new
disposable run for another trial. Historical verification and signer-probe
receipts do not prove ongoing reachability, authorization or current readiness.
This harness adds no cryptographic authority, shared PW, `PWOpen` or Trust.

Plain `up` also prints exactly three lines after setup and config publication:

~~~text
OK run-abcdef0123456789abcdef0123456789 READY_FOR_INVITATION
ALICE_LOG /home/user/.ic-pw-demo/run-abcdef0123456789abcdef0123456789/logs/alice.stderr
BOB_LOG /home/user/.ic-pw-demo/run-abcdef0123456789abcdef0123456789/logs/bob.stderr
~~~

For another message exchange, allocate a fresh disposable run with
`up --chat-ready`. The one-message/one-reply bound is unchanged; there is no
reset or message-history deletion.

After the trial:

~~~text
$ python3 scripts/pw_demo.py down
alice: stopped
bob: stopped
root-alice: stopped
root-bob: stopped
DOWN; evidence retained: /home/me/.ic-pw-demo/run-<id>
~~~

## Diagnosis and cleanup

`status` only reads the manifest, startup output, configs and process identity. It does
not probe HTTP or mutate a node. Stored owner URLs and header paths describe
that invocation; graceful Go shutdown removes its temporary header files.
`down` preserves the remaining directory, binary, logs, identity/state files
and manifest, including both config snapshots as historical artifacts.
Restarting a node makes its old config stale; use a new run for the next trial.
It is safe to repeat. It sends SIGINT only through pidfds after
checking boot ID, process start time, UID, executable inode and exact command
digest. It waits at most eight seconds per recorded server. A mismatch or
shutdown timeout returns failure and prevents destruction; no unrelated PID
or process group is signaled.

Setup polls startup output and authenticated status with deadlines, detects
early process exits, and never retries a mutation after a lost reply. A failed
or lost mutating response can follow a committed effect; its outcome remains
unresolved, with no rollback inferred. Create a fresh disposable run. A failed
or interrupted `up` reports `FAILED run=RUN_ID stage=STAGE reason=FIXED_CODE`
and its private evidence/diagnostic paths, stops its own children and retains
the partial run. Failure before allocation omits the run ID. Only failure
cleanup may escalate from SIGINT to SIGTERM/SIGKILL for the same verified child,
with bounded waits.
SIGKILL of the orchestrator itself or host power loss cannot run cleanup;
use `status`/`down` to inspect any registered survivors. There is no resume or
repair of partial state.

All harness directories are 0700; logs, markers, manifests and secret files
are 0600. Alice diagnostics are `RUN/logs/alice.stderr`, Bob diagnostics are
`RUN/logs/bob.stderr`; their stdout is in the corresponding `.stdout` files.
Root's two invocations have separate `root-alice.*` and `root-bob.*` files.
Go temporary credentials stay under `RUN/tmp`. Keep the whole run private.

Deletion requires matching base/run markers, UID, directory inode, checkout,
manifest and explicit run ID. It refuses symlinks, hardlinks, unexpected entry
types, permissions, top-level entries, mount/device changes and ambiguous
process ownership. When `config` exists it must contain exactly `alice.json`
and `bob.json`, both 0600 regular single-link files matching the manifest's
five-field snapshots. Missing, extra or modified config content is refused.
Older and partial runs without `config` remain supported.
Removal uses directory descriptors and never follows links
or runs a shell deletion command. These checks catch mistakes and unexpected
state; they are not a security boundary against a malicious process running as
the same user, which could forge markers or alter the checkout. Do not edit
the manifest or copy unrelated files into a disposable run.

## Validation

Socket-free deterministic tests use fake processes and HTTP:

~~~sh
python3 -B -m unittest discover -s scripts -p 'test_pw_demo.py' -v
~~~

Opt-in live smoke (uses a newly allocated private `/tmp/ic-pw-demo-smoke-*`
parent, builds the current checkout, runs `up`, checks both authenticated owner
statuses and saved Known/device/ad receipts, then runs `down`):

~~~sh
PW_DEMO_LIVE=1 python3 -B -m unittest discover -s scripts -p 'test_pw_demo.py' -k LiveSmoke -v
~~~

That existing smoke remains invitation-free. The separate chat-ready smoke
builds the actual Go binary, runs `up --chat-ready --json`, checks the JSON run
ID and log paths, recorded stages, both running nodes' authenticated v2 empty
inboxes and the config pair, then runs `down` and verifies process shutdown
and retained configs:

~~~sh
PW_DEMO_CHAT_LIVE=1 python3 -B -m unittest discover -s scripts -p 'test_pw_demo.py' -k ChatReadyLiveSmoke -v
~~~

Both live tests retain evidence on success and failure and print their private
`/tmp` parent paths. A denied loopback permission probe reports
`NOT RUN / BLOCKED BY SANDBOX`; it never changes permissions or counts a skip
as a pass. Child execution and build failures remain failures, with private
logs. Deterministic fake-controller tests do not establish real-node readiness.
A chat-ready live pass covers real CLI/owner operations and historical checks;
it sends no test message and does not perform the manual Flutter rehearsal.
Report those three forms of validation separately.

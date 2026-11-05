# Disposable pairwise demo

From the Go checkout, on a trusted Linux host with Python 3.9+ and Linux
pidfd support, run:

~~~sh
python3 scripts/pw_demo.py up
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

`status` and `down` default to the most recently allocated run, including a
failed partial run. Use `--run-id RUN_ID` to select an older one. A new `up`
does not stop an older run. `destroy --confirm RUN_ID` selects that exact run,
independently of the latest pointer; it does not accept a deletion path.

## Presenter workflow

Wait for `READY_FOR_INVITATION`. Setup uses two successive in-memory Root
offers, restarting the same saved Root between Alice and Bob, then stops Root.
It starts each operational node with `--v=1`, separate owner/peer loopback
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

After successful setup, `up` publishes `RUN/config/alice.json` and
`RUN/config/bob.json` together by an atomic directory rename. Both snapshots
come only from the already checked manifest and startup output; generating
them makes no additional HTTP, Vault, signing or device calls. `config` is
0700 and both files are 0600. A failed or interrupted `up`, including failure
while printing success, removes its new snapshots. Old runs are never rewritten.

`up` and read-only `status` print both absolute config paths. Launch the
bundled Flutter executable in two separate processes, using the appropriate
path in each. From `apps/node_ui`, with cached offline dependencies on ARM64:

~~~sh
flutter build linux --debug --no-pub
./build/linux/arm64/debug/bundle/ic_node_ui --config /absolute/RUN/config/alice.json
~~~

In a second terminal in the same package directory:

~~~sh
./build/linux/arm64/debug/bundle/ic_node_ui --config /absolute/RUN/config/bob.json
~~~

Use `build/linux/x64/debug/bundle/ic_node_ui` for an x64 build. These are
executable arguments, not a `flutter run` forwarding form. The existing Linux
runner forwards them to Dart and allows independent windows. The harness
does not launch Flutter or change process supervision. See the
[actual native launch check](../apps/node_ui/README.md#ui-02-verification)
for the paths used during this increment.

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

Snapshots contain no bearer token, unlock/storage key, invitation ID or signed
bytes. Paths themselves are not credentials. Flutter prefills `My node` and
displays the selectable role and full key with **Configuration supplied by demo
harness; not independently authenticated by Flutter.** Editing either owner
field hides that identity association. Startup sends no owner requests and
does not read the credential. Launch snapshots are not proof of current
identity, availability, invitation state or credential validity. The fictional
wallet switcher, graph and chat remain separate fixtures.

Bob is the invitation **issuer/acceptor**; Alice is the **requester**.
Use Bob's existing UI to issue an invitation, transfer it through the existing
UI, redeem it as Alice, then explicitly perform authenticated first use as
Alice. These remain operator-controlled actions. The script never calls
invitation issue/redeem/revoke, first use, Deny or Delete, and adds no messaging.
Bob's invitation slot is still unused when setup finishes.

The ad and eventual invitation have **distinct 15-minute TTLs**. Issue/redeem
shortly after setup. READY is a checkpoint at setup time, not a permanent
promise. There is no refresh loop, republish or invitation renewal. Use a new
disposable run for another trial. Historical verification and signer-probe
receipts do not prove ongoing reachability, authorization or current readiness.
This harness adds no cryptographic authority, shared PW, `PWOpen` or Trust.

Example output, abbreviated with placeholders for per-run values (the actual
command prints all three full keys, all receipts and both diagnostic paths):

~~~text
Preparing disposable run: /home/me/.ic-pw-demo/run-<id>
READY_FOR_INVITATION
Run: run-<id>
Evidence directory: /home/me/.ic-pw-demo/run-<id>
Last setup stage: ready-for-invitation | lifecycle: ready
Alice actual COSE public-key hex: <full actual Alice COSE hex>
Alice Flutter owner status URL: http://127.0.0.1:45725/owner/status
Alice Flutter owner.header file: /home/me/.ic-pw-demo/run-<id>/tmp/node-owner-status-<n>/owner.header
Bob actual COSE public-key hex: <full actual Bob COSE hex>
Bob Flutter owner status URL: http://127.0.0.1:39925/owner/status
Bob Flutter owner.header file: /home/me/.ic-pw-demo/run-<id>/tmp/node-owner-status-<m>/owner.header
Bob peer introduction URL: http://127.0.0.1:45635/peer/introduction
Alice = requester; Bob = invitation issuer/acceptor.
Alice Flutter config: /home/me/.ic-pw-demo/run-<id>/config/alice.json
Bob Flutter config: /home/me/.ic-pw-demo/run-<id>/config/bob.json
alice process: running
bob process: running
Historical receipt: alice-known at <UTC observation time>
  Observed both actual Alice and Bob subjects in this owner's Known.
Historical receipt: bob-device at <UTC observation time>
  Observed authorized=true, usable=true at this bootstrap invocation.
Bob published ad expiry (server-issued): <UTC expiry>
Historical receipt: alice-ad-verified at <UTC observation time>
  Observed verified=true for Bob's actual subject on Alice.
WARNING: READY is a setup-time checkpoint, not a permanent promise. Issue/redeem shortly afterward in Flutter. The ad and eventual invitation have separate 15-minute TTLs; nothing auto-renews.
No invitation issued or consumed; no first use performed.
~~~

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
or interrupted `up` reports its named stage and private diagnostic path, stops
its own children and retains the partial run. Only failure cleanup may escalate
from SIGINT to SIGTERM/SIGKILL for the same verified child, with bounded waits.
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

The live test leaves its evidence on success and failure and prints its parent
path. It never issues an invitation. A denied loopback permission probe reports
`NOT RUN / BLOCKED BY SANDBOX`; it never changes permissions or counts a skip
as a pass. Child execution and build failures remain failures, with private
logs. A live pass covers real CLI processes, sockets and setup receipts, not
Flutter invitation redemption or authenticated first use. Those manual UI
steps remain the presenter trial.

The next research increment is to **specify real text messaging**. The existing
one-shot authenticated first-use exchange is not a chat transport.

# Native file Copy/Paste between Client and Linux Host

Status: generalized X11 support (`file_clipboard`), lazy on-demand chunked streaming (`lazy_clipboard`),
and unified XDND drop (`xdnd_drop`) design specification.
The separately negotiated `file_clipboard` (and `lazy_clipboard`) capability extends the
text/PNG and inbox/outbox contract in [DESIGN.md](DESIGN.md). Both upgraded
ends, explicit per-host consent and the permissions described below are needed.
Live Finder acceptance of lazy `NSPasteboardTypeFileURL` vs. concrete staged `NSURL`
is validated on the macOS client build.

## Requested interaction and consent

Copy files (or large images) in Finder, then Paste into a chosen folder in the Linux
file manager; copy files (or large images) in the Linux file manager, then Paste into
a chosen Finder folder.
The user does not manage an inbox/outbox, run scripts, or choose a transport
folder. Each native file manager performs the final local copy into the folder
the user selected. With `lazy_clipboard`, Copy exchanges metadata only (`file_max`
up to 4 GiB total via 4 MiB chunks); bytes transfer only on Paste (and never on
clipboard-manager probes). It does not forward Cut, folders, symbolic links or special files.

On the upgraded macOS client, open the Linux host card menu and choose
**Approve File Clipboard**. Check the host name in the consent dialog. Keep the
ordinary Clipboard and File Transfer settings enabled. **Revoke File Clipboard**
in the same menu removes approval for that paired host. Approval is tied to the
certificate, so a replacement certificate requires a new approval.

The opt-in setting must clearly say that **Copy of files during the
active connection privately transfers those files to that paired endpoint**.
Wire bytes may move after Copy and before Paste. Paste authorizes the final
destination write. Enabling ordinary text/image clipboard alone must not enable
this behavior. Existing file transfer permissions alone must not silently enable
it either. No directory scanning, background folder synchronization, initial
clipboard replay, or export to the next connected peer is permitted.

This is a clipboard integration, not an access-control boundary against other
applications running as the same local user. Native system clipboards and files
that have already been delivered can be read by those applications. Revocation
stops future SDS requests and removes SDS-owned state; it cannot retract bytes
already copied or a native destination file already created by the user.

## Architecture baseline and clipboard semantics

In the integrated Secure Desktop Stream stack:

- `moonlight-qt/`: `ClipboardItem` and `clipboard_mac.mm` handle UTF-8/PNG, `SdsController` owns session clipboard polling, and `SdsClient` handles mTLS I/O.
- `sunshine/`: `clipboard_backend.h` and `clipboard_x11.cpp` handle text/PNG, while file endpoints confine uploads to the inbox and reads to the outbox.

The inbox/outbox endpoints cannot accept arbitrary source/destination paths without changing their security contract, so native file clipboard uses a separately negotiated feature and scoped offer objects.

The upstream [libfm-qt clipboard implementation](https://github.com/lxqt/libfm-qt/blob/0d67000d8e6491307ff577cd5f224bdc126b0623/src/utilities.cpp#L69) reads `x-special/gnome-copied-files`, then URI lists, and passes the resulting paths to a local file copy/move operation with the selected destination. Its Copy path emits `copy` plus file URIs (compatible with LXQt's `pcmanfm-qt`).

Apple exposes [file URLs through NSPasteboard](https://developer.apple.com/documentation/AppKit/NSPasteboard). Its [file-promise sample](https://developer.apple.com/documentation/appkit/supporting-drag-and-drop-through-file-promises) concerns the dragging pasteboard, which is separate from ordinary Copy/Paste. A promise-provider callback is not evidence of a user Paste; a slow [pasteboard data provider can time out](https://developer.apple.com/documentation/appkit/nspasteboard/data%28fortype%3A%29). Completing private staging (or chunked demand-pull with concrete `NSURL` publication on completion) prevents timeouts against Finder.

## Alternatives and decision

| Approach | Benefit | Decisive problem or condition |
| --- | --- | --- |
| Privately stage at Copy; advertise native local file URLs only after verification | Ordinary native Paste chooses destination; no filesystem extension or paste shortcut hook | Copy transfers bytes, so explicit opt-in and clear disclosure are required; readiness and expiry need UX |
| Delay download inside native pasteboard/file-promise callback | Could avoid early bytes for some consumers | Callback is not reliable Paste intent; blocking network work can time out; drag promises do not prove Finder Copy/Paste support |
| Lazy virtual filesystem/FileProvider or native file-manager extension | Could defer content reads without eager staging | Adds deployment, OS integration, lifecycle, and native permission requirements; still needs application proof |

Select private staging for a first implementation, conditional on the native
acceptance gates. It fits the clarified Copy consent model. Do not add a FUSE
dependency, global keyboard monitoring, AppleScript destination discovery,
filesystem mount, or file-manager patch merely to make the ordinary flow work.

## Proposed transport and object lifecycle

Keep existing mTLS certificate pinning, active-stream authorization, rate limits,
single-peer control policy, and bounded I/O workers. Add a separately negotiated
`file_clipboard` feature and a default-off per-pair user setting. Old peers omit
the feature and keep the existing text/image/file-transfer behavior.

Direction-specific authorization is a conjunction, checked at every operation:

| Direction | Required server permissions | Additional conditions |
| --- | --- | --- |
| Client to Linux host | `clipboard_write` and `file_upload` | Paired active stream; both endpoint feature settings enabled |
| Linux host to Client | `clipboard_read` and `file_download` | Paired active stream; both endpoint feature settings enabled |

Use a fresh unpredictable stream epoch and offer ID. An offer belongs to exactly
one certificate identity, epoch, direction, and source clipboard generation.
Events, retries, chunks, completion, and publication carry those bindings.
Unknown, wrong-client, stale-epoch, expired, or revoked objects return no usable
metadata or bytes. Capability discovery must not advertise usable support before
both platform adapters are available.

Suggested protocol extension, subject to implementation review:

- A source announces an offer manifest containing opaque entry IDs, sanitized
  basenames, sizes, and integrity metadata. No absolute paths, parent paths,
  usernames, remote file URLs, or final destination paths cross the wire.
- Mac-origin offers use new offer-scoped chunk upload/completion operations,
  following the existing upload integrity and resource-budget patterns, but
  publishing only into the hidden clipboard stage rather than the inbox. With
  `lazy_clipboard`, Copy publishes metadata only (`PUT /sds/v1/clipboard-offer`)
  and bytes stream via `chunk_max` (4 MiB) ranges only when Paste is triggered.
- Host-origin offers expose chunk reads only for entries captured from the
  newly copied native selection (files or materialized `0600` stage files for
  large `image/png` clipboard items). They do not expose arbitrary paths supplied
  by an API caller and do not extend the outbox endpoint.
- Only a completely verified offer becomes a native local file clipboard (or
  completes a held on-demand X11/Mac paste request). Publish all entries
  atomically as one generation; never advertise part files.
- New clipboard content, capability revocation, unpair, disconnect, expiry, or
  switching peer cancels transfers and retires the offer. Completion of an old
  transfer must not overwrite a newer local clipboard generation.

State sequence:

`disabled -> watching fresh changes -> offer published -> pull/transferring -> verified
-> native clipboard/paste served -> retired`.

Failure retires the candidate without publishing its paths. Background clipboard
history managers (`qlipper`, `klipper`, `parcellite`, `clipit`, `copyq`, `diodon`,
`xfce4-clipman`, `gpaste-daemon`) must be detected (`_NET_WM_PID`, `WM_CLASS`,
`WM_NAME`/`_NET_WM_NAME`, and parent hierarchy) and refused data targets so they
never trigger background lazy pulls. Non-manager X11 `SelectionRequest`s are held
non-blockingly pending pull completion (`INCR` for large payloads). On macOS,
lazy `NSPasteboardItemDataProvider` backs `NSPasteboardTypePNG` (and
`NSPasteboardTypeFileURL` when accepted by Finder, with concrete chunked-staged
`NSURL` publication as the Finder fallback if AppKit/Finder rejects lazy file URL
promises). On early completion during transfer show progress and `"Files ready —
press Cmd+V"` in the overlay. Do not intercept/replay Paste to compensate for a
file that is still transferring.

At connection/enablement, record the current clipboard generation as a baseline
and ignore it. Require a fresh source selection change after the feature is
active. Do not apply the text clipboard's startup reconciliation to file offers.
Per-offer origin metadata plus local generation/ownership tracking must suppress
echoes. The marker alone is not authority: validate every local staged path and
keep an in-memory association with the offer that SDS actually published.

## Platform adapters and safe file handling

On Mac, read native local file URLs from a fresh Finder Copy selection. On Linux,
enable `file_clipboard` globally across any active X11 display (configured via
`file_clipboard = enabled` or `SDS_FILE_CLIPBOARD=1`, no display `:97`
hardcode), parse local `text/uri-list`, `x-special/gnome-copied-files`, and
`image/png`. Accept local `file` URLs only, with strict URL decoding; reject
remote authorities, alternate schemes, NULs, malformed escapes, and ambiguous
encodings. Never treat a path copied as plain text as a file selection. Reject
Cut/move selections in the first implementation, with a clear message; never
delete the original source.

Phase one supports bounded lists of regular files only (plus lazy `image/png`
offers). Reject the entire offer for directories, bundles, symlinks, special
files, or unsupported metadata rather than silently skipping selected entries.
Directory support is a separate gate: it needs descriptor-relative recursive
traversal, cycle/resource limits, relative manifest validation, and native
acceptance before it can be advertised.

Open each source securely before transfer: resolve symlinks in parent system
directories cleanly (e.g. macOS `/tmp` -> `/private/tmp`) when validating the
parent `O_DIRECTORY`, then open the final file component with `O_NOFOLLOW` so
the leaf file cannot be a symlink. Require user-owned regular files and check
descriptor identity, size, and stable metadata around hashing/reads. An open
descriptor prevents pathname replacement but does not prevent in-place
modification: integrity verification and mutation checks must fail the whole
offer on inconsistent content. Do not retry by opening an unvalidated path. Do
not copy ACLs, execute bits, device metadata, or arbitrary extended attributes
from the sender.

Each receiver owns a private, non-visible application cache subtree (`$XDG_RUNTIME_DIR/sds-clipboard-stage` when free capacity allows, falling back to
disk-backed `appdata/sds-clipboard-stage` for multi-GiB staged files),
partitioned by peer and stream epoch, with mode-0700 real directories and
mode-0600 files (checked via `O_NOFOLLOW`/`fstat`). Verify ownership, no-follow
traversal, and existing-directory replacement on every operation. Enforce per-file,
file-count, aggregate-byte (`file_max` up to 4 GiB with `chunk_max` 4 MiB chunks),
free-space, concurrency, bandwidth, and expiry budgets before allocation and per
chunk. Use exclusive part files and no-replace atomic publication, reject
traversal and ambiguous/colliding basenames, and verify size/hash before
publication.

## Unified Drag-and-Drop (`xdnd_drop`)

Alongside lazy clipboard, dragging local files or images onto the Moonlight
stream window uploads them over `POST /sds/v1/drops`, `PUT /sds/v1/drops/<id>?offset=N`,
and `POST /sds/v1/drops/<id>/complete` carrying normalized `(nx, ny)` coordinates
relative to the rendered desktop rectangle (accounting for letterboxing/pillarboxing).
On Linux X11, Sunshine finds the deepest mapped `XdndAware` child window at `(x, y)`
and drives XDND v5 (`XdndSelection`, `XdndEnter`, `XdndPosition`, `XdndStatus`,
`XdndDrop`, `SelectionRequest text/uri-list`, `XdndFinished`) holding the staged
read-only file lease across completion, falling back atomically (`0600`, no-replace
collision naming) into the host `file_inbox_dir` (`~/Downloads/Moonlight`) when no
target window accepts the drop.

Write Mac quarantine metadata before exposing received files to Finder. Linux
receipts have no execute bits. Never execute, preview, or automatically open
received files. Native Paste is handled by the user's file manager; ordinary
destination collision prompts and permission failures belong to that application,
not a remote overwrite endpoint.

After verification, Mac publishes local staged file URLs through AppKit. Linux
offers local staged URIs through `text/uri-list` and the native `copy` marker;
never advertise a cut marker. These local staging paths stay local and are never
sent back as clipboard text or file offers. Do not fall back to plain-text paths.

Retire only files belonging to this offer, through held directory descriptors.
Clear native clipboard content only when SDS still owns exactly its published
generation; preserve a subsequent user Copy. Cleanup removes SDS clipboard
references first, then staged files. Crash recovery removes only proven-owned
expired session artifacts and must not republish them. An unguessable directory
name alone does not establish ownership.

Native file managers may keep a URL or open descriptor after clipboard ownership
changes. Disconnect/expiry can therefore interrupt a Paste already in progress;
already-open reads or completed destination copies cannot be recalled. The
implementation must document this limit, test safe failure, and avoid claiming
that cleanup revokes already delivered bytes. Do not retain a previous peer's
stage indefinitely to hide this race.

## Phased verification and release gates

| Phase | Required regression/acceptance cases | Completion evidence |
| --- | --- | --- |
| 0: platform feasibility | Isolated AppKit named file-URL round trip; isolated Linux X11 selection URI/marker round trip; correct URL escaping | Mac named pasteboard and isolated native Linux Paste passed; live paired application acceptance remains pending |
| 1: core and protocol | Disabled/old-peer behavior; both permission conjunctions; wrong cert/client/epoch/direction; stale sequence; expiry; revocation during every state; replay/duplicate completion; bounded malformed manifests/chunks | Focused unit tests, mTLS integration tests, clean client/host containing gates; Mac and focused host tests passed; real paired application acceptance is tracked separately |
| 2: filesystem safety | Symlink in each component; file replacement/in-place mutation; FIFO/device/socket; directories rejected; malicious names; newline/percent/Unicode names; duplicate normalized names; disk full; inode/ACL/owner change; hash mismatch; interrupted transfer; crash cleanup | Synthetic filesystem tests prove no escape, overwrite, execution, part publication, or unsafe cleanup |
| 3: lifecycle isolation | Copy before connection ignored; disabled-to-enabled baseline; new Copy supersedes pending transfer; text/image replacement; echo suppression; peer A disconnect then peer B; reconnect epoch; late completion; user clipboard preserved; expiry during native reads | Two-peer automated lifecycle tests plus native synthetic canary, with bytes/metadata asserted not just HTTP status |
| 4: native end-to-end | Finder Copy -> PCManFM-Qt Paste in two chosen directories; reverse direction; zero-byte/multiple/large files; matching hashes; no final file before Paste; early Paste during transfer; collisions; denied destination; canceled Paste; disconnect/expiry during Paste; repeated Paste; clipboard manager present | Isolated real Mac/Linux application interaction, exact build IDs, synthetic hashes and narrowly targeted screenshots; AppKit/URI round trips do not satisfy this gate |
| 5: release | Review opt-in wording and threat model; rerun text/PNG clipboard and inbox/outbox regressions; exact immutable artifacts; serialized approved deploy; repeat phase-4 representative flows | Native feature remains off until all relevant gates pass; report source/build/install/native acceptance separately |

Native testing must preserve unrelated windows, clipboards, and user files by using dedicated synthetic directories and temporary staging. Normal retirement gives an active native paste reader up to 60 seconds before cleanup, subject to a bounded stage cache.

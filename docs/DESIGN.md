# secure-desktop-stream: protocol and design (clipboard, file transfer, microphone)

Status: draft v1 (2026-11-21). This document is the contract between the host fork
(`sunshine/`) and the client fork (`moonlight-qt/` + `moonlight-common-c/`). Change it first,
then the code on both sides.

## 1. Goals and non-goals

Goals: shared clipboard (text and images, both directions), in-stream file transfer (both
directions), microphone passthrough (Mac -> host), all only between a paired client and its
host, only while that client has an active stream, each gated by a per-client permission.

Non-goals: internet/WAN use, relays, more than one simultaneous controlling client, folder
sync, clipboard file lists (copying files via clipboard), audio from host other than the
existing stream.

## 2. Threat model (summary)

| Actor | Can | Must not be able to |
| --- | --- | --- |
| Unpaired LAN device | reach open ports | use any new endpoint, read/write clipboard, drop or read files, inject audio |
| Paired client without an active stream | reach mTLS endpoints | use clipboard / files / mic (all require an active stream of *that* client) |
| Paired client with a stream but without a permission | stream | use the feature the permission guards |
| Paired, permitted, malicious client | send data | escape the drop folder, overwrite files, follow symlinks, fill the disk, exhaust memory, make the host execute anything, read files outside the outbox |
| Malicious host (client side) | send data to the client | write outside `~/Downloads/Moonlight`, overwrite files, exhaust client memory, get files executed without Gatekeeper |

Everything below is designed so that each of those "must not" rows maps to a concrete check
(section 9 lists them; the security review verifies each one).

## 3. Transport decisions

* **Clipboard and files use the paired mTLS HTTPS server (TCP 47984).** It already
  authenticates the client by its pinned certificate, is TLS-encrypted regardless of
  `lan_encryption_mode`, handles large bodies better than the UDP control stream, and can be
  exercised with `curl --cert` in tests. New endpoints live under the `/sds/v1/` prefix and
  are registered **only** on the HTTPS server; the plain HTTP server (47989) returns 404 for
  them.
* **Host -> client notifications use an HTTPS long-poll** (`GET /sds/v1/events`), not a new
  control-stream message. This keeps all clipboard/file traffic on one authenticated
  channel, needs no moonlight-common-c change for these two features, and the host can end
  the poll the moment the stream ends.
* **Microphone uses a new encrypted UDP stream** negotiated over RTSP, because audio needs
  low latency and loss tolerance that TCP long-polls do not give (section 7).

### 3.0 Server constraints that shape the endpoints

Facts from the host source (Sunshine v2026.1120.205658):

* The nvhttp HTTPS server runs on **one asio thread** (`thread_pool_size=1`). A handler that
  blocks stalls `/serverinfo`, `/launch` and every other client. Therefore every `/sds/v1/*`
  handler only validates and enqueues work; disk I/O, hashing and clipboard backend calls run
  on dedicated worker threads that write the response asynchronously (the handler keeps the
  `shared_ptr<Response>`). Long-polls are parked the same way. The host uses two workers:
  `sds` (clipboard backend calls, events, stream lifecycle) and `sds-io` (uploads, outbox
  reads, hashing), so a large file operation never delays clipboard traffic. `sds::stop()`
  runs before the HTTPS server is destroyed and completes every parked response.
* Simple-Web-Server buffers the whole request body before calling the handler, so the
  server-wide `max_request_streambuf_size` caps memory (section 4.3) and uploads are chunked
  at the application level.
* Upstream maps a request to its client certificate through globals written during the TLS
  handshake (`last_verified_client_cert`), which can race between connections. The fork
  replaces that with a per-connection map keyed by the connection's remote endpoint
  (`nvhttp::verified_client_cert(request)`), used by `/launch` and all `/sds/v1/*` handlers.
  Until that lands, the host core keeps an equivalent registry in `src/sds/auth.cpp`
  (`sds::client_cert_pem(request)`), filled right after a successful verify in the TLS
  handshake, keyed by remote and local endpoint, and ignored/purged once the connection object
  is gone.
* The UDP control stream limits messages to 64 KiB and needs fixed-size encoders, which is
  another reason clipboard and files use HTTPS.

### 3.1 Feature discovery

`GET /serverinfo` (HTTPS) gains `<sdsVersion>1</sdsVersion>` and
`<sdsFeatures>clipboard,files,mic</sdsFeatures>` listing what the host build supports and the
admin has enabled globally (host: `clipboard` only when a clipboard backend was created,
`mic` only when the mic module reports a usable sink via `sds::set_mic_available()`; paired
HTTPS responses additionally advertise `host_encoder`, `host_resolution`, and when enabled/available
`file_clipboard`, `lazy_clipboard`, `xdnd_drop`; the plain-HTTP `/serverinfo` carries none of
these elements). Paired HTTPS `/serverinfo` also includes `<sdsEncoders>` (available host
encoders e.g. `vaapi,software`), `<sdsAdapters>` (enumerated render devices with `<ID>`,
`<Name>`, `<Default>`), and `<sdsSoftwareCodecModeSupport>` (software encoder codec bitmask so
clients know YUV 4:4:4 support when overriding to software). `/launch` and `/resume` accept
paired session override query parameters (`sdsEncoder`, `sdsAdapter`, `sdsHevc`, `sdsMatchRes`,
`sdsRevertRes`) which apply only for that session and revert cleanly when the stream ends. The
client only offers features listed there. The authoritative, per-client answer comes from
`GET /sds/v1/capabilities` (section 4.2).

Client: it never sends a `/sds/v1/*` request without the server certificate pinned at pairing.
Pinning is strict: the TLS CA list is only the pinned certificate, TLS errors are ignored only
when every error names that certificate, and the peer certificate is compared byte for byte
again once the connection is encrypted. A mismatch stops clipboard and file transfer for the
session.

## 4. Common rules for `/sds/v1/*`

### 4.1 Authorization pipeline (every request, in this order)

1. Request arrived on the HTTPS server and the TLS client certificate verified against the
   paired-client store (existing nvhttp verify callback). Otherwise the connection is
   rejected before HTTP.
2. Map certificate -> paired client record (uuid). Unknown -> `401`.
3. Global feature switch in `sunshine.conf` enabled (`clipboard`, `file_transfer`,
   `mic_passthrough`). Disabled -> `404` (feature not present).
4. The client has an active stream session (the session was launched/resumed by this same
   client certificate and has not ended). None -> `409 {"error":"no_active_stream"}`.
5. The per-client permission for this operation is granted. Otherwise `403`.
6. Per-client rate limit / concurrency limit. Exceeded -> `429` with `Retry-After`.
7. Size limits (section 4.3). Exceeded -> `413`.

Only after all seven checks does any clipboard/file code run. The checks live in one function
(`sds::authorize(request, permission)`) so that no handler can skip one.

Host details: a missing verified certificate (step 1) or a certificate without exactly one
enabled paired record (step 2, also after an unpair/disable on a kept-alive connection) gives
`401 {"error":"unauthorized"}`. Before the pipeline, the dispatcher answers an unknown path under
`/sds` with `404 not_found`, a known path with the wrong method with `405 bad_request`, and a
request with a repeated query parameter with `400 bad_request`. On the plain HTTP server every
method on `/sds...` gets `404` without reaching any sds code.

### 4.2 Permissions

Per paired client, stored with the client record in `sunshine_state.json`:

| Permission | Meaning | Default for newly paired clients |
| --- | --- | --- |
| `clipboard_read` | client may read the host clipboard (host -> client) | off |
| `clipboard_write` | client may set the host clipboard (client -> host) | off |
| `file_upload` | client may drop files into the host inbox | off |
| `file_download` | client may list and download files from the host outbox | off |
| `mic` | client may send microphone audio | off |

The admin toggles them per client in the web UI (Clients page) or via
`POST /api/clients/permissions` on the admin API. `config.sds_default_permissions`
(comma-separated list, default empty) changes the default for new pairings.

Host details: `POST /api/clients/permissions` takes `{"uuid":"...","permissions":[...]}`
(admin authentication and CSRF like the other client endpoints), rejects unknown names with
`400` and answers `{"status":true,"permissions":[<canonical order>]}` (`status:false` for an
unknown uuid). `GET /api/clients/list` includes each client's `permissions`. The state file
stores a `permissions` array per client; unknown names are dropped on load, a missing array
means `sds_default_permissions`, an explicitly empty one stays empty. A change takes effect on
the next request; a streaming client additionally gets a `capabilities` event, revoking
`file_upload` deletes its open uploads, and clipboard watching is re-evaluated.

`GET /sds/v1/capabilities` returns, for the calling client:

```json
{
  "version": 1,
  "features": ["clipboard", "files"],
  "permissions": ["clipboard_read", "clipboard_write", "file_upload"],
  "limits": {
    "clipboard_text_max": 1048576,
    "clipboard_image_max": 16777216,
    "file_max": 4294967296,
    "chunk_max": 4194304,
    "uploads_max_concurrent": 2
  },
  "stream_active": true
}
```

`capabilities` requires steps 1-4 of 4.1 but no permission. So does `events` (4.5); the host
only enqueues events the client is permitted to see. `features` lists the features enabled
and available on the host; `permissions` lists only granted permissions whose feature is in
`features`. `capabilities` is `404` when no feature is available, `events` when neither
clipboard nor files is.

Client rules: any `version` other than 1 disables the features. Every limit is clamped to the
client's own caps (`clipboard_text_max` 16 MiB, `clipboard_image_max` 64 MiB, `chunk_max`
16 MiB, `file_max` 64 GiB) so a host cannot make the client allocate unbounded memory.
`stream_active: false` is treated like `409 no_active_stream`.

### 4.3 Limits (host config keys, defaults)

| Key | Default | Notes |
| --- | --- | --- |
| `clipboard_text_max` | 1 MiB | UTF-8 bytes |
| `clipboard_image_max` | 16 MiB | PNG bytes |
| `clipboard_rate` | 10/s | per client, both directions |
| `file_max` | 4 GiB | per file |
| `file_chunk_max` | 4 MiB | request body cap for upload chunks and download ranges |
| `file_uploads_max_concurrent` | 2 | open upload sessions per client |
| `file_min_free_space` | 1 GiB | refuse uploads that would leave less free space |
| `file_upload_idle_timeout` | 120 s | idle upload sessions are discarded with their `.part` file |

The HTTPS server's maximum request buffer is set to
`max(file_chunk_max, clipboard_image_max, clipboard_text_max) + 64 KiB` (a clipboard PNG of up
to 16 MiB must fit in one PUT, which is larger than a 4 MiB chunk). A request announcing a
larger body is refused before the body is read: Simple-Web-Server then closes the connection
without sending a response (its own 413 is never written). Smaller bodies that exceed the
operation's limit (step 7: chunk > `file_chunk_max`, clipboard text/PNG above its limit,
anything above 64 KiB on endpoints without a payload, a download `length` > `file_chunk_max`)
get `413 too_large`.

Config syntax: sizes are a byte count or a binary suffix (`64K`, `4M`, `4 MiB`, `1G`, `1T`);
`clipboard_rate` accepts `10` or `10/s` (1..1000); `file_upload_idle_timeout` accepts `120` or
`120s` (10..86400); `file_chunk_max` 64 KiB..32 MiB, `clipboard_text_max` up to 16 MiB,
`clipboard_image_max` up to 64 MiB, `file_uploads_max_concurrent` 1..16. Out-of-range or
malformed values are ignored with a warning. `file_inbox_dir`/`file_outbox_dir` must be
absolute; the switches `clipboard`, `file_transfer`, `mic_passthrough` default to enabled, while
`file_clipboard` defaults to disabled (or enabled when `SDS_FILE_CLIPBOARD=1`).

### 4.4 Errors

JSON body `{"error": "<code>", "message": "<human text>"}` with the status codes above.
Codes: `no_active_stream`, `forbidden`, `too_large`, `rate_limited`, `bad_request`,
`not_found`, `conflict`, `insufficient_space`, `unsupported_type`, `internal`.

* `insufficient_space` is sent with status `507`.
* Host additions: `unauthorized` (`401`, steps 1-2), `mismatch` (`422`, upload size or SHA-256
  mismatch), `405` uses `bad_request`, `410` (stale clipboard seq) uses `conflict`, and `503`
  with `internal` is returned while the host shuts down. Every response carries
  `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.
* Two different `409`s exist (`no_active_stream` and the upload offset `conflict`); clients
  distinguish them by `error`.
* Transport: HTTP/1.1, keep-alive allowed. Every request with a body carries `Content-Length`
  (no chunked request bodies). The host never redirects and the client never follows
  redirects.

### 4.5 Event stream (long-poll)

```
GET /sds/v1/events?after=<last seen id>&timeout=<seconds, 0..30, default 25>
-> 200 {"events":[{"id":7,"type":"clipboard","seq":3,...},{"id":8,"type":"outbox","count":2}],
        "last_id":8}
```

* Event ids are per client and per stream session, start at 1 and increase by 1. `after=0`
  returns every retained event. If events with `id > after` exist the host answers at once;
  otherwise it parks the request for up to `timeout` seconds and then answers
  `{"events":[],"last_id":<newest id>}`. `timeout=0` never parks.
* The host retains at least the last 64 events per client and parks at most one poll per
  client (a new poll completes the older one with an empty list).
* Event types: `clipboard` (5.3), `outbox` (6.3), `clipboard_offer` / `clipboard_pull` (6.6),
  `stream_ended` (the stream ended: a parked poll completes immediately, later requests get
  `409`), and optionally `capabilities` (permissions or limits changed; the client refetches
  `capabilities`). Clients ignore unknown types.
* If `last_id` is smaller than the client's `after` (numbering restarted), the client resets
  `after` to 0.
* Client behaviour: one outstanding poll; `409`, transport errors and `5xx` -> exponential
  backoff 1 s .. 10 s; `429` -> `Retry-After` (capped at 30 s); `401`/`403`/`404` -> features
  off for the rest of the session; stop on `stream_ended`. A `200` that brings no new event
  less than 1 s after a long poll was sent is treated like an error (backoff), so a misbehaving
  host cannot make the client spin.
* Host details: `last_id` is the newest id assigned in the current stream session (0 before
  the first event). `timeout` above 30 is clamped to 30; a non-numeric `after` or `timeout` is
  `400`. A poll whose `after` is greater than `last_id` is answered at once with an empty list.
  Events are coalesced per type: a newer `clipboard`, `outbox` or `capabilities` event replaces
  the retained older one of the same type, so ids can have gaps. The `stream_ended` event takes
  the next id. When the host shuts down, parked polls complete with `stream_ended`. Retained
  events, ids and the parked poll are discarded when the stream ends.

## 5. Shared clipboard

### 5.1 Data model

The clipboard is a single item with one or both representations:

* `text/plain;charset=utf-8` — must be valid UTF-8, NUL bytes rejected.
* `image/png` — must start with the PNG signature and pass a header sanity check
  (width*height*4 <= 256 MiB) before any decoder sees it.

Each side keeps a monotonically increasing `seq` for its own clipboard. The host's `seq`
increments on every host clipboard change it observes (including ones made by the client).

### 5.2 Client -> host

```
PUT /sds/v1/clipboard
Content-Type: text/plain;charset=utf-8 | image/png
X-SDS-Client-Seq: <client seq>
<body>
-> 204, X-SDS-Host-Seq: <new host seq>
```

The host sets its clipboard to exactly that content (one representation per PUT; a second
PUT with the other type within 500 ms and the same `X-SDS-Client-Seq` adds that
representation to the same item). The host remembers `(host seq, origin=client)` so it does
not echo the change back as an event to the same client.

### 5.3 Host -> client

The host emits `{"type":"clipboard","seq":N,"types":["text/plain","image/png"],"sizes":{...}}`
on the event stream when its clipboard changes and the client holds `clipboard_read`. The
client fetches eagerly:

```
GET /sds/v1/clipboard?seq=N&type=text/plain   (or image/png)
-> 200 body,  X-SDS-Host-Seq: N
-> 410 if the clipboard has changed again since N (client waits for the next event)
```

Changes the host made because of a client PUT are not announced to that client.

Host details: `seq` is optional (absent = the current item). `404 not_found` when the item has
no such representation; `410` carries the current `X-SDS-Host-Seq`. A host clipboard that
became empty (or holds only unsupported formats) increments `seq` but is not announced.
Content read from the backend is validated again (5.1) and invalid or oversized
representations are dropped. A change the backend reports for content equal to the last
client PUT is treated as an echo of that PUT and ignored.

PUT errors: missing or non-numeric `X-SDS-Client-Seq`, invalid UTF-8, NUL, bad PNG header or a
decoded size above 256 MiB -> `400 bad_request`; above the configured limit -> `413`; another
media type or a charset other than UTF-8 -> `415 unsupported_type`; backend write failure ->
`500` (the clipboard is unchanged). A coalesced second representation (5.2) produces a new host
`seq`; other clients get one event listing both types.

Client rules: a type whose announced size exceeds the client's limit is not fetched; every
body is validated (5.1) before use; a body whose `X-SDS-Host-Seq` is missing or differs from
the requested `seq` is discarded; the types of one item are fetched one after the other (text, then image)
and a newer `clipboard` event supersedes an item still being fetched. `GET` takes
`type=text/plain` or `type=image/png`.

### 5.4 When syncing happens

Only while the stream is active. Client side: poll `NSPasteboard.changeCount` every 300 ms
while the stream window exists (macOS has no change notification); push on change, unless the
content equals the last content synced in either direction. The host watches its clipboard
only while at least one permitted stream is active.

Start sequence (host wins if both sides have content):

1. The client fetches `capabilities`.
2. When a client's stream session starts and the client holds `clipboard_read`, the host
   enqueues one `clipboard` event for its current clipboard (if not empty) as the first event
   of that session. The client's first poll is immediate (`after=0&timeout=0`) and sees it.
3. If that poll contained a `clipboard` event, the client fetches and applies it and does not
   push its own clipboard. Otherwise the client pushes its current clipboard once (if
   `clipboard_write`).
4. The client continues with the long-poll (4.5).

A host that does not enqueue the initial event degrades to "client pushes its clipboard".

Host details: the backend is started while at least one streaming client holds
`clipboard_read` or `clipboard_write` (writing needs a running backend to own the selection)
and stopped when none is left; stopping releases clipboard ownership and drops the cached
content. The initial event of step 2 is enqueued from the session-start notification; a first
poll that arrives before it simply sees no event (the client then pushes).

### 5.5 Host backends

| Host | Backend | Notes |
| --- | --- | --- |
| Windows | Win32 clipboard: message-only window + `AddClipboardFormatListener`; text via `CF_UNICODETEXT`; images read from `PNG` registered format or `CF_DIBV5`/`CF_DIB`, converted to PNG with WIC; written as both `PNG` and `CF_DIB` | Runs in the Sunshine process inside the user session on `WinSta0\Default` |
| Linux X11 (LXQt) | Own X11 connection on a dedicated thread; XFixes `SelectionNotify` for change detection on `CLIPBOARD`; serves `TARGETS`, `UTF8_STRING`, `text/plain;charset=utf-8`, `image/png`; INCR for large transfers both ways | `DISPLAY` / `XAUTHORITY` from the session environment |
| Linux GNOME 50 Wayland | `org.freedesktop.portal.Clipboard` on the RemoteDesktop session `portalgrab.cpp` creates: `RequestClipboard` before `Start`, `SelectionOwnerChanged` for change detection, `SelectionRead`/`SelectionWrite` fds for data, `SetSelection` to offer client content | No extra consent dialog: rides on the existing session. If capture does not use the portal (e.g. KMS), the clipboard is unavailable on GNOME and `capabilities` omits it |

### 5.6 Client backend (macOS)

`NSPasteboard generalPasteboard`: text via `NSPasteboardTypeString`; images: read
`NSPasteboardTypePNG`, else `NSPasteboardTypeTIFF` converted to PNG with
`NSBitmapImageRep`; write PNG (and TIFF for apps that only read TIFF). The client records the
`changeCount` it produced so it does not push host content back.

## 6. File transfer

### 6.1 Host folders

* Inbox (client -> host): `file_inbox_dir`, default `~/Downloads/Moonlight` of the logged-in
  user (Windows: the user's `FOLDERID_Downloads\Moonlight`).
* Outbox (host -> client): `file_outbox_dir`, default `~/Downloads/Moonlight/Outbox`. The host
  user puts files there to send them to the Mac.

Both are created on first use with mode `0700` (Windows: protected private DACL),
owned by the session user. At startup and before each operation the host verifies that the
directory is a real directory owned by the user, not a symlink/reparse point.

Host details: the check applies to the final path component (a symlinked `~/Downloads` above
it is allowed). POSIX additionally refuses a folder writable by group or others and requires
`st_uid == geteuid()`. Windows accepts the session user or `BUILTIN\Administrators` as owner,
keeps the folder handle open without `FILE_SHARE_DELETE` and re-checks its final path.
Windows directories and existing files must also have an inspectable DACL without mutation
grants to untrusted principals; NULL DACLs are refused. Newly created objects grant access
only to the session user, SYSTEM and Administrators. Client macOS directories and part files
are checked through their descriptors for extended ACL mutation grants as well as mode bits;
inherited grants to another user cannot bypass mode `0700`/`0600`. Default
folders are resolved at use time (Linux: `XDG_DOWNLOAD_DIR` from the environment or
`user-dirs.dirs`, else `~/Downloads`; Windows: `FOLDERID_Downloads` of the console user's
token, refused when running as SYSTEM without a logged-on user). A refused folder makes the
operation fail with `500 internal`.

### 6.2 Client -> host upload (chunked, resumable)

```
POST /sds/v1/files/uploads
Content-Type: application/json
{"name": "report.pdf", "size": 1234567, "sha256": "<hex>"}
-> 201 {"id": "<128-bit random hex>", "chunk_max": 4194304, "offset": 0}

PUT /sds/v1/files/uploads/{id}?offset=<n>
Content-Type: application/octet-stream
<= chunk_max bytes
-> 200 {"offset": <n + len>}
-> 409 {"error":"conflict","offset":<expected>} if offset != current offset

POST /sds/v1/files/uploads/{id}/complete
-> 201 {"name": "report (1).pdf", "size": 1234567}   (final name after collision handling)
-> 422 if size or sha256 mismatch (the .part file is deleted)

DELETE /sds/v1/files/uploads/{id}
-> 204 (cancel; .part file deleted)
```

Host rules:

* `name` is sanitized (6.4). The data goes to `.<id>.part` inside the inbox, opened with
  `O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC`, mode `0600`, relative to an inbox directory fd
  (`openat`). Windows: `CreateFileW(CREATE_NEW, FILE_FLAG_OPEN_REPARSE_POINT)` under the
  user's impersonated token.
* `complete` verifies size and SHA-256, then links the part file to the first free name
  (`name`, `name (1)`, ... `name (999)`) with `renameat2(RENAME_NOREPLACE)` (fallback
  `linkat`+`unlinkat`); never overwrites an existing file.
* Received files are never executed or opened. No execute bit on Linux. On Windows the
  `Zone.Identifier` alternate data stream is written and flushed on the part file (`ZoneId=3`)
  before publication. A marking failure cancels publication and removes the part file.
* Upload sessions belong to the client that created them, die with the stream, and are
  removed after `file_upload_idle_timeout`.

Host details:

* create: invalid JSON, missing fields, negative `size`, `sha256` not 64 hex digits (either
  case) or a name rejected by 6.4 -> `400`; `size > file_max` -> `413`; more open sessions than
  `file_uploads_max_concurrent` -> `429` (`Retry-After: 1`); free space minus
  `file_min_free_space` smaller than `size` -> `507`.
* chunk: missing or non-numeric `offset` -> `400`; an id that does not exist **or belongs to
  another client** -> `404` (never `403`, so ids are not confirmed); data beyond the declared
  size or above `file_chunk_max` -> `413`; free space checked again per chunk -> `507`; an empty
  body just returns the current offset. Data is written through the open part-file descriptor
  and hashed incrementally, so `complete` is O(1).
* complete: called before all bytes arrived or with a wrong hash -> `422 mismatch` (part file
  deleted); all names up to `name (999)` taken -> `409 conflict` (part deleted); inbox replaced
  or part file swapped for another file -> `500` (part deleted, nothing renamed). Final files
  are `0600`.
* Part files left by a previous run (`.<32 hex>.part`) are removed when the inbox is first
  opened. Sessions also end when `file_upload` is revoked or the client is unpaired/disabled.

Client rules:

* The create request needs `sha256`, so the client hashes the file in a first pass, then
  uploads. It uploads one file at a time (any `uploads_max_concurrent` >= 1 works).
* Chunk size = min(capabilities `chunk_max`, create response `chunk_max`, 16 MiB). Every PUT
  carries `Content-Length`.
* On a network error the client resends the same offset (up to 5 tries with backoff). A
  `409 conflict` whose `offset` equals `offset + len` means the chunk had arrived; any other
  `offset` in `[0, size]` is resumed from.
* The client also hashes the bytes the host acknowledged, in order; if that differs from the
  first pass (file changed while sending) it sends `DELETE` instead of `complete`. After a
  resend from an earlier offset this hash is incomplete and the host's check at `complete`
  decides (`422`).
* `complete` is retried up to 3 times on transport errors and `5xx`; a `404` after such a retry
  is reported as "sent but not confirmed".
* Zero-byte files go straight from create to `complete`.

### 6.3 Host -> client download (outbox)

```
GET /sds/v1/files/outbox
-> 200 {"files":[{"id":"<hex>","name":"photo.jpg","size":123,"mtime":1763700000}]}

GET /sds/v1/files/outbox/{id}?offset=<n>&length=<m>      (m <= chunk_max)
-> 200 application/octet-stream, X-SDS-File-Size, X-SDS-File-Sha256 (on offset 0 only)
-> 404 if the id no longer matches a file
```

Listing contains only regular files directly in the outbox (no recursion, no symlinks, no
hidden files, no special files). `id` = first 128 bits of
`HMAC-SHA256(per-boot key, name | size | mtime_ns | inode)`, so it changes when the file
changes and cannot be used to name arbitrary paths. Reads open the file with
`O_NOFOLLOW|O_NONBLOCK` via `openat` on the outbox fd and re-check `fstat` against the listed
size/mtime/inode.

The host emits `{"type":"outbox","count":N}` when the outbox content changes (polled every
2 s while a permitted stream is active).

Host details: the listing is sorted by name and capped at 1000 entries; besides the rules
above it skips names that are not valid UTF-8 and (POSIX) files not owned by the session user,
(Windows) files with the hidden or system attribute. `length` defaults to `file_chunk_max`;
`offset` beyond the size -> `400`; `offset` equal to the size -> `200` with an empty body. The
SHA-256 is computed once per id on the first offset-0 read and cached (single `sds-io` worker:
hashing a very large file delays other file operations). The change detection baseline is taken
when the first downloader's stream starts, so files already present then are not announced;
the client can list them explicitly.

Client rules: an offset-0 response must carry `X-SDS-File-Size` equal to the listed size and a
64-hex-digit `X-SDS-File-Sha256`, otherwise the download fails (no unverifiable files). A
response with more body bytes than requested is aborted. Entries whose `id` is not 32
lowercase hex characters are ignored, and at most 1000 entries per listing are considered.
For a zero-byte file the client requests `offset=0&length=<chunk_max>` and expects an empty
body. Each range (at most `chunk_max`, i.e. at most 16 MiB) is held in memory and written and
hashed only once it is complete; a short or failed range is requested again (up to 5 tries).
Per session the client queues at most 1000 downloads, tracks at most 10000 ids and runs at most
one automatic listing every 2 s (outbox events are coalesced).

### 6.4 File name sanitization (both sides)

Reject or rewrite:
* not valid UTF-8, empty, longer than 200 bytes, `.` or `..`;
* any of `/ \ : * ? " < > |`, NUL, and C0/C1 control characters -> `_`;
* leading `.` or `-` -> `_` (no hidden files, no option-like names);
* trailing `.` or space removed (Windows);
* Windows reserved device names (`CON PRN AUX NUL COM1-9 LPT1-9`, with any extension) -> prefixed with `_`;
* Unicode normalized to NFC (macOS sends NFD).

Client implementation (`filesanitize.cpp`), in this order: reject invalid UTF-8 and unpaired
surrogates; NFC; reject empty, `.` and `..`; replace the characters above plus DEL (U+007F)
and the Unicode bidi controls (U+061C, U+200E, U+200F, U+202A-U+202E, U+2066-U+2069, which can
disguise an extension) with `_`; strip trailing dots and spaces; leading `.` or `-` -> `_`;
reserved device names (also `COM¹²³`/`LPT¹²³`) -> `_` prefix; a name longer than 200 bytes is
shortened on a code point boundary, keeping an extension of up to 32 bytes (rewritten, not
rejected); an empty result is rejected. Hosts should apply the bidi rule as well.

Host implementation (`sds::files::sanitize_file_name`): the same rules in the same order,
including DEL, the bidi controls, `COM¹²³`/`LPT¹²³` and `CONIN$`/`CONOUT$`; a reserved stem is
compared without trailing spaces (`NUL .txt` -> `_NUL .txt`). NFC uses tables generated from
the Unicode database (`scripts/generate_sds_nfc_data.py`). Collision names split at the last
dot like the client (`archive.tar (1).gz`).

### 6.5 Client side

* **Send:** drag files onto the stream window (`SDL_DROPFILE`). Directories are rejected with
  an overlay message (no recursive send in v1). The client streams the file from disk in
  `chunk_max` pieces, computes SHA-256 while reading, retries a chunk on network error from
  the server-reported offset, and shows progress in the stream overlay.
* **Receive:** on an `outbox` event (or hotkey `Ctrl+Alt+Shift+O`; `D` is Moonlight's
  existing minimize hotkey), the client downloads every
  outbox file it has not downloaded in this session to `~/Downloads/Moonlight/` using the same
  sanitizer, `O_EXCL` + collision renaming, `.part` + rename on completion, SHA-256 check, and
  sets the `com.apple.quarantine` extended attribute so Gatekeeper checks the file before it
  is opened. Auto-download is a client setting (default on when the permission is granted).
* **Download folder details:** the folder is created with mode `0700`, refused if it is a
  symlink, not a directory or not owned by the user, and opened with `O_NOFOLLOW`; every file
  operation is relative to that directory fd. The part file is `.<128-bit random hex>.part`
  (`O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC`, `0600`). After the SHA-256 check the client sets
  `com.apple.quarantine` = `0081;<hex unix time>;Moonlight;<UUID>` and mode `0644` on the part
  file, then moves it with `renameatx_np(RENAME_EXCL)` (`linkat` + `unlinkat` where the
  filesystem lacks it) to `name`, `name (1)`, ... `name (999)` (split at the last dot). A file
  whose quarantine attribute cannot be set is deleted, never kept. Downloads run one at a time; a download that would leave less than
  1 GiB free is refused; part files older than a day are removed; an id that failed is only
  retried when the user presses the hotkey.

### 6.6 Lazy clipboard offers, chunked streaming & unified drag-and-drop

When `file_clipboard` / `lazy_clipboard` is enabled (permission check `clipboard_write` +
`file_upload` for client -> host; `clipboard_read` + `file_download` for host -> client):

* **Client -> Host lazy offer:** On local file Copy (or large PNG), client opens sources
  safely (canonical parent `O_DIRECTORY` + `O_NOFOLLOW` leaf), announces metadata only via
  `PUT /sds/v1/clipboard-offer` (offer id, entries, `kind` `"files"` or `"image"`, sanitized
  names, sizes). No bytes move until paste.
* **Host clipboard manager guard & X11 hold:** On X11, background clipboard managers
  (`qlipper`, `klipper`, `parcellite`, `clipit`, `copyq`, `diodon`, `xfce4-clipman`,
  `gpaste-daemon`) are refused data targets with `property = None` so they never trigger lazy
  pulls. A non-manager `SelectionRequest` triggers `clipboard_pull` (`{offer_id, targets}`),
  causing the client to stream each entry in `chunk_max` (4 MiB) chunks (`POST .../entries/<e>`,
  `PUT .../entries/<e>?offset=N`, `POST .../complete`), verified via SHA-256 into a private
  `0700`/`0600` stage (`$XDG_RUNTIME_DIR/sds-clipboard-stage` when free space permits, else
  `appdata/sds-clipboard-stage`) before serving `x-special/gnome-copied-files`, `text/uri-list`,
  or `image/png` (`INCR` for large payloads).
* **Host -> Client lazy offer:** Host stages/captures copied files (or materializes copied PNG
  to a private `0600` stage file) and emits a `clipboard_offer` event. On Mac paste demand
  (via lazy `NSPasteboardItemDataProvider` for PNG / Finder-tested file URLs, or concrete
  staged `NSURL` fallback on chunk completion if Finder rejects lazy `NSPasteboardTypeFileURL`),
  client downloads `GET /sds/v1/clipboard-offer/<offer>/entries/<entry>?offset=N&length=M`
  (checking `X-SDS-File-Sha256`) into quarantined `0600` files.
* **Unified Drag-and-Drop (`xdnd_drop`):** Dragged files/images upload via `POST /sds/v1/drops`
  (carrying normalized `[0,1]` coordinates relative to the rendered video rect), `PUT /sds/v1/drops/<id>?offset=N`,
  and `POST /sds/v1/drops/<id>/complete`. Host drives X11 XDND v5 at the deepest `XdndAware`
  window under the mapped pointer coordinates and falls back atomically to `file_inbox_dir`
  (`~/Downloads/Moonlight`) when unaccepted.

## 7. Microphone passthrough

Prior art (moonlight-common-c PR #123, moonlight-qt PR #2095, closed Sunshine PR #4078) uses
AES-128-CBC without authentication and, in #123, fails the whole RTSP handshake when the host
does not know the mic stream. We follow what the Sunshine reviewers asked for in #4078
instead: advertise in SDP, a dedicated UDP port at offset 13 (48002), AES-GCM like the
control stream, no control-stream changes.

### 7.1 Negotiation

* Host advertises support in the RTSP DESCRIBE SDP with a new bit in
  `x-ss-general.featureFlags`: `SS_FF_SDS_MIC = 0x10000000` (high bit range to avoid
  upstream collisions; common-c: `LI_FF_SDS_MIC`), only when `mic_passthrough` is enabled, a
  virtual mic sink can be created right now, and the client (identified by its paired
  certificate) holds the `mic` permission.
* The client opts in with `STREAM_CONFIGURATION.enableMicrophone` and sends
  `SETUP streamid=mic/0/0` **only if that bit is present** (and the host is Sunshine), after
  the control SETUP and before ANNOUNCE (ANNOUNCE allocates the host stream session). Stock
  hosts never see it. A failed, non-200 or malformed SETUP (missing `server_port` or a ping
  payload that is not exactly 16 characters; there is no well-known fallback port) is logged
  and the stream continues without mic; the handshake never fails because of the mic.
* Host answers with `Transport: server_port=<base+13>` (48002 by default, UDP) and
  `X-SS-Ping-Payload: <16 hex chars>`. The mic payload is generated per launch session at the
  first mic SETUP (8 random bytes, hex) and is **distinct from the audio/video ping payload**.
  A host that does not advertise the bit for this client answers the SETUP with 404 as before.
* The client sends `SS_PING` (16-byte payload + 4-byte big-endian counter, 20 bytes) from the
  same UDP socket it later sends mic packets from: the first ping immediately when the mic
  stream starts, then every 500 ms until the first mic packet, then every 5 s.
* The host binds the UDP source endpoint (address **and port**) of the first valid ping, and
  only if the ping's source address equals the RTSP client's address (IPv4-mapped IPv6 is
  normalized). A ping from another endpoint never rebinds. Data packets are routed by the bound
  endpoint; packets from any other source, or before the binding, are dropped without
  decryption. (An on-path attacker can race the binding, which only denies the mic: data must
  still authenticate.)
* The host opens the mic UDP socket only while at least one mic session is running and closes
  it after the last one ends (not with the other stream sockets).
* Client lifecycle (common-c): the mic stream starts after the input stream, i.e. once the
  connection is established, outside the stage machine (failure only disables the mic);
  `LiStopConnection()` stops it first. `LiIsMicrophoneStreamActive()` reports whether it runs.

### 7.2 Packets

Client -> host UDP datagrams, one Opus frame each, <= 1400 bytes:

```
struct sds_mic_header {      // 12 bytes, big-endian, authenticated as GCM AAD
  uint8_t  version;           // 1
  uint8_t  flags;             // 0 (reserved, must be 0)
  uint16_t reserved;          // 0 (must be 0)
  uint32_t sequence;          // starts at 0, +1 per packet, never wraps (mic stops at 2^32-1)
  uint32_t timestamp;         // 48 kHz sample clock of the first sample in the frame
};
// followed by: uint8_t tag[16]; uint8_t ciphertext[];   (AES-128-GCM over the Opus frame)
```

* Key: the session `rikey` (same key the control stream uses).
* IV (12 bytes): `sequence` as u32 little-endian in bytes 0-3, bytes 4-9 zero, byte 10 `'C'`
  (client to host), byte 11 `'M'` (mic). Control uses `'C'`/`'H'` + `'C'`, RTSP `'R'` and
  video `'V'` in byte 11, so IVs never collide across streams under the same key.
* Sizes: Opus payload 1..1372 bytes (so the datagram is 29..1400 bytes); exactly 20-byte
  datagrams are pings.
* Timestamp: `sequence * 960` while frames flow; after a send gap longer than 100 ms (mute,
  capture stall) the client advances it by the elapsed wall-clock time in whole frames. The
  host orders and conceals by `sequence` only; the timestamp is informational.
* Host checks, in this order (cheapest first, nothing is decrypted before 1-4):
  1. session active (stream running, `mic_passthrough` on, permission held; re-checked every
     second, and a session switched off is never re-enabled within the stream),
  2. source endpoint == bound endpoint,
  3. token bucket: 200 packets/s sustained, burst 40,
  4. size, version, flags and reserved field,
  5. replay window: 128 packets, sequence older than the window or already accepted is
     dropped (the window is committed only after authentication),
  6. GCM tag over header (AAD) and ciphertext.
* Opus: 48 kHz, mono, 20 ms frames (960 samples), `OPUS_APPLICATION_VOIP`, 48 kbit/s VBR,
  in-band FEC on (expected loss 10 %), DTX off. Frames longer than 20 ms are not decoded
  (silence).
* Test vectors (key `00 01 .. 0f`), shared by `moonlight-common-c/tests/sds_mic_test.c` and
  Sunshine `tests/unit/test_sds_mic.cpp`, cross-checked with Python `cryptography`:
  * seq 0, ts 0, payload `f8 ff fe` ->
    `01000000 00000000 00000000 | 1c3427e561cd56a123ba6e514a2d15b1 | a893dc`
  * seq 0x01020304, ts 0x0a0b0c0d, payload `00 01 .. 1f` ->
    `01000000 01020304 0a0b0c0d | 4c180803f566cf29ccb2a83d0cb0ebbc |
    dac1cd4df23f801c45084659309aaca9a22a068cc4fbb05fcd6ad7b755f02d20`

### 7.3 Host side

* Jitter buffer keyed by sequence: playout starts or resumes after 7 frames are queued and
  trims the span from the playout cursor to the newest frame to 12 frames (240 ms of encoded
  audio). macOS can deliver five 20 ms frames as a burst, so these bounds leave room for
  the next burst and its arrival jitter. The hard 64-packet storage limit still applies.
  For a gap, the decoder uses the next packet's in-band FEC where possible, or Opus PLC,
  and stops after 5 consecutive concealed frames (100 ms). A 20 ms playout thread decodes
  into the sink; the sink's ring buffer needs 40 ms before it starts reading (and again
  after an underrun) and keeps at most 200 ms (oldest dropped).
* Linux: a PipeWire stream with `media.class=Audio/Source` named "Moonlight Microphone"
  (`node.name=sunshine-mic`, S16 mono 48 kHz, `node.latency=960/48000`, connected like
  module-loopback's playback stream) on its own thread loop, created at mic start and destroyed
  at stream end. Fallback when no PipeWire daemon is reachable but PulseAudio is:
  `module-null-sink sink_name=sunshine_mic_sink` + `module-remap-source
  master=sunshine_mic_sink.monitor source_name=sunshine-mic` loaded and unloaded by the mic
  code's own PulseAudio context, fed by a playback stream into the null sink.
* Windows: render with WASAPI (shared mode, 48 kHz mono S16 with auto-conversion) into the
  playback side of a loopback cable whose capture side apps use as a microphone: "CABLE Input"
  (VB-CABLE), else a "Steam Streaming Microphone" render endpoint. `mic_device` (name substring
  or endpoint ID) overrides the choice and disables the automatic fallback. We ship no kernel
  driver; without such a device the host does not advertise `SS_FF_SDS_MIC` and
  `capabilities` omits `mic`.
* All mic state (binding, replay window, jitter buffer, sink, and the socket after the last
  session) is torn down when the stream session is joined; packets are dropped as soon as the
  stream session leaves the running state.
* Config: `mic_passthrough` (default enabled; the per-client `mic` permission, default off,
  is the real gate) and `mic_device` (Windows).

### 7.4 Client side

* Capture with AVAudioEngine (input node, voice processing / echo cancellation on by
  default, other-audio ducking set to minimum on macOS 14+), convert to 48 kHz mono with
  AVAudioConverter, Opus-encode 20 ms frames with libopus on a dedicated thread (capture
  backlog capped at 200 ms), send through `LiSendMicrophoneOpusData(const unsigned char *data,
  int len)`, which does the GCM framing, owns the socket and is thread-safe; it returns
  `LI_ERR_UNSUPPORTED` (frame dropped) when no mic stream runs.
* `NSMicrophoneUsageDescription` in Info.plist and the hardened-runtime entitlement
  `com.apple.security.device.audio-input` for signed builds. Permission is requested when the
  user enables the setting (and, if still undetermined, when the stream starts); capture
  starts only after it is granted. `enableMicrophone` is not set when access is denied.
* Settings: `micPassthrough` (default off), `micEchoCancellation` (default on). Mute hotkey:
  **Ctrl+Alt+Shift+U** (Ctrl+Option+Shift+U on macOS); muting stops sending and shows
  "Microphone muted" in the status overlay. Audio already sent can play out from the host
  and sink buffers, with up to 100 ms of loss concealment after the final queued frame.
  Disconnect and observed permission revocation close the sink and discard queued audio.
  Taken already: Q Z X S M C D V L E K, O (outbox download, 6.5) and U (mic mute).
* Other platforms have no capture backend yet; the setting is hidden there.

## 8. Other client changes

* Cmd->Ctrl remap: optional setting (default off), macOS only: left/right Command are sent as
  left/right Control and Control as Command (Windows key), so Cmd+C/V/Z/A behave as Ctrl+C/V/Z/A
  on Linux/Windows hosts.
* Client private key stored in the login Keychain as a generic password item. The service
  is `local.secure-desktop-stream.Moonlight.identity.<SHA256 of absolute profile path>`;
  separate profiles and the upstream application have separate identities. The implementation
  uses the login Keychain's access control; it does not set an iOS-style "this device only"
  accessibility attribute. Existing matching QSettings PEM is migrated and removed from
  QSettings after a verified Keychain write. If either half of an existing identity is missing
  or mismatched, startup preserves it and reports a recovery error rather than replacing it.
* Connections use numeric private/link-local or loopback addresses. Hostnames and public
  addresses are refused before network activity; HTTP redirects are never followed. HTTPS
  traffic is pinned to the paired host certificate with client-certificate authentication.
* The macOS build records both source revisions and the maximum deployment requirement of
  every bundled Mach-O image before signing. Homebrew-built bundles target the host macOS SDK version used at build time.

## 8a. Implementation map

Host (`sunshine/`):

| Path | Content |
| --- | --- |
| `src/sds/sds.h/.cpp` | module init/shutdown, config, the `sds`/`sds-io` worker threads, stream start/stop hooks, request dispatcher |
| `src/sds/auth.h/.cpp` | live authorization and rate limiter; HTTP identity comes from the verified TLS connection |
| `src/sds/permissions.h/.cpp` | permission enum and parsing (also used by nvhttp and confighttp) |
| `src/sds/worker.h/.cpp`, `src/sds/reply.h` | worker thread with timers; transport-independent replies |
| `src/sds/text.h/.cpp`, `src/sds/nfc_data.h` | UTF-8 validation and NFC (generated tables) |
| `src/sds/clipboard_backend_none.cpp` | fallback `make_backend()` (nullptr), linked only when no `src/platform/*/clipboard*.cpp` is in the build |
| `src/sds/events.h/.cpp` | per-client event queues, long-poll parking, wake on stream end |
| `src/sds/clipboard.h/.cpp` | platform-independent clipboard core: validation, limits, seq, echo suppression |
| `src/sds/files.h/.cpp` | upload sessions, outbox listing/ids, range reads, sanitizer |
| `src/sds/fs.h`, `fs_common.cpp`, `fs_posix.cpp`, `fs_windows.cpp` | directory/file primitives (openat/O_NOFOLLOW; CreateFileW + impersonation + MOTW) |
| `src/sds/http.h/.cpp` | registers `/sds/...` on the nvhttp HTTPS server only, and a 404 guard on the plain HTTP server |
| `src/rtsp.h/.cpp`, `src/stream.cpp` | `rtsp_stream::has_running_session(cert)`, session observer notified on RUNNING / STOPPING |
| `src/platform/linux/clipboard_x11.cpp` | X11 backend |
| `src/platform/linux/clipboard_portal.cpp` | GNOME portal backend (shares the RemoteDesktop session with `portalgrab.cpp`) |
| `src/platform/windows/clipboard.cpp` | Win32 backend |
| `src/sds/mic.h/.cpp` | mic receive (port base+13), ping binding, rate limit, GCM verify, replay window, jitter buffer, decode, live paired-client permission checks |
| `src/platform/linux/mic_linux.cpp`, `mic_pipewire.cpp`, `mic_sinks.h`; `src/platform/windows/mic_wasapi.cpp`; `src/sds/mic_sink_none.cpp` (macOS) | virtual microphone sinks (PipeWire, PulseAudio fallback, WASAPI cable, none) |
| `tests/unit/sds/*` | gtest suites for all of the above |

Clipboard backend interface (host):

```cpp
namespace sds::clipboard {
  struct limits_t { std::size_t text_max; std::size_t image_max; };
  struct item_t {
    std::optional<std::string> text;           // valid UTF-8, no NUL
    std::optional<std::vector<std::uint8_t>> png;  // PNG bytes
  };
  class backend_t {
  public:
    virtual ~backend_t() = default;
    // Begin watching. on_change is called from any thread, ONLY for changes made by other
    // applications (never for this backend's own writes: X11 owner == our window, Win32
    // GetClipboardOwner() == our hwnd, portal session_is_owner == true).
    virtual int start(std::function<void()> on_change) = 0;
    virtual void stop() = 0;
    // Current host clipboard content, converted to text and/or PNG, each within limits
    // (oversized representations are dropped, not truncated). Blocks at most `timeout`.
    virtual std::optional<item_t> read(const limits_t &limits, std::chrono::milliseconds timeout) = 0;
    // Take clipboard ownership and offer `item` to local applications.
    virtual int write(const item_t &item) = 0;
    virtual std::string_view name() const = 0;
  };
  // Runtime choice: Windows -> win32; Linux -> portal if the portal RemoteDesktop session is
  // available, else X11 if DISPLAY is set; otherwise nullptr (feature unavailable).
  std::unique_ptr<backend_t> make_backend();
}
```

Client (`moonlight-qt/`):

| Path | Content |
| --- | --- |
| `app/backend/sdsclient.h/.cpp` | worker QThread with its own pinned-mTLS QNetworkAccessManager: capabilities, event long-poll, clipboard GET/PUT, uploads, outbox downloads |
| `app/streaming/sds/clipboard_mac.mm` | NSPasteboard read/write/changeCount (`clipboard_null.cpp` elsewhere) |
| `app/streaming/sds/filesanitize.cpp` | sanitizer shared rules (6.4), download folder (part files, no-replace rename), quarantine xattr |
| `app/streaming/sds/clipboardsync.cpp` | clipboard validation (5.1) and change-count echo guard |
| `app/streaming/sds/sdscontroller.cpp` | main-thread controller: clipboard poll, start sequence, dropped files, overlay messages |
| `app/streaming/sds/sdssession.cpp` | SDL glue: 300 ms tick timer, wake events, overlay arbitration, setup from settings and serverinfo |
| `app/streaming/audio/miccapture_mac.mm` | AVAudioEngine capture (voice processing on) + macOS permission |
| `app/streaming/audio/micstreamer.h/.cpp`, `micsession.h/.cpp`, `miccapture.h`, `miccapture_none.cpp` | Opus encoder thread, per-stream mic controller (permission flow, mute hotkey, overlay) |
| `moonlight-common-c/src/SdsMic*.c`, `SdsMic.h` | mic RTSP SETUP, GCM framing, ping thread, `LiSendMicrophoneOpusData()` |
| `tests/unit/*` | Qt Test suites |
| `tests/sds/*` | Qt Test suites for clipboard and file transfer, plus `mock_sds_host.py` (mTLS mock of `/sds/v1`); run with `tools/run-client-sds-tests.sh` |

## 9. Security checks (each must have a test)

| # | Check | Where |
| --- | --- | --- |
| S1 | `/sds/v1/*` not routed on the plain HTTP server | host, nvhttp |
| S2 | No/unknown/unpaired client cert -> rejected | host |
| S3 | No active stream for that cert -> 409 | host |
| S4 | Missing permission -> 403, per endpoint | host |
| S5 | Global feature off -> 404 | host |
| S6 | Body > limit -> 413; nothing buffered beyond `max(chunk_max, clipboard_image_max, clipboard_text_max) + 64 KiB` (connection closed) | host |
| S7 | Name sanitization incl. `..`, `/`, `\`, NUL, reserved names, NFD, overlong | both |
| S8 | Symlink/reparse inbox or outbox, symlinked `.part` target, symlink in outbox -> refused | host |
| S9 | Never overwrite: collision -> `name (n)`; `O_EXCL` | both |
| S10 | Upload session of client A not usable by client B | host |
| S11 | Disk space floor and per-file max | host |
| S12 | Concurrency and rate limits | host |
| S13 | Clipboard: invalid UTF-8 / NUL / bad PNG header / oversized -> rejected | both |
| S14 | Received files not executable; Windows MOTW; macOS quarantine xattr | both |
| S15 | Mic: unauthenticated or replayed packets dropped; mic only with permission | host |
| S16 | All new state cleared when the stream ends | host |

Host tests live in `sunshine/tests/unit/sds` (`test_sds_*.cpp`: auth S2-S6/S12, http S1/S2/S6/S10
over a real mTLS server, sanitize S7, files S8/S9/S10/S11/S14, clipboard S13, module S16,
events, fs, rtsp, nvhttp permissions, config). Client-side tests live in `moonlight-qt/tests/sds`: S7 `tst_sanitizer`, S9 and S14
`tst_downloaddir` and `tst_sdsclient`, S13 `tst_clipboard` and `tst_sdsclient`, plus server
certificate pinning (`tst_sdsclient::pinningRejectsWrongServerCert`).

## 10. Hardening (non-feature) changes, for reference

Host: mDNS advertising off by default (`mdns_advertise`), UPnP off, `lan_encryption_mode=2`,
`wan_encryption_mode=2`, `origin_web_ui_allowed=pc`, no unauthenticated first-run password
setup (credentials must exist before the service starts: `sunshine --creds` or a
pre-provisioned state file), web UI login rate limiting and lockout, no external fetches from
the web UI or the C++ code (igdb covers, GitHub release checks), no `setcap` in packages.

Client: no update checks, no compatibility list or gamepad DB downloads, no STUN, no
connection test servers, no Discord RPC. Optional mDNS discovery sends local multicast
queries and listens for replies; it does not advertise the client as a Sunshine host.

## 11. Revision log

2026-11-21, client clipboard and file transfer (clarifications where v1 was ambiguous; the
safest reading was chosen):

* 3.1: client-side strict pinning described.
* 4.2: `events` needs steps 1-4 only; client accepts only `version` 1 and clamps limits.
* 4.4: `insufficient_space` -> `507`; the two `409`s are told apart by `error`; HTTP/1.1,
  `Content-Length` on every body, no redirects.
* 4.5 (new): event stream envelope, ids, `timeout` 0..30, `stream_ended`, optional
  `capabilities` event, client backoff rules.
* 5.3: client validation and supersede rules; `type` values.
* 5.4: start sequence made explicit; the host enqueues an initial `clipboard` event per
  stream session; host wins means the client does not push when the host announced content.
* 6.2: client uploads (first-pass hash, sequential uploads, resume rules, acknowledged-bytes
  hash, zero-byte files).
* 6.3: client checks on download responses.
* 6.4: client order of rules, bidi controls and DEL, overlong names shortened.
* 6.5: hotkey is `Ctrl+Alt+Shift+O` (`D` is already minimize); download folder details.
* 8a, 9: client file map and test locations.
* After review: idle-poll backoff (4.5), `X-SDS-Host-Seq` required (5.3), `complete` retry and
  acknowledged-hash scope (6.2), in-memory ranges and outbox caps (6.3), rename fallback (6.5).

2026-11-21, host core (sunshine `feature/sds-host-core`):

* 3.0: two worker threads (`sds`, `sds-io`); interim per-connection identity registry.
* 3.1: `sdsFeatures` only lists available features; HTTPS only.
* 4.1: `401 unauthorized`; dispatcher `404`/`405`/`400` before the pipeline; plain HTTP guard.
* 4.2: `features` in capabilities; permissions filtered by availability; admin API and state
  file details; permission changes take effect immediately.
* 4.3: request buffer is `max(chunk, image, text) + 64 KiB` (16 MiB PNG PUTs); oversized
  requests are dropped by closing the connection; config value syntax and ranges.
* 4.4: codes `unauthorized`, `mismatch`; `410` uses `conflict`; `503` on shutdown.
* 4.5: host details (clamping, `after > last_id`, coalescing, ids restart per stream).
* 5.3, 5.4: optional `seq`, `404`/`410` details, PUT error statuses, watching rules.
* 6.1-6.4: folder checks, upload/download error statuses, ownership `404`, stale part cleanup,
  outbox baseline, sanitizer specifics.
* 9: S6 wording; host test locations.

2026-11-24, encoder/adapter override, host resolution switching, lazy clipboard & XDND drops:

* 3.1: added `host_encoder`, `host_resolution`, `file_clipboard`, `lazy_clipboard`, `xdnd_drop`
  discovery tokens; `/serverinfo` `<sdsEncoders>`, `<sdsAdapters>`, `<sdsSoftwareCodecModeSupport>`;
  paired `/launch`/`/resume` parameters (`sdsEncoder`, `sdsAdapter`, `sdsHevc`, `sdsMatchRes`,
  `sdsRevertRes`) scoped to active stream lifetime.
* 4.3, 4.5, 6.6: `file_clipboard` generalized config toggle, lazy clipboard offers & 4 MiB
  chunked streaming (`clipboard_offer`, `clipboard_pull`), clipboard-manager `SelectionRequest`
  blocking, and unified `/sds/v1/drops` XDND v5 delivery with `~/Downloads/Moonlight` fallback.

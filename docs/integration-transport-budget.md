# SDS transport admission and lifetime budget

The worker queue budget starts too late to bound HTTPS transport memory. A
paired peer can open many connections, announce large Content-Length bodies and
stop sending, or stop reading responses after a worker finishes. Those buffers
remain outside the worker queue and retain memory independently of job count.

Three approaches were considered. Enlarging the worker budget does not cover
pre-dispatch bodies or completed jobs awaiting network writes. Replacing the
HTTP parser would duplicate framing and TLS lifecycle machinery with a much
larger compatibility surface. The selected design adds narrow admission/lifetime
hooks to the existing Simple-Web-Server adapter and keeps its parser.

## Contract

1. Bound accepted connections globally before TLS processing (64 by default),
   then bound authenticated connections per paired certificate (8). Connection
   leases live on the connection, including idle keep-alive/header reads.
2. Read headers into an independent buffer capped at 64 KiB. This cap must not
   become the body cap: the body buffer still accepts the module's configured
   maximum, including legitimate clipboard bodies above 5 MiB.
3. Before copying or reading a body, the SDS header admission hook rejects
   Transfer-Encoding, duplicate Content-Length, nondecimal/overflowing length,
   and a declared length above the configured request cap. Rejections close the
   connection, so unread bytes cannot be reinterpreted as another request.
4. Reserve twice the declared body length before buffering: one SWS content
   buffer plus the dispatch payload copy. The request owns a shared RAII lease.
   The defaults are 256 MiB global and 128 MiB per certificate. Header/TLS/socket
   overhead is bounded separately by the header and connection counts; these
   byte limits are not a claim about whole-process RSS.
5. Before copying a serialized reply into the SWS response buffer, reserve twice
   its body size as well, conservatively covering the existing reply/serialized
   string and SWS output copy. Keep the request reservation until completion.
   If adjustment fails, close the response connection without allocating another
   large output buffer. JSON serialization happens once; output copies are not
   hidden behind an already-completed worker lease.
6. The request lease lives through `Response -> Session -> Request` until the
   actual asynchronous send completion/error. A partial body, timeout, refused
   response reservation, client reset and server shutdown must all release it.
   An application may retain the Request after its socket closes; its request
   count and reservations stay alive until that last owner releases it. Request
   and connection counts are independently capped, and a client record is removed
   only when connections, requests and bytes are all zero. Finishing a worker job
   is not release authority. Content and request timeouts
   remain finite; tests use short deterministic timeouts.

At the maximum 64 MiB raw clipboard body, the two body copies consume exactly
the default 128 MiB per-client byte limit. Fixed header/connection overhead is
accounted separately. The worker's own pending-job byte limits remain a second
gate; neither gate replaces the other.

## Regression plan

Use the production certificate-verifying HTTPS server with synthetic credentials
and loopback sockets. Fixture overrides reduce connection and byte budgets.
Prove that partial large bodies reserve their declared charge, the same-client
and global caps reject additional bodies before buffering, another permitted
client can use remaining capacity, and closing/timeouts restore admission.

For output, use a real TLS peer that sends a request but does not read a response
larger than its TCP receive window. Observe that the output reservation survives
worker completion, rejects another response that would exceed the cap, and is
released after an actual read completes or the peer resets. Preserve the real
clipboard transfer above 5 MiB. Exercise duplicate/ambiguous framing, oversized
headers, send errors and shutdown. Unit accounting checks alone do not establish
these socket lifetime properties.

The integrated implementation uses the local Simple-Web-Server adapter changes.
The Linux host suite from November 22, 2026 passed with the exact transport
headers and tests in this checkout. Its full run passed 1,295 cases and skipped
eight system cases. The HTTPS cases exercised partial bodies, timeout and reset,
connection and framing limits, slow TLS readers, and a clipboard payload above
5 MiB. The earlier pre-transport source capture is not a failing test result.
Native Windows operation and end-to-end desktop feature acceptance remain
separate checks.

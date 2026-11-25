# Syncing Fork `main` Commits Into the Monorepo

This umbrella monorepo pins the clean, verified `main` commits of the three public forks (`sunshine/`, `moonlight-qt/`, `moonlight-common-c/`).

All custom fork changes on top of the upstream bases have been squashed with open-source author metadata (`dst0 <2117299+dst0@users.noreply.github.com>`), scrubbed of personal/host-specific literals, and pinned to `main`:

## Integrated Components on `main`

| Component | Upstream Base | Key Additions Included on `main` | Pinned `main` SHA |
| --- | --- | --- | --- |
| `dst0/Sunshine` | `v2026.1120.205658` (`de1e671e`) | Memory-safe Rust `sds-http-rs` (`tokio` + `rustls`/`aws-lc-rs` `X25519MLKEM768` + RFC 9112 framing), OpenGL/VAAPI `YCoCg-R` `P010` 4:4:4, adaptive dirty-tile lossless QOI refinement (`/sds/v1/tile-refinement`), host GPU/capture GPU selection, XRandR dynamic resolution, clipboard/files/mic, and parameterized private X11 runtime checks | `94e817b191bc49fe00e4ba57525adec122eb6f52` |
| `dst0/moonlight-qt` | `master` @ `2dc63d1f` | Strict PQ TLS 1.3 client & cert pinning, Metal `YCoCg-R` `P010` 4:4:4 unpack & adaptive dirty-tile lossless QOI refinement (`VTMetalRenderer`), per-PC settings overrides, OS-following Light/Dark theme, host encoder/GPU/XRandR UI, lazy file clipboard, mic passthrough, and Qt 5.14/6.2 + OpenSSL 1.0 + MSVC build compatibility | `9d79619bfe05df809a6c68e23d798970df1cee8b` |
| `dst0/moonlight-common-c` | `master` @ `94c65fd` | LAN-only hardening, fail-closed RTSP/AEAD encryption, and encrypted microphone stream | `4fbeb00df3089501b920dee2b005a1b39c20fcf9` |

## Updating Pinned Submodule SHAs Here

Whenever upstream forks (`dst0/{Sunshine,moonlight-qt,moonlight-common-c}` `main`) receive verified, PII-clean commits, bump the pins and verify both root history and submodule deltas:

```bash
bash tools/sync-forks.sh
git diff --submodule
python3 tools/audit-pii.py --strict --check-git-history --check-submodule-deltas
```

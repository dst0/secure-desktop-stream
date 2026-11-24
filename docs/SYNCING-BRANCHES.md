# Syncing Fork `main` Commits Into the Monorepo

This umbrella monorepo pins the clean, verified `main` commits of the three public forks (`sunshine/`, `moonlight-qt/`, `moonlight-common-c/`).

All custom fork changes on top of the upstream bases have been squashed with open-source author metadata (`dst0 <2117299+dst0@users.noreply.github.com>`), scrubbed of personal/host-specific literals, and pinned to `main`:

## Integrated Components on `main`

| Component | Upstream Base | Key Additions Included on `main` | Pinned `main` SHA |
| --- | --- | --- | --- |
| `dst0/Sunshine` | `v2026.1120.205658` (`de1e671e`) | Memory-safe Rust `sds-http-rs` (`tokio` + `rustls`/`aws-lc-rs` `X25519MLKEM768` + RFC 9112 framing), OpenGL/VAAPI `YCoCg-R` `P010` 4:4:4, host GPU/capture GPU selection, XRandR dynamic resolution, clipboard/files/mic, and parameterized private X11 runtime checks | `8773e498ce157c31d916f5b6eff196ad582f717e` |
| `dst0/moonlight-qt` | `master` @ `2dc63d1f` | Strict PQ TLS 1.3 client & cert pinning, Metal `YCoCg-R` `P010` 4:4:4 unpack (`VTMetalRenderer`), host encoder/GPU/XRandR UI, lazy file clipboard & mic passthrough | `fc686569a9723cc58e59c4ed375a249b9fa83491` |
| `dst0/moonlight-common-c` | `master` @ `94c65fd` | LAN-only hardening, fail-closed RTSP/AEAD encryption, and encrypted microphone stream | `4fbeb00df3089501b920dee2b005a1b39c20fcf9` |

## Updating Pinned Submodule SHAs Here

Whenever upstream forks (`dst0/{Sunshine,moonlight-qt,moonlight-common-c}` `main`) receive verified, PII-clean commits, bump the pins and verify both root history and submodule deltas:

```bash
bash tools/sync-forks.sh
git diff --submodule
python3 tools/audit-pii.py --strict --check-git-history --check-submodule-deltas
```

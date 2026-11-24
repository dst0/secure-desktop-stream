# Syncing Active Feature Branches Into Submodule `main`

This umbrella monorepo pins the current verified `main` commits of the three public forks (`sunshine/`, `moonlight-qt/`, `moonlight-common-c/`).

Several parallel feature branches were completed or are finishing integration in the upstream fork trees and should be merged into their respective fork `main` branches (after full post-edit verification and PII scrubbing), then bumped here via [`tools/sync-forks.sh`](../tools/sync-forks.sh).

## Active / Ready Fork Branches

| Component | Branch | Key Addition | Target Commit / Status |
| --- | --- | --- | --- |
| `dst0/Sunshine` | `feat/rust-http-server-rs` | Replaces `Simple-Web-Server` with in-tree memory-safe Rust `sds-http-rs` (`tokio` + `rustls`/`aws-lc-rs` `X25519MLKEM768` + `httparse`) | `537e73ea8581e8d41142e4253351c04571a3b09c` (built & tested; scrub legacy runtime literals before merge to `main`) |
| `dst0/Sunshine` | `feat/vcn-ycocgr-444` | Host OpenGL/VAAPI `YCoCg-R` `P010` `1.5W x 2H` 4:4:4 packing, `hw_ycocgr_444` signaling, `test_packed444` (including exhaustive `256^3` check) | `a78fd9694e573f043244dcb2934cf2dde271db00` |
| `dst0/moonlight-qt` | `feat/vcn-ycocgr-444` | Client `VTMetalRenderer` `ps_draw_ycocgr_a1` unpack shader, Settings edge-case handling (`TestPacked444`), live Metal shader tests (`TestMetalYCoCgR`) | `873e20943801bcd5ce8246c95f3eb1984708f249` |
| `dst0/Sunshine` + `dst0/moonlight-qt` | Feature integration (working trees) | Host `<sdsAdapters>` / `<sdsEncoders>` / `software` 4:4:4 selection, XRandR dynamic resolution (`sdsMatchRes`/`sdsRevertRes`), lazy file clipboard & `XDND` drag-and-drop | Pending final merge & verification |

## Required Pre-Merge Scrub in `dst0/Sunshine`

Before pushing merged branches to public `dst0/Sunshine` `main`, generalize the remaining environment-specific string literals in these four files (where legacy host-specific `sds-<host>-display` / `sds-<host>-sunshine` slugs or fixed display `:97` appear):

1. `sunshine/src/platform/linux/x11_virtual_input.h` — derive the allowed private Xauthority socket directory dynamically from `SDS_PRIVATE_DISPLAY_DIR` / generic `%t/<instance>-display/Xauthority` pattern rather than hardcoding a single host slug and `:97`.
2. `sunshine/src/sds/file_clipboard.cpp` — replace explicit host-slug literals in `forbidden_component()` and `private_x11_enabled()` with generic `sds-*-sunshine` / `sds-*-display` pattern matching and `XAUTHORITY` under `$XDG_RUNTIME_DIR`.
3. `sunshine/src/sds/file_clipboard.h` — generalize the doc comment.
4. `sunshine/tests/unit/sds/test_sds_module.cpp` — replace specific instance-slug test fixture paths with generic `sds-host-sunshine` / `sds-host-display` / `sds-alt-sunshine`.

## Updating Pinned Submodule SHAs Here

Once fork changes are verified, scrubbed (`python3 tools/audit-pii.py --include-submodules`), and pushed to `dst0/{Sunshine,moonlight-qt,moonlight-common-c}` `main`:

```bash
bash tools/sync-forks.sh
git diff --submodule
python3 tools/audit-pii.py --strict --check-git-history
```

# Fork Bases

| Submodule / Component | Public `origin` (`main`) | Upstream | Base | Current Pinned SHA |
| --- | --- | --- | --- | --- |
| `sunshine/` | https://github.com/dst0/Sunshine | https://github.com/LizardByte/Sunshine | tag `v2026.1120.205658` (`de1e671e`) | `182526e827a0f4a105151ad05fcced672540cf29` |
| `moonlight-qt/` | https://github.com/dst0/moonlight-qt | https://github.com/moonlight-stream/moonlight-qt | `master` @ `2dc63d1f` (v6.2.0-79) | `044dc781dae6a689f1152edf9a93bd5c580f7364` |
| `moonlight-common-c/` | https://github.com/dst0/moonlight-common-c | https://github.com/moonlight-stream/moonlight-common-c | `master` @ `94c65fd` | `4fbeb00df3089501b920dee2b005a1b39c20fcf9` |

`moonlight-qt` tracks `master` rather than the `v6.2.0` tag because `master` pins the same `moonlight-common-c` commit (`94c65fd`) as the Sunshine release, keeping host and client on one shared protocol fork.

> **Retired Fork:** `Simple-Web-Server` is superseded by the in-tree memory-safe Rust HTTP/TLS crate (`sds-http-rs` using `tokio` + `rustls`/`aws-lc-rs` with `X25519MLKEM768` + `httparse`), now integrated directly on `dst0/Sunshine` `main` (`182526e827a0f4a105151ad05fcced672540cf29`). See [Branch Sync Guide](docs/SYNCING-BRANCHES.md) for syncing updated `main` SHAs with [sync-forks.sh](tools/sync-forks.sh).

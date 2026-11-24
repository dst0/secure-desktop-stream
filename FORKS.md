# Fork Bases

| Submodule / Component | Public `origin` (`main`) | Upstream | Base | Current Pinned SHA |
| --- | --- | --- | --- | --- |
| `sunshine/` | https://github.com/dst0/Sunshine | https://github.com/LizardByte/Sunshine | tag `v2026.1120.205658` | `39a7ce55df251152dc7ef31f1b74077b6276d436` |
| `moonlight-qt/` | https://github.com/dst0/moonlight-qt | https://github.com/moonlight-stream/moonlight-qt | `master` @ `2dc63d1f` (v6.2.0-79) | `88732eda8d96bfe44f86c0f2a332fd3bf1709f1a` |
| `moonlight-common-c/` | https://github.com/dst0/moonlight-common-c | https://github.com/moonlight-stream/moonlight-common-c | `master` @ `94c65fd` | `a48135a0c0d83d1f56d06c50cdc46602551c029c` |

`moonlight-qt` tracks `master` rather than the `v6.2.0` tag because `master` pins the same `moonlight-common-c` commit (`94c65fd`) as the Sunshine release, keeping host and client on one shared protocol fork.

> **Retired Fork:** `Simple-Web-Server` is superseded by the in-tree memory-safe Rust HTTP/TLS crate (`sds-http-rs` using `tokio` + `rustls`/`aws-lc-rs` with `X25519MLKEM768` + `httparse`) on the `feat/rust-http-server-rs` branch of `dst0/Sunshine` (`537e73ea`). See [Branch Sync Guide](docs/SYNCING-BRANCHES.md) for active feature branches and how to sync updated `main` SHAs with [sync-forks.sh](tools/sync-forks.sh).

# Fork Bases

| Submodule / Component | Public `origin` (`main`) | Upstream | Base | Current Pinned SHA |
| --- | --- | --- | --- | --- |
| `sunshine/` | https://github.com/dst0/Sunshine | https://github.com/LizardByte/Sunshine | tag `v2026.1120.205658` (`de1e671e`) | `421ad0e8380856a68a6cf2add7beb44c819e283d` |
| `moonlight-qt/` | https://github.com/dst0/moonlight-qt | https://github.com/moonlight-stream/moonlight-qt | `master` @ `2dc63d1f` (v6.2.0-79) | `1f2e093edbd05fcf54874ead660a3f3d964cdb7a` |
| `moonlight-common-c/` | https://github.com/dst0/moonlight-common-c | https://github.com/moonlight-stream/moonlight-common-c | `master` @ `94c65fd` | `7e895b719a7907f4dbb62902c6ba4ef650d71df0` |

`moonlight-qt` tracks `master` rather than the `v6.2.0` tag because `master` pins the same `moonlight-common-c` commit (`94c65fd`) as the Sunshine release, keeping host and client on one shared protocol fork.

> **Retired Fork:** `Simple-Web-Server` is superseded by the in-tree memory-safe Rust HTTP/TLS crate (`sds-http-rs` using `tokio` + `rustls`/`aws-lc-rs` with `X25519MLKEM768` + `httparse`), now integrated directly on `dst0/Sunshine` `main` (`421ad0e8380856a68a6cf2add7beb44c819e283d`). See [Branch Sync Guide](docs/SYNCING-BRANCHES.md) for syncing updated `main` SHAs with [sync-forks.sh](tools/sync-forks.sh).

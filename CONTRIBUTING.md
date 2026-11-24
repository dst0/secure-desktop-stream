# Contributing

Thank you for contributing to **Secure Desktop Stream**!

## Repository Hygiene Rules

1. **Zero Personal Data or Environment Leaks:**
   - Never commit real home paths, private LAN IPs (`192.168.*`), personal usernames, hostnames, hardware serials/PCI IDs, or private keys/tokens.
   - Always run the repository PII scanner before pushing:
     ```bash
     python3 tools/audit-pii.py --strict --check-git-history
     ```
2. **Umbrella Submodule Workflow:**
   - Core host/client/protocol code changes belong in their respective submodules (`sunshine/`, `moonlight-qt/`, `moonlight-common-c/`).
   - Keep `.gitmodules` pointing strictly to clean public HTTPS remotes (`https://github.com/dst0/...`).
   - Use [tools/sync-forks.sh](tools/sync-forks.sh) to pull verified `main` commits from the submodules and update pinned revisions cleanly.
3. **Post-Edit Verification:**
   - Run all checks strictly after your final edit:
     ```bash
     cd installer
     cargo fmt --check
     cargo clippy --all-targets -- -D warnings
     cargo test --locked --all-targets
     bash tests/test-bootstraps.sh
     cd ..
     python3 -m unittest discover -s tests -v
     python3 -m unittest discover -s tools/builder-sunshine-windows -p 'test_*.py' -v
     python3 tools/audit-pii.py --strict --check-git-history
     ```
4. **Pure Native Rust UI Hygiene:**
   - `sds-installer` uses `floem` (`FLOEM_FORCE_TINY_SKIA=1`) and `ratatui`/`crossterm` without any HTML/JS/WebView or local HTTP server. Keep all UI logic and validation cleanly separated in `installer/src/ui_state.rs` so headless tests can verify all state transitions and inputs.

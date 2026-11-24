#!/usr/bin/env python3
"""Scan tracked files (and optionally full git history) for PII, local paths,
personal hostnames/emails, private LAN IPs, hardware serials/PCI paths, and secrets.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

SUBMODULE_PREFIXES = ("sunshine/", "moonlight-qt/", "moonlight-common-c/")


def _c(*parts: str) -> str:
    return "".join(parts)


# Patterns are assembled dynamically so this scanner does not trigger false positives on itself.
FORBIDDEN_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "macos_user_path",
        re.compile(r"/Users/[A-Za-z0-9._-]+(?:/|$|\s|\"|'|`)"),
    ),
    (
        "linux_non_generic_home_path",
        re.compile(r"/home/(?!user(?:/|$|\"|'|\s)|runner(?:/|$|\"|'|\s)|builder(?:/|$|\"|'|\s))[A-Za-z0-9._-]+"),
    ),
    (
        "windows_user_path",
        re.compile(r"C:\\{1,2}Users\\{1,2}(?!(?:Public|Default|YourUser)(?:\\|$))[A-Za-z0-9._-]+", re.IGNORECASE),
    ),
    (
        "personal_hostname_or_slug",
        re.compile(
            r"(?:"
            + _c("mini", "-pc")
            + r"|"
            + _c("mini", r"\s+", "pc")
            + r"|"
            + _c("mini", "pc")
            + r"|"
            + _c(r"\b", "pc", "2", r"\b")
            + r"|"
            + _c("sds-", "pc", "2")
            + r")",
            re.IGNORECASE,
        ),
    ),
    (
        "personal_user_or_email_or_org",
        re.compile(
            r"(?:"
            + _c("d", "st@")
            + r"|"
            + _c("4d", "@ukr")
            + r"|"
            + _c("Dmy", "tro")
            + r"|"
            + _c("Stepa", "nov")
            + r"|"
            + _c("destination", "works")
            + r"|"
            + _c("MacBook", " Controller")
            + r")",
            re.IGNORECASE,
        ),
    ),
    (
        "personal_lan_subnet",
        re.compile(r"\b192\.168\.8\.\d+\b"),
    ),
    (
        "personal_gpu_or_pci_id",
        re.compile(
            r"(?:"
            + _c("0000:", "09:00", r"\.0")
            + r"|"
            + _c("0000:", "07:00", r"\.0")
            + r"|"
            + _c("0000:", "03:00", r"\.0")
            + r"|"
            + _c("0000:", "c4:00", r"\.0")
            + r"|"
            + _c("RX", r"\s+", "9070")
            + r"|"
            + _c("76", "0M")
            + r")",
            re.IGNORECASE,
        ),
    ),
    (
        "private_key_block",
        re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    ),
    (
        "api_token_or_secret",
        re.compile(r"(?:ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,})"),
    ),
]


def run_git(root: Path, args: list[str]) -> str:
    res = subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
    )
    if res.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {res.stderr.strip()}")
    return res.stdout


def iter_tracked_files(root: Path, include_submodules: bool) -> list[Path]:
    out = run_git(root, ["ls-files", "-z"])
    paths: list[Path] = []
    for rel in out.split("\0"):
        if not rel:
            continue
        p = root / rel
        if p.is_dir() or not p.is_file():
            continue
        if not include_submodules and any(rel.startswith(pref) for pref in SUBMODULE_PREFIXES):
            continue
        paths.append(p)
    if include_submodules:
        for sub in ("sunshine", "moonlight-qt", "moonlight-common-c"):
            sub_dir = root / sub
            if (sub_dir / ".git").exists():
                sub_out = run_git(sub_dir, ["ls-files", "-z"])
                for rel in sub_out.split("\0"):
                    if not rel:
                        continue
                    sp = sub_dir / rel
                    if sp.is_file():
                        paths.append(sp)
    return paths


def scan_text(label: str, text: str) -> list[str]:
    findings: list[str] = []
    if _c("# audit-pii:", " skip-file") in text:
        return findings
    lines = text.splitlines()
    for lineno, line in enumerate(lines, start=1):
        if "audit-pii: ignore-line" in line:
            continue
        for rule_name, pat in FORBIDDEN_PATTERNS:
            m = pat.search(line)
            if m:
                snippet = line.strip()
                if len(snippet) > 140:
                    snippet = snippet[:137] + "..."
                findings.append(f"{label}:{lineno}: [{rule_name}] matched {m.group(0)!r} in: {snippet}")
    return findings


def scan_git_history(root: Path) -> list[str]:
    findings: list[str] = []
    has_commits = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--verify", "HEAD"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode == 0
    if not has_commits:
        return findings

    authors = run_git(root, ["log", "--all", "--format=%H\t%an\t%ae\t%cn\t%ce"])
    for idx, row in enumerate(authors.splitlines(), start=1):
        parts = row.split("\t")
        if len(parts) != 5:
            continue
        sha, an, ae, cn, ce = parts
        for label, val in (("author_name", an), ("author_email", ae), ("committer_name", cn), ("committer_email", ce)):
            for rule_name, pat in FORBIDDEN_PATTERNS:
                m = pat.search(val)
                if m:
                    findings.append(f"git-metadata:{sha[:12]}:{label}: [{rule_name}] matched {m.group(0)!r} in {val!r}")
        if not ae.endswith("@users.noreply.github.com") or (
            ce != ae and ce != "noreply@github.com"
        ):
            # Allow clean GitHub noreply emails (and GitHub Web merge/squash committer email) only
            findings.append(f"git-metadata:{sha[:12]}: commit email {ae!r}/{ce!r} should use *@users.noreply.github.com")

    diff_text = run_git(root, ["log", "--all", "-p", "--no-color"])
    current_commit = "unknown"
    current_file = "unknown"
    for line in diff_text.splitlines():
        if line.startswith("commit "):
            current_commit = line.split()[1][:12]
        elif line.startswith("+++ b/"):
            current_file = line[6:]
        elif line.startswith("+") and not line.startswith("+++"):
            content = line[1:]
            for rule_name, pat in FORBIDDEN_PATTERNS:
                m = pat.search(content)
                if m:
                    findings.append(
                        f"git-diff:{current_commit}:{current_file}: [{rule_name}] matched {m.group(0)!r}"
                    )
    return findings


def scan_git_internals(root: Path) -> list[str]:
    findings: list[str] = []
    for alt in root.glob(".git/**/alternates"):
        findings.append(f"git-internal:{alt.relative_to(root)}: object alternates file must not exist in portable repo")
    gitmodules = root / ".gitmodules"
    if gitmodules.is_file():
        txt = gitmodules.read_text(encoding="utf-8", errors="replace")
        for line in txt.splitlines():
            if "url" in line and "https://github.com/dst0/" not in line and not line.strip().startswith("["):
                findings.append(f".gitmodules: unexpected non-public submodule URL: {line.strip()}")
        findings.extend(scan_text(".gitmodules", txt))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit repository for PII, local paths, IPs, and secrets")
    parser.add_argument("--root", default=".", help="Repository root directory")
    parser.add_argument("--include-submodules", action="store_true", help="Also scan initialized submodules")
    parser.add_argument("--check-git-history", action="store_true", help="Scan full git log diff & author metadata")
    parser.add_argument("--strict", action="store_true", help="Fail if any untracked non-ignored files exist or on any finding")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    findings: list[str] = []

    for p in iter_tracked_files(root, include_submodules=args.include_submodules):
        try:
            raw = p.read_bytes()
        except OSError as exc:
            findings.append(f"{p}: failed to read ({exc})")
            continue
        if b"\0" in raw[:8192]:
            continue  # binary file
        rel = p.relative_to(root)
        findings.extend(scan_text(str(rel), raw.decode("utf-8", errors="replace")))

    if args.strict:
        status = run_git(root, ["status", "--porcelain=v1", "-z", "-uall"])
        for entry in status.split("\0"):
            if not entry or not entry.startswith("?? "):
                continue
            rel = entry[3:]
            if any(rel.startswith(pref) for pref in SUBMODULE_PREFIXES):
                continue
            p = root / rel
            if p.is_file():
                try:
                    raw = p.read_bytes()
                except OSError as exc:
                    findings.append(f"untracked:{rel}: failed to read ({exc})")
                    continue
                if b"\0" not in raw[:8192]:
                    findings.extend(scan_text(f"untracked:{rel}", raw.decode("utf-8", errors="replace")))

    findings.extend(scan_git_internals(root))
    if args.check_git_history:
        findings.extend(scan_git_history(root))

    if findings:
        print(f"PII/Security audit FAILED with {len(findings)} finding(s):", file=sys.stderr)
        for item in findings:
            print(f"  - {item}", file=sys.stderr)
        return 1

    print("PII/Security audit PASSED (0 findings).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

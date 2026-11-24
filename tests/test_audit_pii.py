"""Regression tests for tools/audit-pii.py."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
AUDIT_SCRIPT = REPO_ROOT / "tools" / "audit-pii.py"


def _c(*parts: str) -> str:
    return "".join(parts)


class AuditPiiTests(unittest.TestCase):
    def _init_temp_repo(self, root: Path, name: str = "dst0", email: str = "2117299+dst0@users.noreply.github.com") -> None:
        subprocess.run(["git", "init", "-b", "main", str(root)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["git", "-C", str(root), "config", "user.name", name], check=True)
        subprocess.run(["git", "-C", str(root), "config", "user.email", email], check=True)

    def _run_audit(self, root: Path, extra: list[str] | None = None) -> subprocess.CompletedProcess[str]:
        cmd = [sys.executable, str(AUDIT_SCRIPT), "--root", str(root), "--strict", "--check-git-history"]
        if extra:
            cmd.extend(extra)
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def test_clean_repo_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._init_temp_repo(root)
            (root / "README.md").write_text("Use $HOME/.config/sds-host-sunshine and 192.168.1.50.\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "README.md"], check=True)
            subprocess.run(["git", "-C", str(root), "commit", "-m", "clean init"], check=True, stdout=subprocess.DEVNULL)
            res = self._run_audit(root)
            self.assertEqual(res.returncode, 0, msg=res.stderr)

    def test_catches_paths_hostnames_ips_secrets_and_bad_git_email(self) -> None:
        bad_samples = [
            _c("/Users/", "alice", "/dev/repo"),
            _c("/home/", "alice", "/config"),
            _c("C:\\Users\\", "Alice", "\\Desktop"),
            _c("ssh ", "d", "st@", "mini", "-pc"),
            _c("between Mac and ", "mini ", "PC"),
            _c("host=", "pc", "2"),
            "192.168." + "8.42",
            "0000:" + "09:00.0",
            "-----BEGIN RSA " + "PRIVATE KEY-----",
            "ghp_" + "A" * 24,
        ]
        for idx, sample in enumerate(bad_samples):
            with self.subTest(idx=idx, sample=sample):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    self._init_temp_repo(root)
                    (root / "leak.txt").write_text(f"val={sample}\n", encoding="utf-8")
                    subprocess.run(["git", "-C", str(root), "add", "leak.txt"], check=True)
                    subprocess.run(["git", "-C", str(root), "commit", "-m", "add leak"], check=True, stdout=subprocess.DEVNULL)
                    res = self._run_audit(root)
                    self.assertNotEqual(res.returncode, 0, msg=f"audit failed to flag {sample!r}")

    def test_catches_non_noreply_git_author_email(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._init_temp_repo(root, name="Person", email="person@example.com")
            (root / "README.md").write_text("Clean content.\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "README.md"], check=True)
            subprocess.run(["git", "-C", str(root), "commit", "-m", "init"], check=True, stdout=subprocess.DEVNULL)
            res = self._run_audit(root)
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("noreply.github.com", res.stderr)


    def test_strict_scans_files_inside_untracked_subdirectories(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._init_temp_repo(root)
            (root / "README.md").write_text("Clean.\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "README.md"], check=True)
            subprocess.run(["git", "-C", str(root), "commit", "-m", "init"], check=True, stdout=subprocess.DEVNULL)
            untracked_sub = root / "nested" / "sub"
            untracked_sub.mkdir(parents=True)
            (untracked_sub / "leak.txt").write_text(_c("/Users/", "alice", "/secret\n"), encoding="utf-8")
            res = self._run_audit(root)
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("nested/sub/leak.txt", res.stderr)


if __name__ == "__main__":
    unittest.main()

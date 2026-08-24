from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "tools" / "start_sos_windows.ps1"


class WindowsWslLauncherContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = LAUNCHER.read_text(encoding="utf-8")

    def test_launcher_is_host_only_and_never_provisions_or_elevates(self) -> None:
        self.assertIn('if ($env:OS -cne "Windows_NT")', self.text)
        for forbidden in (
            "wsl.exe --install",
            "--install -d",
            "Start-Process -Verb RunAs",
            "runas.exe",
            "Enable-WindowsOptionalFeature",
            "dism.exe",
        ):
            self.assertNotIn(forbidden, self.text)
        self.assertIn('"SOS_WSL2_REQUIRED"', self.text)
        self.assertIn('"SOS_WSL_DISTRO_REQUIRED"', self.text)
        self.assertIn('"SOS_WSL2_VERSION_REQUIRED"', self.text)
        self.assertIn('"SOS_WSL_PYTHON_UNSUPPORTED"', self.text)
        self.assertIn('foreach ($prerequisite in @("git", "uv", "codex"))', self.text)

    def test_canonical_workspace_is_native_linux_and_windows_mounts_are_artifacts_only(self) -> None:
        self.assertIn('/.local/share/sos/workspaces/', self.text)
        self.assertIn('if ($Script:LinuxRoot -match \'^/mnt/\')', self.text)
        self.assertNotRegex(self.text, r'LinuxRoot\s*=\s*"/mnt/')
        self.assertIn('wslpath", "-u", $temporaryBundle', self.text)
        self.assertIn('wslpath", "-u", $bundle', self.text)

    def test_import_requires_clean_exact_git_and_never_copies_a_worktree(self) -> None:
        required = (
            '"status", "--porcelain=v1", "--untracked-files=all"',
            '"bundle", "create", $temporaryBundle, "--all"',
            '"bundle", "verify", $temporaryBundle',
            '"git", "clone", "--no-checkout"',
            '"rev-parse", "HEAD"',
            '"SOS_WINDOWS_SOURCE_NOT_CLEAN"',
            '"SOS_WINDOWS_IMPORT_VERIFICATION_FAILED"',
        )
        for value in required:
            self.assertIn(value, self.text)
        self.assertNotIn("Copy-Item", self.text)
        self.assertNotIn("robocopy", self.text.lower())
        self.assertIn('"check-ref-format", "--branch", $branchProbe.Output', self.text)

    def test_one_preview_one_confirmation_and_qualification_remains_separate(self) -> None:
        self.assertEqual(self.text.count("Read-Host"), 1)
        self.assertIn('Type INSTALL to import/connect this exact plan', self.text)
        self.assertIn('qualification_runs = $false', self.text)
        self.assertNotRegex(self.text, r'Invoke-Wsl[^\n]+"qualify"')
        self.assertIn('qualification_state = "not_verified"', self.text)

    def test_mapping_is_stable_typed_and_drift_fails_closed(self) -> None:
        for value in (
            "sos_windows_wsl2_mapping_v1",
            '"importing", "imported", "ready"',
            '"SOS_WINDOWS_MAPPING_DRIFT"',
            '"SOS_WINDOWS_MAPPING_TARGET_MISSING"',
            '"SOS_WINDOWS_TARGET_COLLISION"',
            '"SOS_WINDOWS_TARGET_HEAD_DRIFT"',
            '"SOS_WINDOWS_TARGET_REPOSITORY_INVALID"',
        ):
            self.assertIn(value, self.text)
        self.assertRegex(self.text, re.compile(r"Get-ProjectId[\s\S]+SHA256"))

    def test_codex_uses_same_distro_and_exact_linux_root(self) -> None:
        self.assertIn('$wslArguments = @("-d", $Distro, "--exec") + $Arguments', self.text)
        self.assertIn('& $Script:Wsl -d $Distro --exec codex -C $Script:LinuxRoot', self.text)
        self.assertNotIn("cmd.exe", self.text.lower())
        self.assertNotIn("Invoke-Expression", self.text)

    def test_bundle_contract_includes_windows_launcher(self) -> None:
        finalizer = (ROOT / "tools" / "finalize_release_bundle.py").read_text(encoding="utf-8")
        linux_launcher = (ROOT / "tools" / "start_sos_alpha.py").read_text(encoding="utf-8")
        release = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        for text in (finalizer, linux_launcher, release):
            self.assertIn("start-sos-windows.ps1", text)
        self.assertIn('$Script:MaxFileBytes', self.text)
        self.assertIn('"SOS_WINDOWS_BUNDLE_FILE_TOO_LARGE"', self.text)


if __name__ == "__main__":
    unittest.main()

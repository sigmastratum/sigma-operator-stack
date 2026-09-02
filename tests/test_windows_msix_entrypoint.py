from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = ROOT / "installers/windows-msix-entrypoint"
INSTRUCTION = (
    "Install SOS in my current project. Show me the preview before changing it."
)


class WindowsMSIXEntrypointTests(unittest.TestCase):
    def test_gui_contract_is_static_and_non_mutating(self) -> None:
        model = (ENTRYPOINT / "model.go").read_text(encoding="utf-8")
        implementation = (ENTRYPOINT / "main_windows.go").read_text(encoding="utf-8")
        self.assertIn('productName = "Sigma Operator Stack"', model)
        self.assertIn('statusText  = "SOS is installed"', model)
        self.assertIn('versionText = "Version 0.1.0a2"', model)
        self.assertIn(INSTRUCTION, model)
        self.assertIn('createControl("BUTTON", "Copy instruction"', implementation)
        self.assertIn('createControl("BUTTON", "Close"', implementation)
        for forbidden in (
            "net/http",
            "os/exec",
            "CreateFile",
            "ShellExecute",
            "WinHttp",
            "RegSetValue",
            "runas",
        ):
            self.assertNotIn(forbidden.lower(), (model + implementation).lower())

    def test_builder_requires_gui_subsystem_candidate_and_asinvoker(self) -> None:
        source = (ROOT / "tools/build_windows_msix_entrypoint.py").read_text(
            encoding="utf-8"
        )
        for required in (
            "-H=windowsgui",
            "candidate.encode(\"ascii\") not in payload",
            "pe_subsystem(payload) != WINDOWS_GUI_SUBSYSTEM",
            '"verify-pe"',
            '"installers/windows-installer/application.manifest"',
        ):
            self.assertIn(required, source)
        manifest = (
            ROOT / "installers/windows-installer/application.manifest"
        ).read_text(encoding="utf-8")
        self.assertEqual(manifest.count('requestedExecutionLevel level="asInvoker"'), 1)
        self.assertIn('uiAccess="false"', manifest)

if __name__ == "__main__":
    unittest.main()

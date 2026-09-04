from __future__ import annotations

import re
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "installers/windows-msix/AppxManifest.xml.in"
ASSETS = ROOT / "installers/windows-msix/assets"
NS = {"f": "http://schemas.microsoft.com/appx/manifest/foundation/windows10"}


def dimensions(path: Path) -> tuple[int, int]:
    value = path.read_bytes()
    if len(value) < 24 or value[:8] != b"\x89PNG\r\n\x1a\n" or value[12:16] != b"IHDR":
        raise AssertionError(f"{path.name} is not a bounded PNG")
    return int.from_bytes(value[16:20], "big"), int.from_bytes(value[20:24], "big")


def store_acceptance_errors(manifest: str) -> list[str]:
    try:
        root = ET.fromstring(manifest)
    except ET.ParseError:
        return ["manifest_xml_invalid"]
    errors: list[str] = []
    identities = root.findall("f:Identity", NS)
    if len(identities) != 1:
        errors.append("identity_count_invalid")
    else:
        version = identities[0].get("Version", "")
        match = re.fullmatch(r"([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)", version)
        if (
            match is None
            or any(int(value) > 65535 for value in match.groups())
            or int(match.group(1)) == 0
            or int(match.group(4)) != 0
        ):
            errors.append("store_version_invalid")
    publisher = root.findall("f:Properties/f:PublisherDisplayName", NS)
    if len(publisher) != 1 or (publisher[0].text or "").strip() != "SSRG":
        errors.append("publisher_display_name_invalid")
    resources = root.findall("f:Resources/f:Resource", NS)
    if len(resources) != 1 or resources[0].get("Language") != "en-US":
        errors.append("language_resources_invalid")
    expected_logos = {
        "Square44x44Logo.png": (44, 44),
        "Square50x50Logo.png": (50, 50),
        "Square150x150Logo.png": (150, 150),
    }
    if "Assets\\Square50x50Logo.png" not in manifest:
        errors.append("properties_logo_invalid")
    for name, expected in expected_logos.items():
        path = ASSETS / name
        if not path.is_file() or dimensions(path) != expected:
            errors.append(f"asset_invalid:{name}")
    return errors


class WindowsStoreAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = MANIFEST.read_text(encoding="utf-8")

    def test_exact_manifest_and_assets_satisfy_store_acceptance_contract(self) -> None:
        self.assertEqual(store_acceptance_errors(self.manifest), [])
        self.assertIn('Version="1.0.5.0"', self.manifest)
        self.assertIn('<Resource Language="en-US" />', self.manifest)
        self.assertIn('<PublisherDisplayName>SSRG</PublisherDisplayName>', self.manifest)

    def test_nonzero_revision_is_rejected(self) -> None:
        changed = self.manifest.replace('Version="1.0.5.0"', 'Version="1.0.5.1"')
        self.assertIn("store_version_invalid", store_acceptance_errors(changed))

    def test_zero_major_is_rejected(self) -> None:
        changed = self.manifest.replace('Version="1.0.5.0"', 'Version="0.1.0.0"')
        self.assertIn("store_version_invalid", store_acceptance_errors(changed))

    def test_missing_or_unknown_language_is_rejected(self) -> None:
        missing = self.manifest.replace('    <Resource Language="en-US" />\n', "")
        unknown = self.manifest.replace('Language="en-US"', 'Language=""')
        self.assertIn("language_resources_invalid", store_acceptance_errors(missing))
        self.assertIn("language_resources_invalid", store_acceptance_errors(unknown))

    def test_blank_publisher_display_name_is_rejected(self) -> None:
        changed = self.manifest.replace(
            "<PublisherDisplayName>SSRG</PublisherDisplayName>",
            "<PublisherDisplayName></PublisherDisplayName>",
        )
        self.assertIn("publisher_display_name_invalid", store_acceptance_errors(changed))

    def test_wrong_properties_logo_reference_is_rejected(self) -> None:
        changed = self.manifest.replace(
            "Assets\\Square50x50Logo.png", "Assets\\MissingLogo.png"
        )
        self.assertIn("properties_logo_invalid", store_acceptance_errors(changed))


if __name__ == "__main__":
    unittest.main()

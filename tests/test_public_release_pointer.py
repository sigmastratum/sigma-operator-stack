from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "sos_public_release_pointer_check",
    ROOT / "tools" / "check_public_release_pointer.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("public release pointer checker import failed")
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


class PublicReleasePointerTests(unittest.TestCase):
    def test_checked_in_pointer_is_bound_to_published_tag_authority(self) -> None:
        result = checker.inspect(ROOT)
        self.assertEqual(result["status"], "passed", result)
        required = checker.inspect(ROOT, require_public=True)
        self.assertEqual(required["status"], "passed", required)

    def test_routing_pointer_is_bound_to_immutable_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            subprocess.run(["git", "init", "-q", str(repository)], check=True)
            subprocess.run(
                ["git", "-C", str(repository), "config", "user.email", "test@example.invalid"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(repository), "config", "user.name", "Synthetic Test"],
                check=True,
            )
            schemas = repository / "src" / "sos" / "schemas"
            schemas.mkdir(parents=True)
            for name in (
                "sos-public-release-pointer-v1.schema.json",
                "sos-public-release-index-v1.schema.json",
            ):
                (schemas / name).write_bytes((ROOT / "src" / "sos" / "schemas" / name).read_bytes())
            (repository / "seed").write_text("synthetic\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repository), "add", "."], check=True)
            subprocess.run(["git", "-C", str(repository), "commit", "-qm", "seed"], check=True)
            head = subprocess.run(
                ["git", "-C", str(repository), "rev-parse", "HEAD"],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            ).stdout.strip()
            tree = subprocess.run(
                ["git", "-C", str(repository), "show", "-s", "--format=%T", "HEAD"],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            ).stdout.strip()
            fixture_index = json.loads(
                (ROOT / "tests" / "fixtures" / "agent-first-release" / "sos-release-index-v1.json").read_text()
            )
            fixture_index["candidate"] = head
            fixture_index["tree"] = tree
            release = repository / "release"
            release.mkdir()
            index_bytes = (json.dumps(fixture_index, sort_keys=True, separators=(",", ":")) + "\n").encode()
            (release / "sos-release-index-v1.json").write_bytes(index_bytes)
            pointer = {
                "availability": "public",
                "candidate": head,
                "claim_state": "agent_first_qualified",
                "contract": "sos_public_release_pointer_v1",
                "index_path": "releases/download/v0.1.0a2/sos-release-index-v1.json",
                "index_sha256": hashlib.sha256(index_bytes).hexdigest(),
                "maturity": "community_alpha",
                "release_tag": "v0.1.0a2",
                "tree": tree,
                "version": "0.1.0a2",
            }
            (release / "current.json").write_text(
                json.dumps(pointer, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            subprocess.run(["git", "-C", str(repository), "add", "."], check=True)
            subprocess.run(
                ["git", "-C", str(repository), "commit", "-qm", "routing pointer"],
                check=True,
            )
            routing_head = subprocess.run(
                ["git", "-C", str(repository), "rev-parse", "HEAD"],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            ).stdout.strip()
            self.assertNotEqual(routing_head, head)
            self.assertEqual(checker.inspect(repository)["status"], "passed")
            unavailable = checker.inspect(repository, require_public=True)
            self.assertEqual(unavailable["status"], "failed")
            self.assertEqual(unavailable["failures"], ["SOS_PUBLIC_RELEASE_TAG_UNAVAILABLE"])
            pointer["index_sha256"] = "0" * 64
            (release / "current.json").write_text(json.dumps(pointer), encoding="utf-8")
            self.assertIn(
                "SOS_PUBLIC_RELEASE_INDEX_DIGEST_MISMATCH",
                checker.inspect(repository)["failures"],
            )


if __name__ == "__main__":
    unittest.main()

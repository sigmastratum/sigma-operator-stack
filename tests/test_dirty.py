from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sos import dirty
from sos.contracts import exclusion_policy_digest
from sos.repository import inspect_repository, repository_identity_contract
from sos.workspace import initialize_workspace, workspace_status


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class DirtyApplicationObserverTests(unittest.TestCase):
    def make_project(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        git(root, "init", "-q")
        git(root, "config", "user.name", "Synthetic Operator")
        git(root, "config", "user.email", "synthetic@example.invalid")
        (root / "README.md").write_text("synthetic\n", encoding="utf-8")
        (root / "tracked.txt").write_text("tracked\n", encoding="utf-8")
        git(root, "add", ".")
        git(root, "commit", "-qm", "synthetic base")
        return temporary, root

    def observation(self, root: Path):
        identity = repository_identity_contract(root, local_repository_nonce="1" * 32)
        inspection = inspect_repository(root, local_repository_nonce="1" * 32)
        exclusion = {
            "contract": "sos_bootstrap_exclusion_policy_v2",
            "schema_major": 2,
            "control_plane_root": ".sigma",
            "staging_prefix": ".sigma.init.",
            "transaction_id": "2" * 64,
            "policy_digest": "sha256:" + "0" * 64,
        }
        exclusion["policy_digest"] = exclusion_policy_digest(exclusion)
        return dirty.observe_application(root, identity.repository_id, inspection.head or "", exclusion["policy_digest"])

    def test_clean_fingerprint_is_stable_and_non_null(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        first = self.observation(root)
        second = self.observation(root)
        self.assertEqual(first, second)
        self.assertEqual(first.state, "clean")
        self.assertTrue(first.complete)
        self.assertEqual(first.entry_count, 0)
        self.assertRegex(first.fingerprint or "", r"^sha256:[0-9a-f]{64}$")

    def test_entry_and_clean_stream_match_normative_big_endian_encoding(self) -> None:
        entry = dirty._Entry("a.txt", 0x03, 0o100644, 0, 0x02, b"x" * 32)
        expected_entry = (
            b"\x01"
            + (5).to_bytes(4, "big")
            + b"a.txt"
            + b"\x03"
            + (0o100644).to_bytes(4, "big")
            + b"\x00\x02"
            + (32).to_bytes(4, "big")
            + b"x" * 32
        )
        self.assertEqual(dirty._entry_bytes(entry), expected_entry)
        repository_id = "sha256:" + "11" * 32
        head = "22" * 20
        policy = "sha256:" + "33" * 32
        stream = b"sos_dirty_v1\0" + bytes.fromhex("11" * 32) + b"\x14" + bytes.fromhex(head) + bytes.fromhex("33" * 32) + b"\0\0\0\0"
        self.assertEqual(
            "sha256:" + hashlib.sha256(dirty._stream(repository_id, head, policy, [])).hexdigest(),
            "sha256:" + hashlib.sha256(stream).hexdigest(),
        )

    def test_staged_unstaged_untracked_deletion_and_symlink_are_bound(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        baseline = self.observation(root).fingerprint
        (root / "tracked.txt").write_text("staged\n", encoding="utf-8")
        git(root, "add", "tracked.txt")
        staged = self.observation(root)
        self.assertEqual(staged.entry_count, 1)
        (root / "tracked.txt").write_text("unstaged too\n", encoding="utf-8")
        both = self.observation(root)
        self.assertEqual(both.entry_count, 2)
        (root / "untracked.txt").write_text("untracked\n", encoding="utf-8")
        untracked = self.observation(root)
        self.assertEqual(untracked.entry_count, 3)
        (root / "link").symlink_to("untracked.txt")
        linked = self.observation(root)
        self.assertEqual(linked.entry_count, 4)
        (root / "README.md").unlink()
        deleted = self.observation(root)
        self.assertEqual(deleted.entry_count, 5)
        fingerprints = {baseline, staged.fingerprint, both.fingerprint, untracked.fingerprint, linked.fingerprint, deleted.fingerprint}
        self.assertEqual(len(fingerprints), 6)
        self.assertGreater(deleted.bytes_hashed, 0)

    def test_untracked_content_change_after_bootstrap_is_stale(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        (root / "notes.txt").write_text("first\n", encoding="utf-8")
        self.assertEqual(initialize_workspace(str(root), confirmed=True, controlling_tty_observed=True).status, "success")
        before = workspace_status(str(root))
        self.assertEqual(before.status, "success")
        (root / "notes.txt").write_text("second\n", encoding="utf-8")
        after = workspace_status(str(root))
        self.assertEqual(after.status, "stale")
        self.assertIn("SOS_SOURCE_STATUS_CHANGED", after.reasons)

    def test_protected_ignored_presence_is_bound_without_content_hash(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        (root / ".gitignore").write_text(".env\n", encoding="utf-8")
        git(root, "add", ".gitignore")
        git(root, "commit", "-qm", "synthetic ignore")
        protected = root / ".env"
        protected.write_text("SYNTHETIC_SECRET_MARKER=never-serialize\n", encoding="utf-8")
        protected.chmod(0)
        observed = self.observation(root)
        self.assertEqual(observed.state, "dirty")
        self.assertTrue(observed.complete)
        self.assertEqual(observed.content_completeness, "protected_content_not_observed")
        self.assertEqual(observed.bytes_hashed, 0)
        self.assertEqual(observed.protected_presence[0]["path_projection"], ".env")
        self.assertFalse(observed.protected_presence[0]["content_opened"])
        serialized = json.dumps(observed.to_dict(), sort_keys=True)
        self.assertNotIn("SYNTHETIC_SECRET_MARKER", serialized)
        first = observed.fingerprint
        protected.chmod(0o600)
        protected.write_text("SYNTHETIC_SECRET_MARKER=changed-but-deliberately-unobserved\n", encoding="utf-8")
        protected.chmod(0)
        self.assertEqual(self.observation(root).fingerprint, first)

    def test_overlay_projection_uses_exact_ignore_decision_for_directory_rule(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        (root / ".gitignore").write_text("AGENTS.md\n.codex/\n", encoding="utf-8")
        git(root, "add", ".gitignore")
        git(root, "commit", "-qm", "synthetic managed-target ignores")
        overlays = {
            "AGENTS.md": b"synthetic managed instructions\n",
            ".codex/config.toml": b"synthetic = true\n",
        }
        identity = repository_identity_contract(root, local_repository_nonce="1" * 32)
        inspection = inspect_repository(root, local_repository_nonce="1" * 32)
        exclusion = {
            "contract": "sos_bootstrap_exclusion_policy_v2",
            "schema_major": 2,
            "control_plane_root": ".sigma",
            "staging_prefix": ".sigma.init.",
            "transaction_id": "2" * 64,
            "policy_digest": "sha256:" + "0" * 64,
        }
        exclusion["policy_digest"] = exclusion_policy_digest(exclusion)
        projected = dirty.observe_application(
            root,
            identity.repository_id,
            inspection.head or "",
            exclusion["policy_digest"],
            overlays=overlays,
        )
        (root / "AGENTS.md").write_bytes(overlays["AGENTS.md"])
        (root / ".codex").mkdir()
        (root / ".codex" / "config.toml").write_bytes(overlays[".codex/config.toml"])
        actual = dirty.observe_application(
            root,
            identity.repository_id,
            inspection.head or "",
            exclusion["policy_digest"],
        )
        self.assertTrue(projected.complete)
        self.assertEqual(projected, actual)
        self.assertEqual(projected.state, "clean")

    def test_tracked_overlay_remains_fingerprint_bound_despite_ignore_rule(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        (root / "AGENTS.md").write_text("tracked original\n", encoding="utf-8")
        git(root, "add", "AGENTS.md")
        (root / ".gitignore").write_text("AGENTS.md\n", encoding="utf-8")
        git(root, "add", ".gitignore")
        git(root, "commit", "-qm", "synthetic tracked managed target")
        identity = repository_identity_contract(root, local_repository_nonce="1" * 32)
        inspection = inspect_repository(root, local_repository_nonce="1" * 32)
        exclusion = {
            "contract": "sos_bootstrap_exclusion_policy_v2",
            "schema_major": 2,
            "control_plane_root": ".sigma",
            "staging_prefix": ".sigma.init.",
            "transaction_id": "2" * 64,
            "policy_digest": "sha256:" + "0" * 64,
        }
        exclusion["policy_digest"] = exclusion_policy_digest(exclusion)
        projected = dirty.observe_application(
            root,
            identity.repository_id,
            inspection.head or "",
            exclusion["policy_digest"],
            overlays={"AGENTS.md": b"tracked replacement\n"},
        )
        self.assertTrue(projected.complete)
        self.assertEqual(projected.state, "dirty")
        self.assertEqual(projected.entry_count, 1)
        self.assertGreater(projected.bytes_hashed, 0)

    def test_sensitive_name_grammar_distinguishes_public_sources_from_private_material(self) -> None:
        expected = {
            ".env": "environment_or_secret",
            ".env.local": "environment_or_secret",
            ".env.production": "environment_or_secret",
            "private/.env.example/value": "environment_or_secret",
            "database.dump": "production_or_database_dump",
            "prod_dump.sql": "production_or_database_dump",
            "database-backup.sql": "production_or_database_dump",
            "snapshot.sql": "production_or_database_dump",
        }
        for path, classification in expected.items():
            with self.subTest(path=path):
                self.assertEqual(dirty.sensitive_path_class(path), classification)

        for path in (
            ".env.example",
            ".env.sample",
            ".env.template",
            ".env.dist",
            "catalog.sql",
            "schema.sql",
            "migrations/001.sql",
            ".codex/config.toml",
        ):
            with self.subTest(path=path):
                self.assertIsNone(dirty.sensitive_path_class(path))

    def test_protected_directory_type_is_presence_bound(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        (root / ".gitignore").write_text(".env/\n", encoding="utf-8")
        git(root, "add", ".gitignore")
        git(root, "commit", "-qm", "synthetic directory ignore")
        protected = root / ".env"
        protected.mkdir()
        observed = self.observation(root)
        self.assertEqual(observed.state, "dirty")
        self.assertEqual(observed.protected_presence[0]["filesystem_type"], "directory")
        directory_fingerprint = observed.fingerprint
        protected.rmdir()
        protected.write_text("not opened\n", encoding="utf-8")
        file_observation = self.observation(root)
        self.assertNotEqual(file_observation.fingerprint, directory_fingerprint)
        self.assertEqual(file_observation.protected_presence[0]["filesystem_type"], "regular")

    def test_file_limit_and_snapshot_race_fail_closed(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        (root / "large.txt").write_bytes(b"12345")
        with mock.patch.object(dirty, "MAX_FILE_BYTES", 4):
            limited = self.observation(root)
        self.assertEqual(limited.state, "not_verified")
        self.assertIsNone(limited.fingerprint)
        self.assertEqual(limited.reasons, ("SOS_DIRTY_FILE_LIMIT_EXCEEDED",))

        with mock.patch.object(dirty, "MAX_TOTAL_BYTES", 4):
            total_limited = self.observation(root)
        self.assertEqual(total_limited.state, "not_verified")
        self.assertEqual(total_limited.reasons, ("SOS_DIRTY_TOTAL_LIMIT_EXCEEDED",))

        original = dirty._candidate_snapshot
        calls = 0

        def changed_snapshot(candidate: Path):
            nonlocal calls
            calls += 1
            value = original(candidate)
            if calls == 2:
                return value[0], value[1], value[2] + ("synthetic-race.txt",), value[3], value[4]
            return value

        with mock.patch.object(dirty, "_candidate_snapshot", side_effect=changed_snapshot):
            raced = self.observation(root)
        self.assertEqual(raced.state, "not_verified")
        self.assertIsNone(raced.fingerprint)
        self.assertEqual(raced.reasons, ("SOS_DIRTY_SNAPSHOT_RACE",))

    def test_candidate_path_limit_fails_before_filesystem_reads(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        baseline = dirty._candidate_snapshot(root)
        oversized = baseline[0], baseline[1], tuple(f"p-{index}" for index in range(10_001)), baseline[3], baseline[4]
        with mock.patch.object(dirty, "_candidate_snapshot", return_value=oversized):
            observed = self.observation(root)
        self.assertEqual(observed.state, "not_verified")
        self.assertIsNone(observed.fingerprint)
        self.assertEqual(observed.reasons, ("SOS_DIRTY_PATH_LIMIT_EXCEEDED",))

    def test_control_and_valid_staging_roots_are_exactly_excluded(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        (root / ".sigma").mkdir()
        (root / ".sigma" / "local.json").write_text("{}\n", encoding="utf-8")
        staging = root / (".sigma.init." + "a" * 64)
        staging.mkdir()
        (staging / "record.json").write_text("{}\n", encoding="utf-8")
        observed = self.observation(root)
        self.assertEqual(observed.state, "clean")
        lookalike = root / ".sigma.init.not-valid"
        lookalike.mkdir()
        (lookalike / "record.json").write_text("{}\n", encoding="utf-8")
        self.assertEqual(self.observation(root).state, "dirty")
        init = initialize_workspace(str(root), confirmed=True, controlling_tty_observed=True)
        self.assertEqual(init.status, "invalid")
        self.assertEqual(init.reasons, ("SOS_CONTROL_PLANE_COLLISION",))

    def test_unmerged_index_stages_are_complete_and_deterministic(self) -> None:
        temporary, root = self.make_project()
        self.addCleanup(temporary.cleanup)
        git(root, "checkout", "-qb", "synthetic-side")
        (root / "tracked.txt").write_text("side\n", encoding="utf-8")
        git(root, "commit", "-qam", "synthetic side")
        git(root, "checkout", "-q", "master")
        (root / "tracked.txt").write_text("main\n", encoding="utf-8")
        git(root, "commit", "-qam", "synthetic main")
        subprocess.run(
            ["git", "-C", str(root), "merge", "synthetic-side"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        first = self.observation(root)
        second = self.observation(root)
        self.assertEqual(first, second)
        self.assertTrue(first.complete)
        self.assertEqual(first.state, "dirty")
        self.assertGreaterEqual(first.entry_count, 3)

    def test_submodule_identity_changes_without_recursive_content_hashing(self) -> None:
        temporary, root = self.make_project()
        module_temporary, module = self.make_project()
        self.addCleanup(temporary.cleanup)
        self.addCleanup(module_temporary.cleanup)
        subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "-c",
                "protocol.file.allow=always",
                "submodule",
                "add",
                "-q",
                str(module),
                "vendor/module",
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        git(root, "commit", "-qam", "synthetic submodule")
        checkout = root / "vendor" / "module"
        (checkout / "tracked.txt").write_text("submodule dirty one\n", encoding="utf-8")
        first = self.observation(root)
        self.assertEqual(first.state, "dirty")
        self.assertEqual(first.entry_count, 1)
        self.assertEqual(first.bytes_hashed, 0)
        (checkout / "tracked.txt").write_text("submodule dirty two\n", encoding="utf-8")
        second = self.observation(root)
        # The v2 contract intentionally binds only the recursive dirty booleans,
        # not submodule content bytes.  Both states are tracked-dirty.
        self.assertEqual(first.fingerprint, second.fingerprint)


if __name__ == "__main__":
    unittest.main()

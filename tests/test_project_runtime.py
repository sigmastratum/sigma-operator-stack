from __future__ import annotations

import copy
import unittest

from sos.contracts import digest_value
from sos.maintenance_binding import MaintenanceLauncherBinding
from sos.project_runtime import (
    ProjectRuntimeError, runtime_identity, validate_runtime_identity,
    transition_event, validate_transition_chain,
)


def digest(label: str) -> str:
    return digest_value({"synthetic": label})


class ProjectRuntimeTests(unittest.TestCase):
    def inputs(self) -> dict:
        return dict(
            owner_digest=digest("user"), root_digest=digest("root"),
            repository_digest=digest("repo"), wheel_digest=digest("wheel"),
            interpreter_digest=digest("python"),
            maintenance_binding=MaintenanceLauncherBinding(
                "0.1.0a6", "v0.1.0a6", "1" * 40, "2" * 40,
                "SOS-Linux-0.1.0a6.zip", "3" * 64, "4" * 64,
                "linux", "x86_64", "linux-native-alpha", "Install-SOS.command", "5" * 64,
            ).payload(),
        )

    def anchors(self) -> dict:
        return dict(plan_digest=digest("plan"), predecessor_receipt_digest=digest("receipt"),
                    identity_digest=runtime_identity(**self.inputs())["identity_digest"])

    def chain(self) -> list:
        events = []
        for state in ("previewed", "confirmed", "provisioning", "ready", "switching", "committed"):
            events.append(transition_event(state=state, previous=events[-1] if events else None, **self.anchors()))
        return events

    def validate_identity(self, value: object, **changes):
        inputs = self.inputs()
        observed = {key: inputs[key] for key in ("owner_digest", "root_digest", "repository_digest")}
        return validate_runtime_identity(value, **(observed | changes))

    def test_deterministic_roundtrip_and_no_input_mutation(self):
        inputs = self.inputs()
        before = copy.deepcopy(inputs)
        identity = runtime_identity(**inputs)
        self.assertEqual(identity, runtime_identity(**inputs))
        self.assertEqual(identity, self.validate_identity(identity))
        self.assertEqual(inputs, before)
        self.assertIs(identity["absolute_paths_serialized"], False)
        self.assertIs(identity["raw_content_serialized"], False)

    def test_two_projects_users_and_copies_have_distinct_keys(self):
        inputs = self.inputs()
        first = runtime_identity(**inputs)
        for key in ("root_digest", "owner_digest", "repository_digest"):
            with self.subTest(key=key):
                changed = inputs | {key: digest("other")}
                second = runtime_identity(**changed)
                self.assertNotEqual(first["project_key"], second["project_key"])
                self.assertNotEqual(first["generation_key"], second["generation_key"])
                with self.assertRaises(ProjectRuntimeError):
                    self.validate_identity(first, **{key: digest("other")})

    def test_artifact_drift_changes_generation_not_project(self):
        inputs = self.inputs()
        first = runtime_identity(**inputs)
        for key in ("wheel_digest", "interpreter_digest"):
            second = runtime_identity(**(inputs | {key: digest("other")}))
            self.assertEqual(first["project_key"], second["project_key"])
            self.assertNotEqual(first["generation_key"], second["generation_key"])
        binding = MaintenanceLauncherBinding.from_payload(inputs["maintenance_binding"])
        payload = binding.payload(include_digest=False)
        payload["archive_sha256"] = "6" * 64
        second = runtime_identity(**(inputs | {"maintenance_binding": payload}))
        self.assertNotEqual(first["generation_key"], second["generation_key"])

    def test_identity_rejects_missing_extra_tampered_and_resealed_keys(self):
        original = runtime_identity(**self.inputs())
        for key in original:
            bad = copy.deepcopy(original)
            del bad[key]
            with self.subTest(missing=key), self.assertRaises(ProjectRuntimeError):
                self.validate_identity(bad)
        for patch in ({"extra": "raw"}, {"raw_content_serialized": True},
                      {"project_key": digest("other")}, {"generation_key": digest("other")}):
            bad = original | patch
            bad["identity_digest"] = digest_value({k: v for k, v in bad.items() if k != "identity_digest"})
            with self.subTest(patch=patch), self.assertRaises(ProjectRuntimeError):
                self.validate_identity(bad)

    def test_identity_refuses_malformed_digests_and_unsupported_platform(self):
        for value in (None, 1, True, [], {}, "sha256:abc", "sha256:" + "A" * 64, digest("x") + "\n"):
            with self.subTest(value=value), self.assertRaises(ProjectRuntimeError):
                runtime_identity(**(self.inputs() | {"owner_digest": value}))
        inputs = self.inputs()
        binding = inputs["maintenance_binding"]
        binding.pop("binding_digest")
        binding["system"] = "windows"
        with self.assertRaises(ProjectRuntimeError):
            runtime_identity(**inputs)

    def test_complete_chain_and_anchors_are_not_mutated(self):
        chain = self.chain()
        before = copy.deepcopy(chain)
        tip = validate_transition_chain(chain, expected_tip_digest=chain[-1]["event_digest"], **self.anchors())
        self.assertEqual(tip["state"], "committed")
        self.assertEqual(chain, before)
        tip["state"] = "aborted"
        self.assertEqual(chain[-1]["state"], "committed")

    def test_chain_rejects_omission_reorder_duplicate_prefix_and_foreign_anchor(self):
        chain = self.chain()
        for bad in ([], chain[1:], chain[:-1], chain[:2] + chain[3:],
                    chain[:2] + [chain[1]] + chain[2:], list(reversed(chain))):
            with self.subTest(chain=bad), self.assertRaises(ProjectRuntimeError):
                validate_transition_chain(bad, expected_tip_digest=chain[-1]["event_digest"], **self.anchors())
        for key in self.anchors():
            with self.subTest(anchor=key), self.assertRaises(ProjectRuntimeError):
                validate_transition_chain(chain, expected_tip_digest=chain[-1]["event_digest"],
                                          **(self.anchors() | {key: digest("foreign")}))

    def test_no_skipped_phases_or_terminal_reopening(self):
        chain = self.chain()
        for prior, state in ((None, "committed"), (chain[0], "ready"),
                             (chain[2], "committed"), (chain[-1], "switching")):
            with self.subTest(state=state), self.assertRaises(ProjectRuntimeError):
                transition_event(state=state, previous=prior, **self.anchors())

    def test_abort_is_terminal_and_chain_tip_is_required(self):
        first = self.chain()[0]
        aborted = transition_event(state="aborted", previous=first, **self.anchors())
        chain = [first, aborted]
        self.assertEqual(validate_transition_chain(
            chain, expected_tip_digest=aborted["event_digest"], **self.anchors()
        )["state"], "aborted")
        with self.assertRaises(ProjectRuntimeError):
            transition_event(state="confirmed", previous=aborted, **self.anchors())
        for tip in (None, digest("foreign")):
            with self.subTest(tip=tip), self.assertRaises(ProjectRuntimeError):
                validate_transition_chain(chain, expected_tip_digest=tip, **self.anchors())

    def test_chain_rejects_resealed_fork(self):
        chain = self.chain()
        chain[3]["previous_digest"] = digest("another-branch")
        chain[3]["event_digest"] = digest_value({k: v for k, v in chain[3].items() if k != "event_digest"})
        with self.assertRaises(ProjectRuntimeError):
            validate_transition_chain(chain, expected_tip_digest=chain[-1]["event_digest"], **self.anchors())

    def test_failure_cannot_be_projected_as_committed(self):
        chain = self.chain()[:-1]
        failed = transition_event(state="recovery_required", previous=chain[-1], **self.anchors())
        with self.assertRaises(ProjectRuntimeError):
            transition_event(state="committed", previous=failed, **self.anchors())
        restored = transition_event(state="rolled_back", previous=failed, **self.anchors())
        result = validate_transition_chain(chain + [failed, restored],
                                          expected_tip_digest=restored["event_digest"], **self.anchors())
        self.assertEqual(result["state"], "rolled_back")

    def test_malformed_events_fail_closed_even_with_recomputed_digest(self):
        chain = self.chain()
        for patch in ({"sequence": True}, {"sequence": -1}, {"state": []},
                      {"previous_digest": "invalid"}, {"raw_content_serialized": 0},
                      {"unexpected": True}):
            bad = copy.deepcopy(chain)
            bad[1].update(patch)
            bad[1]["event_digest"] = digest_value({k: v for k, v in bad[1].items() if k != "event_digest"})
            with self.subTest(patch=patch), self.assertRaises(ProjectRuntimeError):
                validate_transition_chain(bad, expected_tip_digest=chain[-1]["event_digest"], **self.anchors())

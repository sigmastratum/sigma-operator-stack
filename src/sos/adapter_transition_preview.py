"""Read-only exact target projection using the installed adapters' renderers.

Rollback bytes are reconstructed and checked in memory; no temporary project or
adapter installation is needed to show a transition preview.
"""

from __future__ import annotations

import hashlib

from . import client_integration as codex
from . import claude_integration as claude
from .project_runtime import ProjectRuntimeError


def _hash(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def exact_adapter_targets(root, clients, successor, *, with_images=False):
    targets = []
    images = {}
    for client in clients:
        manifest = (codex._read_setup_manifest(root) if client == "codex"
                    else claude._read_manifest(root))
        if manifest is None or manifest["state"] != "installed":
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_ADAPTER_NOT_INSTALLED")
        for old in manifest["plans"]:
            name = old["target"]
            current, exists, mode = codex.read_integration_target(root, name)
            if not exists or _hash(current) != old["after_digest"]:
                raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PREVIEW_STALE")
            offset = old.get("patch_offset", old["before_byte_count"])
            count = old["patch_byte_count"]
            patch = current[offset:offset + count]
            before = current[:offset] + current[offset + count:]
            if (_hash(patch) != old["patch_digest"] or _hash(before) != old["before_digest"]
                    or len(before) != old["before_byte_count"]):
                raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_PREVIEW_STALE")
            if client == "codex":
                addition = (codex._render_instruction_addition(before) if name == "AGENTS.md"
                            else codex._render_addition(root, successor, before))
                after = before + addition
                if name == ".codex/config.toml":
                    codex._validate_toml(after)
                after_mode = mode if old["before_exists"] else (0o600 if name == ".codex/config.toml" else 0o644)
            elif name == "CLAUDE.md":
                separator = b"" if not before else (b"\n" if before.endswith(b"\n") else b"\n\n")
                after = before + separator + claude._INSTRUCTION_BLOCK
                after_mode = mode if old["before_exists"] else 0o644
            elif name == ".mcp.json":
                if old["before_exists"]:
                    insert, addition = claude._mcp_insert_patch(before, root, successor)
                    after = before[:insert] + addition + before[insert:]
                else:
                    after = claude._new_mcp_file(root, successor)
                claude._strict_json(after)
                after_mode = mode if old["before_exists"] else 0o644
            else:
                raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_TARGET_UNKNOWN")
            targets.append({"client": client, "target": name,
                            "before_digest": _hash(current), "before_mode": mode,
                            "after_digest": _hash(after), "after_mode": after_mode,
                            "after_byte_count": len(after)})
            images[name] = after
    # Images are process-local renderer inputs, never journal/receipt fields.
    return (targets, images) if with_images else targets


def verify_adapter_targets(root, targets, *, after: bool):
    prefix = "after" if after else "before"
    for row in targets:
        content, exists, mode = codex.read_integration_target(root, row["target"])
        if not exists or _hash(content) != row[prefix + "_digest"] or mode != row[prefix + "_mode"]:
            raise ProjectRuntimeError("SOS_PROJECT_RUNTIME_TARGET_DRIFT")

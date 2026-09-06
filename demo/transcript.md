# SOS 0.1.0a5 URL-only Linux demo transcript

This is the canonical content-safe transcript for a real provider-backed Codex
capture against a marker-owned synthetic Git repository. It is bound to SOS
product candidate `ae59b5ac6faf4fa6fe3443550a575ed1b32cfb51`, tree
`e5d75f4b52ff1ed4668bb4572ba1d424af7b8c09`, and the published Linux archive.
Host paths, session identifiers, raw prompts, raw responses and raw tool results
are not retained.

## Scene 1 — URL-only entry

A fresh Codex session receives exactly the public repository URL and:

> Install SOS in my current project. Show me the preview before changing it.

Codex reads the canonical public instructions. It verifies `release/current.json`,
the immutable `v0.1.0a5` tag, release index, Linux x86_64 archive, inner manifest,
wheel and bundled checksums. It does not substitute a branch archive or install
Python, `uv`, or dependencies manually.

## Scene 2 — exact preview and human confirmation

The verified launcher prepares the SOS-owned per-user environment outside the
project. It then produces one aggregate project plan:

- create `.sigma/` control-plane records;
- create the bounded SOS integration in `AGENTS.md`;
- create the project-local MCP configuration in `.codex/config.toml`;
- exclude qualification from installation.

The plan digest is
`sha256:8690e4358a879141a3e57362dbd672cc1872db1150ada653addd943340fa8ad7`.
The project remains unchanged until the human explicitly confirms this exact
plan. After confirmation, installation reports `SOS_WORKSPACE_CURRENT` and the
synthetic user sentinel retains its original SHA-256.

## Scene 3 — genuinely fresh recovery

A new Codex session starts with the installed project configuration. It calls
only the project-local `sigma_operator_stack` MCP server. Six read/proposal
tools complete: `sos_status`, `sos_preflight`, `sos_active_task`,
`sos_next_action`, `sos_qualification_plan`, and `sos_recover`. Shell calls,
mutation tools and external actions are zero in this recovery session.

SOS reports:

- authority: accepted locally with weak evidence;
- workspace: current, control-plane integrity valid;
- current work: `not_configured`, owner input required;
- qualification: `not_verified`, with both registered families unconfigured;
- external actions: owner-required;
- safe next action: review the project map, declare current work, then follow
  the separate doctor and qualification flow.

No green qualification claim is made. No project file changes during recovery.

## Capture accounting and scope

The retained product sequence consists of three successful Codex turns:
verified preview, confirmed installation, and fresh recovery. The public receipt
also accounts for six discarded capture-preparation requests, including three
schema rejections. Those preparation attempts are not product evidence. One
separately approved TTS request generated the narration.

The capture runner used a disposable synthetic project and user environment
because nested Linux `bwrap` is unavailable on the recording host. This is a
capture-harness constraint, not a change to SOS installation semantics. The
demo proves the current Linux URL-only route. It does not claim notarized macOS,
Windows Store readiness, broad agent support, adoption, or time savings.

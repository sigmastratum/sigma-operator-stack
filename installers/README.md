# Installer build sources

> **These files are not a public SOS installer. Do not download or run an individual script from this directory.**

This directory contains source code, templates, manifests, and test entrypoints
used to build the platform release packages. Files such as
`Install-SOS.command`, `Install-SOS.ps1`, and the Windows Go sources work only
inside a complete, digest-verified release bundle with its pinned `uv`, SOS
wheel, dependency wheelhouse, manifest, and checksums.

Public availability is determined only by a valid `release/current.json` whose
immutable tag, release index and digest-bound assets are all reachable.
Cloning a branch, downloading GitHub's automatic source archive, or running a
raw file from this directory is never a supported installation route.

To install a release:

1. return to the [repository README](../README.md);
2. follow the [canonical install-with-Codex route](../docs/install-with-codex.md);
3. use only the exact artifact selected through the published release pointer
   and verify its checksums before setup.

SOS must show one complete preview before it changes a project. Do not bypass
TLS verification, Gatekeeper, Windows security, permissions, or package
integrity checks to make an incomplete bundle run.

## For contributors

The files here are retained in source control so platform packages can be
reviewed, tested, and rebuilt from an exact Git candidate. They are inputs to
the release builders and CI checks; they are not standalone end-user assets.

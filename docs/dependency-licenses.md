# Dependency and license inventory

The machine-readable authority is
[`requirements/dependency-licenses.json`](../requirements/dependency-licenses.json).
An exact requirement, bundled wheel or product dependency missing from that
inventory blocks release.

## Distributed Python runtime

The SOS wheel is Apache-2.0. The exact native runtime wheelhouse contains
`attrs 26.1.0`, `jsonschema 4.26.0`, `jsonschema-specifications 2025.9.1`,
`referencing 0.37.0`, `rpds-py 2026.6.3` under MIT and
`typing-extensions 4.16.0` under PSF-2.0. The checker verifies version,
declared license and the upstream license file inside every supplied wheel.

## Release-only tooling

The direct pinned tools in `requirements/release.txt` and
`requirements/audit.txt` are qualification inputs, not contents of the SOS
wheel. Their licenses are nevertheless recorded and checked. The release SBOM
must contain a complete, known-license dependency closure for the exact SOS
wheel environment; unrelated tooling in the generator environment is not part
of that closure.

## NOTICE decision

A repository-root `NOTICE` is not required for this source preview or the
current SOS wheel. The distributed Python dependency graph has MIT and
PSF-2.0 attribution obligations, while the CycloneDX Apache NOTICE belongs to
release-only tooling that is not redistributed in the wheel.

Native archives and MSIX packages additionally carry Python, `uv` and platform
payloads. Their later release gates must retain every applicable upstream
license or NOTICE in the exact artifact. This decision does not authorize a
native release that omits those files.

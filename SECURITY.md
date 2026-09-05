# Security Policy

## Supported versions

Security reports are accepted for both the public source and the exact alpha
artifacts selected by `release/current.json`. A checked-in pointer is not proof
that a release is available: the immutable tag, index and digest-bound assets
must also be public and mutually consistent.

Security fixes are provided for the latest published `0.1.x` alpha only. The
project is pre-1.0: compatibility may change,
but security boundaries must fail closed rather than silently weaken.

## Reporting a vulnerability

Use GitHub's **Report a vulnerability** private reporting form for this
repository. Do not open a public issue, discussion or pull request containing
an exploit, credential, private repository content or identifying host data.

Include the affected version, a minimal synthetic reproducer, the expected
security boundary and the observed result. Maintainers will acknowledge the
report through GitHub and coordinate disclosure there. No response or repair
SLA is promised for the community alpha.

SOS never needs repository credentials, provider tokens or production data to
reproduce a security report. Redact them before submitting any material.

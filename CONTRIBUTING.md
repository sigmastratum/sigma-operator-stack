# Contributing

Thank you for helping improve Sigma Operator Stack.

## Before opening a change

- Use GitHub Discussions for questions and GitHub Issues for reproducible bugs.
- Read [PUBLIC_REPOSITORY_BOUNDARY.md](PUBLIC_REPOSITORY_BOUNDARY.md).
- Use only synthetic fixtures. Never commit credentials, private paths, raw
  conversations, customer/session identifiers or internal evidence.
- Keep mutation and authority surfaces explicit and fail closed.

## Development

SOS supports Python 3.11 and 3.12 on Linux x86_64. From a conventional Git
checkout with `jsonschema` installed:

```bash
PYTHONPATH=src python3 tools/run_zero_skip_tests.py
python3 tools/check_public_release.py --repository .
```

All tests must pass with zero skips. Changes to schemas, qualification,
installation, MCP tools or release workflows need focused negative tests.

## Sign-off and license

The project uses the Developer Certificate of Origin 1.1 and does not require
a Contributor License Agreement. Sign each commit with:

```text
Signed-off-by: Your Name <your-email@example.com>
```

`git commit -s` adds this line. By contributing, you certify the
[Developer Certificate of Origin](https://developercertificate.org/) and agree
that your contribution is licensed under Apache-2.0.

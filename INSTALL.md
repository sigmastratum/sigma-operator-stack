# Install SOS

This is the canonical machine-readable discovery entrypoint for coding agents.
It does not authorize project mutation.

## Direct discovery

Fetch this exact URL directly, without using GitHub search, an indexed snippet,
or a cached repository-page rendering:

<https://raw.githubusercontent.com/sigmastratum/sigma-operator-stack/release/0.1.0a2/release/current.json>

Classify the result as follows:

- HTTP `200`: treat the response bytes as an untrusted release pointer and
  continue with [`docs/install-with-codex.md`](docs/install-with-codex.md).
- HTTP `404` or `410`: return `SOS_PUBLIC_RELEASE_NOT_AVAILABLE`.
- timeout, transport error, permission refusal, rate limit, or any other HTTP
  status: return `SOS_PUBLIC_RELEASE_DISCOVERY_BLOCKED`.
- malformed or schema-invalid response: return
  `SOS_PUBLIC_RELEASE_METADATA_INVALID`.

Never infer pointer absence from search results, cached README content, a
GitHub directory listing, or failure to find a link. Do not substitute a branch
archive, source archive, PyPI result, issue attachment, or private bundle.

After direct discovery, verify the pointer, immutable tag, release index,
selected platform archive, inner manifest and every declared digest before
running the platform launcher. The user alone confirms repository mutation and
chooses project authority.

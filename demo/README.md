# Reproducible demo assets

`transcript.md` is the canonical public evidence. `capture.sh` resets the
synthetic project and runs the same commands in a real terminal. The operator
must answer the two product confirmations; the script does not inject hidden
approval.

`terminal-frame.txt` is the canonical content-safe terminal frame and
`render_terminal_png.py` deterministically produces `recovery-terminal.png`.
It contains only synthetic commands and typed outcomes; it is not presented as
a provider-backed Codex session.

The final WebM, MP4, PNG, and recovery screenshot are generated only from the
exact release candidate after all support-boundary gates are current. This
public-preparation source contains a draft transcript, capture contract,
diagram, and deterministic PNG renderer; it does not simulate a fresh Codex
session or ship stale video.

Capture requirements:

- terminal: 100 columns by 30 rows, dark background, 16 px monospace;
- no host prompt, username, repository path, environment, credentials, or
  network access in frame;
- captions follow `transcript.md` exactly;
- WebM and MP4 must each remain below 2 MiB;
- GIF is optional and only retained when readable below the same limit;
- media metadata and extracted text must pass the public-content scanner.

Rebuild deterministic PNG assets with:

```bash
python3 demo/render_draft_png.py
python3 demo/render_terminal_png.py
```

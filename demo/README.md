# Reproducible demo assets

`transcript.md` is the canonical public evidence. `capture.sh` resets the
synthetic project and runs the same commands in a real terminal. The operator
must answer the two product confirmations; the script does not inject hidden
approval.

`terminal-frame.txt` is the canonical content-safe terminal frame and
`render_terminal_png.py` deterministically produces `recovery-terminal.png`.
It contains only synthetic commands and typed outcomes; it is not presented as
a provider-backed Codex session.

`recovery-demo.webm` and `recovery-demo.mp4` are deterministic zero-provider
terminal media generated from `terminal-frame.txt`. They demonstrate the local
typed lifecycle and do not simulate a fresh Codex session. A genuine
provider-backed fresh-session capture remains a separately approved release
action.

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
python3 demo/render_video.py --ffmpeg /path/to/ffmpeg
```

The video renderer uses fixed arguments, strips source metadata, validates
size, and rewrites `media-manifest.json`. The containers retain only ordinary
codec/muxer identification. Rebuilding with a different encoder version changes
the media digest and therefore requires a release-evidence rebind.

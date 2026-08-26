# Reproducible demo assets

`transcript.md` is the canonical public evidence. `capture.sh` resets the
synthetic project and runs the same commands in a real terminal. The operator
must answer the two product confirmations; the script does not inject hidden
approval.

`terminal-frame.txt` is the canonical content-safe terminal frame and
`render_terminal_png.py` deterministically produces `recovery-terminal.png`.
It contains only synthetic commands, typed outcomes, and the result of one
receipt-verified ephemeral Codex recovery. Raw task text, response text, tool
results, session identifiers and absolute paths are never retained.

`recovery-demo.webm` and `recovery-demo.mp4` are deterministic terminal media
generated from `terminal-frame.txt`. The local lifecycle is offline. Exactly
one explicitly approved provider-backed Codex step is projected through
`fresh-codex-receipt.json`; preparation failures are not release evidence.

The final cut opens with the product outcome in the first frame, then moves to
the exact terminal sequence after two seconds. `voiceover.txt` is the canonical
public narration. One separately approved TTS call generates `voiceover.mp3`;
the media manifest binds its model, voice, text, bytes and provider-call count.

`capture_fresh_codex.py` accepts the operator instruction from an external
temporary file, runs Codex with `--ephemeral`, `--ignore-user-config`, a
read-only sandbox and only the generated eight-tool SOS MCP allow-list, then
deletes raw events and response with its temporary directory. The public
receipt stores only categorical recovery fields, tool names and digests.

Capture requirements:

- terminal: 100 columns by 30 rows, dark background, 16 px monospace;
- no host prompt, username, repository path, environment, credentials, or
  network access in frame;
- captions follow `transcript.md` exactly;
- narration follows `voiceover.txt` exactly and begins with the first frame;
- WebM and MP4 must each remain below 2 MiB;
- GIF is optional and only retained when readable below the same limit;
- media metadata and extracted text must pass the public-content scanner.
- the fresh step requires `SOS_FRESH_CODEX_PROVIDER_APPROVED=1`; no default or
  hidden provider call exists;
- `SOS_FRESH_CODEX_TASK_FILE` is external and is never copied or hashed into
  the repository.

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

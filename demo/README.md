# Reproducible SOS 0.1.0a5 demo assets

This directory contains the current Linux-primary URL-only demonstration. It
is bound to product candidate `ae59b5ac6faf4fa6fe3443550a575ed1b32cfb51`
and the published `v0.1.0a5` Linux archive.

`transcript.md` is the canonical public text equivalent. `terminal-frame.txt`
is the content-safe terminal projection; `render_terminal_png.py` renders
`recovery-terminal.png` deterministically. `render_video.py` combines the
frame sequence with the exact narration in `voiceover.txt` and the single
approved TTS result in `voiceover.mp3`.

`fresh-codex-receipt.json` records only categorical and digest-bound evidence:
the exact release bindings, preview digest, explicit human confirmation,
sentinel preservation, provider-request accounting, and six completed
read/proposal SOS MCP tools in a genuinely fresh session. Raw prompts,
responses, tool results, session identifiers and absolute paths are not kept.

The retained product sequence is:

1. a fresh Codex session receives only the repository URL and canonical install
   instruction;
2. Codex verifies the pointer, tag, index, Linux archive and inner manifest,
   then runs the verified launcher to obtain the exact preview;
3. a human confirms the digest-bound plan;
4. Codex completes installation without running qualification;
5. a genuinely fresh Codex session recovers currentness, boundaries,
   `not_configured`, `not_verified`, and one safe next action using only the
   project-local SOS MCP server.

The capture used a marker-owned disposable project and user environment. The
recording host cannot nest Codex's Linux `bwrap` sandbox, so the capture runner
was externally bounded to that disposable root. This limitation is explicit in
the transcript and does not alter the product's preview or authority rules.

Media requirements:

- 60–120 seconds, 1200×800, dark terminal presentation;
- no username, host prompt, absolute path, credential, raw conversation or raw
  tool output;
- narration is exactly `voiceover.txt`;
- MP4 and WebM are each below 2 MiB;
- all media, text, release and provider-call bindings are verified by the
  public scanner.

Rebuild deterministic local render products with:

```bash
python3 demo/render_terminal_png.py
python3 demo/render_video.py --ffmpeg /path/to/ffmpeg
```

The old `0.1.0a2` principle demo is retained only in Git history. This packet
does not claim notarized macOS, Windows support, broad agent support, adoption,
or time savings.

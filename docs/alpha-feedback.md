# Alpha feedback

The most useful report is a small synthetic reproduction with one exact SOS
result. Do not send a real repository or a complete `.sigma` directory.

## Include

- `sos --version` output;
- the support profile: OS, architecture, Python version and filesystem class;
- the exact SOS command and exit code;
- the first `SOS_...` reason code;
- whether this was install, qualification, recovery, update or removal;
- minimal reproduction steps in a new disposable Git repository;
- what you expected and what happened instead.

Use the matching typed GitHub issue form. Invited private-alpha testers may
send the same fields through their existing invitation channel until Issues
are public.

## Do not include

- private source, filenames or repository structure;
- raw `.sigma` files, prompts, messages or agent tool payloads;
- usernames, absolute paths, hostnames or customer identifiers;
- `.env` values, credentials, access tokens or crash dumps;
- production or client data.

For a platform refusal, the content-safe `sos capabilities --json` result is
acceptable after confirming it contains no locally added fields. For all
other failures, report the reason code rather than attaching internal state.

Security vulnerabilities do not belong in a public issue. Use GitHub private
vulnerability reporting as described in [`../SECURITY.md`](../SECURITY.md).

# Windows WACK disposition

The supported Windows alpha profile is Windows 11 x86_64 Desktop with UAC
enabled. Windows S mode is not claimed.

Every Windows Store candidate is checked with the Windows App Certification
Kit. All non-optional tests must pass and unresolved warnings are forbidden.
The sole bounded exception is the optional Desktop Bridge `Blocked
executables` result when every finding is a package-relative file finding.
Microsoft documents this test as Windows S-mode compatibility guidance and
states that a finding may be ignored when the flagged file is part of the
application:

<https://learn.microsoft.com/windows/uwp/debug-test-perf/windows-desktop-bridge-app-tests>

`tools/verify_windows_wack_report.py` enforces that disposition without
serializing file paths or message contents. Any other failure, malformed or
absolute finding, duplicate test, missing DPI test, warning, or changed test
shape fails closed.

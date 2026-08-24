"""Host-safe SOS entry point.

Only standard-library and package-identity modules may be imported here. The
Linux implementation is loaded after host admission succeeds.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence

from . import __version__
from .platform_admission import admit_host


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments == ["--version"]:
        print(f"sos {__version__}")
        return 0
    admission = admit_host()
    if admission.status != "success":
        payload = admission.to_dict()
        if "--json" in arguments:
            print(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
        else:
            print(json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False))
        return 2
    from .cli import main as linux_main

    return linux_main(arguments)

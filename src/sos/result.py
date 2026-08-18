"""Closed terminal result contracts used by CLI and later adapters."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any


class Status(StrEnum):
    INVALID = "invalid"
    BLOCKED = "blocked"
    UNSUPPORTED = "unsupported"
    STALE = "stale"
    OWNER_REQUIRED = "owner_required"
    NOT_VERIFIED = "not_verified"
    SUCCESS = "success"


STATUS_PRECEDENCE = (
    Status.INVALID,
    Status.BLOCKED,
    Status.UNSUPPORTED,
    Status.STALE,
    Status.OWNER_REQUIRED,
    Status.NOT_VERIFIED,
    Status.SUCCESS,
)


@dataclass(frozen=True, slots=True)
class TerminalResult:
    contract: str
    status: Status
    reasons: tuple[str, ...]
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["status"] = self.status.value
        value["reasons"] = list(self.reasons)
        return value


def highest_status(statuses: list[Status]) -> Status:
    observed = set(statuses)
    return next(status for status in STATUS_PRECEDENCE if status in observed)


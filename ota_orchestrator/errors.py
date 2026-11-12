from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class Violation:
    code: str
    message: str
    path: str = ""
    details: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.path:
            value["path"] = self.path
        if self.details:
            value["details"] = self.details
        return value


class DomainError(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        path: str = "",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.path = path
        self.details = details or {}

    def as_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.path:
            value["path"] = self.path
        if self.details:
            value["details"] = self.details
        return value


class ValidationError(DomainError):
    def __init__(self, violations: Iterable[Violation]) -> None:
        self.violations = tuple(violations)
        message = "; ".join(item.message for item in self.violations)
        super().__init__(
            "validation_failed",
            message or "validation failed",
            details={"violations": [item.as_dict() for item in self.violations]},
        )


class ConflictError(DomainError):
    pass


class NotFoundError(DomainError):
    pass


class StateError(DomainError):
    pass


class ReceiptError(DomainError):
    pass


class IntegrityError(DomainError):
    pass


def fail(code: str, message: str, **details: Any) -> None:
    raise DomainError(code, message, details=details)


def require(condition: bool, code: str, message: str, **details: Any) -> None:
    if not condition:
        raise DomainError(code, message, details=details)


def require_state(condition: bool, code: str, message: str, **details: Any) -> None:
    if not condition:
        raise StateError(code, message, details=details)


def require_receipt(condition: bool, code: str, message: str, **details: Any) -> None:
    if not condition:
        raise ReceiptError(code, message, details=details)


from __future__ import annotations

import hashlib
import json
import math
import re
import statistics
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable, Iterator, Mapping, Sequence, TypeVar

from .errors import DomainError, Violation


T = TypeVar("T")
SEMVER_PATTERN = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?$")
HEX_64_PATTERN = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")


@dataclass(frozen=True, order=True)
class Version:
    major: int
    minor: int
    patch: int
    prerelease: tuple[str, ...] = ()

    @classmethod
    def parse(cls, value: str, path: str = "version") -> "Version":
        if not isinstance(value, str):
            raise DomainError("invalid_version", f"{path} must be a semantic version", path=path)
        match = SEMVER_PATTERN.fullmatch(value)
        if not match:
            raise DomainError("invalid_version", f"{path} must be a semantic version", path=path)
        prerelease = tuple((match.group(4) or "").split(".")) if match.group(4) else ()
        return cls(int(match.group(1)), int(match.group(2)), int(match.group(3)), prerelease)

    def __str__(self) -> str:
        base = f"{self.major}.{self.minor}.{self.patch}"
        return base if not self.prerelease else f"{base}-{'-'.join(self.prerelease)}"

    def release_key(self) -> tuple[int, int, int, int]:
        return (self.major, self.minor, self.patch, 1 if not self.prerelease else 0)


def parse_time(value: str, path: str = "timestamp") -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise DomainError("invalid_timestamp", f"{path} must be an ISO-8601 timestamp", path=path)
    normalized = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise DomainError("invalid_timestamp", f"{path} must be an ISO-8601 timestamp", path=path) from exc
    if parsed.tzinfo is None:
        raise DomainError("timezone_required", f"{path} must include a timezone", path=path)
    return parsed.astimezone(timezone.utc)


def iso_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def add_seconds(value: str, seconds: int | float) -> str:
    return iso_time(parse_time(value) + timedelta(seconds=seconds))


def stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def fingerprint(value: Any) -> str:
    return sha256_text(stable_json(value))


def deterministic_bucket(seed: str, modulus: int = 1_000_000) -> int:
    if modulus <= 0:
        raise DomainError("invalid_modulus", "modulus must be positive", details={"modulus": modulus})
    digest = hashlib.sha256(seed.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % modulus


def deterministic_order(values: Iterable[T], key: Callable[[T], str], salt: str) -> list[T]:
    return sorted(values, key=lambda item: (deterministic_bucket(f"{salt}|{key(item)}"), key(item)))


def require_mapping(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise DomainError("invalid_object", f"{path} must be an object", path=path)
    return value


def require_list(value: Any, path: str, *, minimum: int = 0) -> list[Any]:
    if not isinstance(value, list):
        raise DomainError("invalid_array", f"{path} must be an array", path=path)
    if len(value) < minimum:
        raise DomainError("array_too_short", f"{path} must contain at least {minimum} items", path=path)
    return value


def require_string(
    value: Any,
    path: str,
    *,
    minimum: int = 1,
    maximum: int = 4096,
    pattern: re.Pattern[str] | None = None,
) -> str:
    if not isinstance(value, str):
        raise DomainError("invalid_string", f"{path} must be a string", path=path)
    result = value.strip()
    if not minimum <= len(result) <= maximum:
        raise DomainError(
            "invalid_string_length",
            f"{path} length must be between {minimum} and {maximum}",
            path=path,
        )
    if pattern and not pattern.fullmatch(result):
        raise DomainError("invalid_string_format", f"{path} has an invalid format", path=path)
    return result


def optional_string(value: Any, path: str, *, maximum: int = 4096) -> str | None:
    if value is None:
        return None
    return require_string(value, path, minimum=0, maximum=maximum)


def require_bool(value: Any, path: str) -> bool:
    if type(value) is not bool:
        raise DomainError("invalid_boolean", f"{path} must be a boolean", path=path)
    return value


def require_int(value: Any, path: str, *, minimum: int | None = None, maximum: int | None = None) -> int:
    if type(value) is not int:
        raise DomainError("invalid_integer", f"{path} must be an integer", path=path)
    if minimum is not None and value < minimum:
        raise DomainError("integer_too_small", f"{path} must be at least {minimum}", path=path)
    if maximum is not None and value > maximum:
        raise DomainError("integer_too_large", f"{path} must be at most {maximum}", path=path)
    return value


def require_number(
    value: Any,
    path: str,
    *,
    minimum: float | None = None,
    maximum: float | None = None,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise DomainError("invalid_number", f"{path} must be a finite number", path=path)
    result = float(value)
    if minimum is not None and result < minimum:
        raise DomainError("number_too_small", f"{path} must be at least {minimum}", path=path)
    if maximum is not None and result > maximum:
        raise DomainError("number_too_large", f"{path} must be at most {maximum}", path=path)
    return result


def require_choice(value: Any, path: str, choices: Sequence[str]) -> str:
    result = require_string(value, path)
    if result not in choices:
        raise DomainError(
            "invalid_choice",
            f"{path} must be one of {', '.join(choices)}",
            path=path,
            details={"allowed": list(choices), "actual": result},
        )
    return result


def require_digest(value: Any, path: str) -> str:
    return require_string(value, path, minimum=64, maximum=64, pattern=HEX_64_PATTERN)


def require_identifier(value: Any, path: str) -> str:
    return require_string(value, path, minimum=3, maximum=128, pattern=IDENTIFIER_PATTERN)


def unique_items(values: Iterable[T], key: Callable[[T], Any], path: str) -> list[T]:
    result: list[T] = []
    seen: dict[Any, int] = {}
    for index, value in enumerate(values):
        token = key(value)
        if token in seen:
            raise DomainError(
                "duplicate_item",
                f"{path} contains duplicate value {token}",
                path=f"{path}[{index}]",
                details={"first_index": seen[token], "duplicate": token},
            )
        seen[token] = index
        result.append(value)
    return result


def group_by(values: Iterable[T], key: Callable[[T], str]) -> dict[str, list[T]]:
    result: dict[str, list[T]] = {}
    for value in values:
        result.setdefault(key(value), []).append(value)
    return result


def bounded_ratio(numerator: int | float, denominator: int | float) -> float:
    if denominator <= 0:
        return 0.0
    return max(0.0, min(1.0, float(numerator) / float(denominator)))


def mean(values: Iterable[float]) -> float:
    materialized = list(values)
    return statistics.fmean(materialized) if materialized else 0.0


def percentile(values: Iterable[float], ratio: float) -> float:
    ordered = sorted(float(value) for value in values)
    if not ordered:
        return 0.0
    if len(ordered) == 1:
        return ordered[0]
    position = max(0.0, min(1.0, ratio)) * (len(ordered) - 1)
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] * (1.0 - fraction) + ordered[upper] * fraction


def chunked(values: Sequence[T], size: int) -> Iterator[list[T]]:
    if size <= 0:
        raise DomainError("invalid_chunk_size", "chunk size must be positive")
    for offset in range(0, len(values), size):
        yield list(values[offset : offset + size])


def collect_violations(callbacks: Iterable[Callable[[], Any]]) -> tuple[list[Any], list[Violation]]:
    values: list[Any] = []
    violations: list[Violation] = []
    for callback in callbacks:
        try:
            values.append(callback())
        except DomainError as exc:
            violations.append(Violation(exc.code, exc.message, exc.path, exc.details))
    return values, violations


def deep_copy(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False))


def canonical_event_hash(previous_hash: str, event: Mapping[str, Any]) -> str:
    return fingerprint({"previous_hash": previous_hash, "event": event})


def clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(maximum, value))


def round_metric(value: float, digits: int = 6) -> float:
    return round(float(value), digits)


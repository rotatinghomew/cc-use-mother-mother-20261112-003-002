from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .errors import DomainError
from .recovery import inspect_recovery
from .reporting import build_completion_report, verify_completion_report
from .service import OtaOrchestrator, load_json, save_json


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="ota-orchestrator")
    subcommands = root.add_subparsers(dest="command", required=True)
    run = subcommands.add_parser("run-fixture")
    run.add_argument("fixture")
    run.add_argument("--database", required=True)
    run.add_argument("--output")
    inspect = subcommands.add_parser("inspect")
    inspect.add_argument("--database", required=True)
    inspect.add_argument("--release", required=True)
    recover = subcommands.add_parser("recover")
    recover.add_argument("--database", required=True)
    recover.add_argument("--release", required=True)
    recover.add_argument("--now", required=True)
    report = subcommands.add_parser("report")
    report.add_argument("--database", required=True)
    report.add_argument("--release", required=True)
    report.add_argument("--generated-at", required=True)
    report.add_argument("--report-id", required=True)
    report.add_argument("--output")
    verify = subcommands.add_parser("verify-report")
    verify.add_argument("report")
    verify.add_argument("--database", required=True)
    verify.add_argument("--release", required=True)
    return root


def emit(value: Any, output: str | None = None) -> None:
    if output:
        save_json(output, value)
    else:
        json.dump(value, sys.stdout, ensure_ascii=False, sort_keys=True, indent=2)
        sys.stdout.write("\n")


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        if arguments.command == "run-fixture":
            fixture = load_json(arguments.fixture)
            database = Path(arguments.database)
            if database.exists():
                database.unlink()
            with OtaOrchestrator(database) as application:
                result = application.run_fixture(fixture)
            emit(result, arguments.output)
            return 0
        with OtaOrchestrator(arguments.database) as application:
            repository = application.repository
            if arguments.command == "inspect":
                emit(repository.export_release(arguments.release))
            elif arguments.command == "recover":
                emit(inspect_recovery(repository, arguments.release, arguments.now))
            elif arguments.command == "report":
                value = build_completion_report(
                    repository,
                    arguments.release,
                    arguments.generated_at,
                    arguments.report_id,
                )
                emit(value, arguments.output)
            elif arguments.command == "verify-report":
                value = load_json(arguments.report)
                emit(verify_completion_report(value, repository, arguments.release))
            else:
                raise AssertionError(arguments.command)
        return 0
    except DomainError as exc:
        json.dump({"error": exc.as_dict()}, sys.stderr, ensure_ascii=False, sort_keys=True)
        sys.stderr.write("\n")
        return 2
    except (ValueError, KeyError, OSError) as exc:
        json.dump(
            {"error": {"code": "execution_failed", "message": str(exc)}},
            sys.stderr,
            ensure_ascii=False,
            sort_keys=True,
        )
        sys.stderr.write("\n")
        return 3


if __name__ == "__main__":
    raise SystemExit(main())


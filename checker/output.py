import csv
import io
import json
import sys

from .dns_checker import DomainResult


def output_text(results: list[DomainResult], verbose: bool = False) -> str:
    available = [r for r in results if r.available]
    lines = [r.domain for r in available]
    return "\n".join(lines)


def output_json(results: list[DomainResult], verbose: bool = False) -> str:
    if verbose:
        data = [
            {
                "domain": r.domain,
                "available": r.available,
                "error": r.error,
                "response_time": round(r.response_time, 3),
            }
            for r in results
        ]
    else:
        data = [
            {"domain": r.domain, "available": r.available}
            for r in results
            if r.available
        ]
    return json.dumps(data, indent=2)


def output_csv(results: list[DomainResult], verbose: bool = False) -> str:
    buf = io.StringIO()
    if verbose:
        writer = csv.writer(buf)
        writer.writerow(["domain", "available", "error", "response_time"])
        for r in results:
            writer.writerow([r.domain, r.available, r.error or "", round(r.response_time, 3)])
    else:
        writer = csv.writer(buf)
        writer.writerow(["domain"])
        for r in results:
            if r.available:
                writer.writerow([r.domain])
    return buf.getvalue().rstrip("\n")


def print_summary(results: list[DomainResult], elapsed: float) -> None:
    available = sum(1 for r in results if r.available)
    errors = sum(1 for r in results if r.error)
    total = len(results)
    print(
        f"\nFound {available} available domains out of {total} checked "
        f"({errors} errors) in {elapsed:.1f}s",
        file=sys.stderr,
    )

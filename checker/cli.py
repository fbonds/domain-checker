import argparse
import asyncio
import sys
import time
from pathlib import Path

from .dns_checker import check_all
from .output import output_csv, output_json, output_text, print_summary


def load_tlds(path: Path) -> list[str]:
    with open(path) as f:
        return [line.strip().lower() for line in f if line.strip()]


def main():
    parser = argparse.ArgumentParser(
        description="Check domain availability across all gTLDs",
    )
    parser.add_argument("name", nargs="?", help="Domain name to check (e.g. 'myname')")
    parser.add_argument(
        "-f", "--tlds-file",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "gtlds.txt",
        help="Path to TLD list file (default: gtlds.txt)",
    )
    parser.add_argument(
        "-c", "--concurrency",
        type=int,
        default=100,
        help="Max concurrent DNS queries (default: 100)",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=5.0,
        help="Per-query timeout in seconds (default: 5)",
    )
    parser.add_argument(
        "-o", "--output",
        choices=["text", "json", "csv"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--dns-server",
        help="Custom DNS server (e.g. 1.1.1.1)",
    )
    parser.add_argument(
        "--long",
        action="store_true",
        help="Only check TLDs with 7+ characters (default: 6 or fewer)",
    )
    parser.add_argument(
        "--all-tlds",
        action="store_true",
        help="Check all TLDs regardless of length",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify DNS-available domains via WHOIS (slower but more accurate)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show progress and summary statistics",
    )

    args = parser.parse_args()

    if not args.name:
        parser.print_help()
        sys.exit(0)

    tlds = load_tlds(args.tlds_file)
    if not tlds:
        print("Error: no TLDs found in file", file=sys.stderr)
        sys.exit(1)

    if not args.all_tlds:
        if args.long:
            tlds = [t for t in tlds if len(t) >= 7]
        else:
            tlds = [t for t in tlds if len(t) <= 6]

    if args.verbose:
        print(f"Checking {len(tlds)} TLDs...", file=sys.stderr)

    checked = 0

    def dns_progress(result):
        nonlocal checked
        checked += 1
        if args.verbose:
            status = "AVAILABLE" if result.available else ("ERROR" if result.error else "taken")
            print(f"  [DNS {checked}/{len(tlds)}] {result.domain}: {status}", file=sys.stderr)

    start = time.monotonic()
    results = asyncio.run(
        check_all(
            name=args.name,
            tlds=tlds,
            concurrency=args.concurrency,
            timeout=args.timeout,
            dns_server=args.dns_server,
            progress_callback=dns_progress,
        )
    )
    dns_elapsed = time.monotonic() - start

    if args.verify:
        from .whois_checker import verify_available

        dns_available = sum(1 for r in results if r.available)
        print(
            f"\nDNS scan done in {dns_elapsed:.1f}s. "
            f"Verifying {dns_available} candidates via WHOIS...",
            file=sys.stderr,
        )

        whois_checked = 0

        def whois_progress(result):
            nonlocal whois_checked
            whois_checked += 1
            if args.verbose:
                status = "AVAILABLE" if result.available else ("ERROR" if result.error else "taken")
                print(
                    f"  [WHOIS {whois_checked}/{dns_available}] {result.domain}: {status}",
                    file=sys.stderr,
                )

        results = asyncio.run(
            verify_available(
                dns_results=results,
                concurrency=10,
                timeout=15.0,
                progress_callback=whois_progress,
            )
        )

    elapsed = time.monotonic() - start

    formatters = {"text": output_text, "json": output_json, "csv": output_csv}
    output = formatters[args.output](results, verbose=args.verbose)
    if output:
        print(output)

    if args.verbose:
        print_summary(results, elapsed)


if __name__ == "__main__":
    main()

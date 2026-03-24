import asyncio
import sys
import time
from dataclasses import dataclass

import asyncwhois

from .dns_checker import DomainResult


async def verify_domain(
    semaphore: asyncio.Semaphore,
    domain: str,
    timeout: float,
) -> DomainResult:
    async with semaphore:
        start = time.monotonic()
        try:
            result = await asyncio.wait_for(
                asyncwhois.aio_whois(domain),
                timeout=timeout,
            )
            elapsed = time.monotonic() - start
            parser = result.parser_output
            registered = bool(
                parser.get("domain_name")
                or parser.get("registrar")
                or parser.get("created")
            )
            return DomainResult(
                domain=domain,
                available=not registered,
                response_time=elapsed,
            )
        except asyncio.TimeoutError:
            elapsed = time.monotonic() - start
            return DomainResult(
                domain=domain,
                available=False,
                error="WhoisTimeout",
                response_time=elapsed,
            )
        except Exception as e:
            elapsed = time.monotonic() - start
            err_msg = type(e).__name__
            return DomainResult(
                domain=domain,
                available=False,
                error=err_msg,
                response_time=elapsed,
            )


async def verify_available(
    dns_results: list[DomainResult],
    concurrency: int = 10,
    timeout: float = 15.0,
    progress_callback=None,
) -> list[DomainResult]:
    candidates = [r for r in dns_results if r.available]
    semaphore = asyncio.Semaphore(concurrency)

    async def check_with_progress(domain: str) -> DomainResult:
        result = await verify_domain(semaphore, domain, timeout)
        if progress_callback:
            progress_callback(result)
        return result

    tasks = [check_with_progress(r.domain) for r in candidates]
    verified = await asyncio.gather(*tasks)

    verified_map = {r.domain: r for r in verified}
    final = []
    for r in dns_results:
        if r.domain in verified_map:
            final.append(verified_map[r.domain])
        else:
            final.append(r)

    return sorted(final, key=lambda r: r.domain)

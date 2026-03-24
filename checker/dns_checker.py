import asyncio
import time
from dataclasses import dataclass

import dns.asyncresolver
import dns.resolver


@dataclass
class DomainResult:
    domain: str
    available: bool
    error: str | None = None
    response_time: float = 0.0


async def check_domain(
    resolver: dns.asyncresolver.Resolver,
    semaphore: asyncio.Semaphore,
    domain: str,
    timeout: float,
    retries: int = 1,
) -> DomainResult:
    async with semaphore:
        start = time.monotonic()
        for attempt in range(1 + retries):
            try:
                await resolver.resolve(domain, "A", lifetime=timeout)
                elapsed = time.monotonic() - start
                return DomainResult(domain=domain, available=False, response_time=elapsed)
            except dns.resolver.NXDOMAIN:
                elapsed = time.monotonic() - start
                return DomainResult(domain=domain, available=True, response_time=elapsed)
            except dns.resolver.NoAnswer:
                elapsed = time.monotonic() - start
                return DomainResult(domain=domain, available=False, response_time=elapsed)
            except (dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout) as e:
                if attempt < retries:
                    await asyncio.sleep(1)
                    continue
                elapsed = time.monotonic() - start
                return DomainResult(
                    domain=domain,
                    available=False,
                    error=type(e).__name__,
                    response_time=elapsed,
                )
            except Exception as e:
                elapsed = time.monotonic() - start
                return DomainResult(
                    domain=domain,
                    available=False,
                    error=str(e),
                    response_time=elapsed,
                )
    # unreachable, but satisfies type checkers
    return DomainResult(domain=domain, available=False, error="unknown")


async def check_all(
    name: str,
    tlds: list[str],
    concurrency: int = 100,
    timeout: float = 5.0,
    dns_server: str | None = None,
    progress_callback=None,
) -> list[DomainResult]:
    resolver = dns.asyncresolver.Resolver()
    if dns_server:
        resolver.nameservers = [dns_server]

    semaphore = asyncio.Semaphore(concurrency)
    domains = [f"{name}.{tld}" for tld in tlds]

    async def check_with_progress(domain: str) -> DomainResult:
        result = await check_domain(resolver, semaphore, domain, timeout)
        if progress_callback:
            progress_callback(result)
        return result

    tasks = [check_with_progress(domain) for domain in domains]
    results = await asyncio.gather(*tasks)
    return sorted(results, key=lambda r: r.domain)

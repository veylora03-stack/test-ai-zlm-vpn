"""ERROR-PANEL — Network Tester Service.

TCP connect latency test for VPN profiles.
Only connects to profile.server_host:profile.server_port to measure latency.
Never port-scans, never downloads payloads, never establishes VPN tunnels.

Settings integration: reads test_attempts, test_timeout, test_concurrency
from the settings table. Falls back to defaults if not present.
"""

import asyncio
import json
import time
import socket
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Settings


# Default values (used if settings table is empty)
DEFAULT_ATTEMPTS = 4
DEFAULT_TIMEOUT = 5.0
DEFAULT_CONCURRENCY = 5


async def _get_test_settings(db: AsyncSession | None = None) -> tuple[int, float, int]:
    """Load test_attempts, test_timeout, test_concurrency from settings."""
    if db is None:
        return DEFAULT_ATTEMPTS, DEFAULT_TIMEOUT, DEFAULT_CONCURRENCY

    attempts = DEFAULT_ATTEMPTS
    timeout = DEFAULT_TIMEOUT
    concurrency = DEFAULT_CONCURRENCY

    try:
        for key, cast in [
            ("test_attempts", int),
            ("test_timeout", float),
            ("test_concurrency", int),
        ]:
            result = await db.execute(
                select(Settings).where(Settings.key == key)
            )
            row = result.scalar_one_or_none()
            if row:
                val = json.loads(row.value) if row.value else None
                if val is not None:
                    parsed = cast(val)
                    if key == "test_attempts":
                        attempts = parsed
                    elif key == "test_timeout":
                        timeout = parsed
                    else:
                        concurrency = parsed
    except Exception:
        pass

    return attempts, timeout, concurrency


async def test_profile(
    profile,
    db: AsyncSession | None = None,
    attempts: int | None = None,
    timeout: float | None = None,
    concurrency: int | None = None,
) -> dict:
    """Run TCP connect latency test on a profile.

    Args:
        profile: Profile ORM object with server_host and server_port.
        db: Optional async session to read settings from.
        attempts: Override number of connect attempts.
        timeout: Override per-attempt timeout in seconds.
        concurrency: Override max concurrent tests.

    Returns:
        Dict with keys:
            ping_ms (float or None): avg of successful attempts
            min_ms (float or None): minimum successful latency
            max_ms (float or None): maximum successful latency
            jitter_ms (float or None): mean absolute difference between successive pings
            packet_loss_pct (float): percentage of failed attempts
            reachable (bool): at least one successful attempt
            error (str or None): error message if all attempts failed
    """
    # Read settings if not overridden
    if attempts is None or timeout is None or concurrency is None:
        s_attempts, s_timeout, s_concurrency = await _get_test_settings(db)
        attempts = attempts or s_attempts
        timeout = timeout or s_timeout
        concurrency = concurrency or s_concurrency

    host = profile.server_host
    port = profile.server_port

    if not host or not port:
        return {
            "ping_ms": None,
            "min_ms": None,
            "max_ms": None,
            "jitter_ms": None,
            "packet_loss_pct": 100.0,
            "reachable": False,
            "error": "Missing host or port",
        }

    semaphore = asyncio.Semaphore(concurrency)

    async with semaphore:
        latencies: list[float] = []
        errors: list[str] = []

        for _ in range(attempts):
            start = time.monotonic()
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=timeout,
                )
                elapsed_ms = (time.monotonic() - start) * 1000.0
                latencies.append(elapsed_ms)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
            except asyncio.TimeoutError:
                errors.append("timeout")
            except OSError as exc:
                errors.append(str(exc))
            except Exception as exc:
                errors.append(str(exc))

    # Compute results
    if latencies:
        ping_ms = round(sum(latencies) / len(latencies), 2)
        min_ms = round(min(latencies), 2)
        max_ms = round(max(latencies), 2)

        # Jitter: mean absolute difference between successive latencies
        if len(latencies) >= 2:
            diffs = [abs(latencies[i] - latencies[i - 1]) for i in range(1, len(latencies))]
            jitter_ms = round(sum(diffs) / len(diffs), 2)
        else:
            jitter_ms = 0.0

        packet_loss_pct = round((len(errors) / attempts) * 100.0, 2)
        reachable = True
        error = None
    else:
        ping_ms = None
        min_ms = None
        max_ms = None
        jitter_ms = None
        packet_loss_pct = 100.0
        reachable = False
        error = "; ".join(errors[:3]) if errors else "Unknown error"

    return {
        "ping_ms": ping_ms,
        "min_ms": min_ms,
        "max_ms": max_ms,
        "jitter_ms": jitter_ms,
        "packet_loss_pct": packet_loss_pct,
        "reachable": reachable,
        "error": error,
    }

"""ERROR-PANEL — Fetcher service.

Fetches content from user-approved HTTP/HTTPS URLs using httpx.
Enforces: scheme check, timeout, max body size, redirect policy.
"""

import hashlib

import httpx
import ipaddress
import socket
import asyncio

MAX_BODY_BYTES = 1 * 1024 * 1024  # 1 MB
TIMEOUT_SECONDS = 30


class FetchError(Exception):
    """Base error for fetch operations."""
    pass


class SchemeError(FetchError):
    """URL scheme is not http or https."""
    pass


class SizeError(FetchError):
    """Response body exceeds the maximum allowed size."""
    pass



class FetchSSRFError(FetchError):
    """URL points to a forbidden internal or private IP address."""
    pass


async def _is_url_safe(url: str) -> bool:
    """
    Check if the URL points to a public IP.
    Blocks private, loopback, link-local, and reserved IPs to prevent SSRF.
    """
    from urllib.parse import urlparse
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return False

    # If it's already an IP address, check it directly
    try:
        ip = ipaddress.ip_address(hostname)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast)
    except ValueError:
        pass # It's a domain name, needs resolution

    # Resolve domain name to IP addresses
    try:
        loop = asyncio.get_event_loop()
        infos = await loop.run_in_executor(None, socket.getaddrinfo, hostname, None)
        for info in infos:
            ip_str = info[4][0]
            try:
                ip = ipaddress.ip_address(ip_str)
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                    return False # Resolved to a private IP
            except ValueError:
                continue
        return True
    except socket.gaierror:
        return False # Cannot resolve, let httpx handle the error

class NetworkError(FetchError):
    """Network-level failure (timeout, connection refused, etc.)."""
    pass


async def fetch_source(url: str) -> dict:
    """Fetch content from a user-approved URL.

    Enforces:
    - Scheme must be http or https (both initial and final redirect URL).
    - Timeout of 30 seconds.
    - Max body size of 1 MB.
    - Redirects are followed, but the final URL must also be http/https.

    Returns:
        dict with keys:
            content (str):  decoded response text
            bytes (int):    raw content length in bytes
            sha256 (str):   hex SHA-256 hash of raw content

    Raises:
        SchemeError:  if URL scheme is not http/https
        SizeError:    if body exceeds 1 MB
        NetworkError: on timeout or connection failure
    """
    # ── SSRF Protection ────────────────────────────────────────────────
    if not await _is_url_safe(url):
        raise FetchSSRFError(f"URL points to a forbidden internal or private IP: {url}")

    # ── Scheme check ───────────────────────────────────────────────────
    if not url.lower().startswith(("http://", "https://")):
        raise SchemeError(f"Scheme not allowed: {url.split('://', 1)[0] if '://' in url else url}")

    # ── Fetch with streaming to enforce size limit ─────────────────────
    try:
        async with httpx.AsyncClient(
            timeout=TIMEOUT_SECONDS,
            follow_redirects=True,
            max_redirects=5,
        ) as client:
            async with client.stream("GET", url) as resp:
                # SSRF Fix: Validate final URL after redirects
                final_url = str(resp.url)
                if not await _is_url_safe(final_url):
                    raise FetchSSRFError(f"Redirected to a forbidden internal IP: {final_url}")
                
                # Check final URL scheme after redirects
                final_scheme = str(resp.url.scheme).lower()
                if final_scheme not in ("http", "https"):
                    raise SchemeError(f"Final URL scheme not allowed after redirect: {final_scheme}")

                resp.raise_for_status()

                # Read in chunks to enforce size limit
                chunks: list[bytes] = []
                total = 0
                async for chunk in resp.aiter_bytes(chunk_size=8192):
                    total += len(chunk)
                    if total > MAX_BODY_BYTES:
                        raise SizeError(
                            f"Response body exceeds {MAX_BODY_BYTES} bytes limit ({total} bytes received)"
                        )
                    chunks.append(chunk)

                raw = b"".join(chunks)
                sha = hashlib.sha256(raw).hexdigest()
                content = raw.decode("utf-8", errors="replace")

                return {
                    "content": content,
                    "bytes": total,
                    "sha256": sha,
                }

    except (SchemeError, SizeError):
        raise  # re-raise our own errors
    except httpx.TimeoutException as exc:
        raise NetworkError(f"Request timed out after {TIMEOUT_SECONDS}s: {exc}") from exc
    except httpx.HTTPStatusError as exc:
        raise NetworkError(f"HTTP {exc.response.status_code}: {exc}") from exc
    except httpx.HTTPError as exc:
        raise NetworkError(f"Network error: {exc}") from exc

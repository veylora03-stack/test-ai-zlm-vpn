"""ERROR-PANEL — Fetcher service.

Fetches content from user-approved HTTP/HTTPS URLs using httpx.
Enforces: scheme check, timeout, max body size, redirect policy.
"""

import hashlib

import httpx

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

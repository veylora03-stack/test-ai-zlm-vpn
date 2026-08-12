import asyncio
import logging

_tester_semaphore = None
_current_concurrency = None

def get_tester_semaphore(concurrency=5):
    global _tester_semaphore, _current_concurrency

    # اگر concurrency تغییر کرده، semaphore را بازسازی کن
    if _current_concurrency is not None and _current_concurrency != concurrency:
        logging.info(f"Recreating semaphore: {_current_concurrency} -> {concurrency}")
        _tester_semaphore = None
        _current_concurrency = None

    if _tester_semaphore is None:
        _tester_semaphore = asyncio.Semaphore(concurrency)
        _current_concurrency = concurrency
        logging.info(f"Semaphore created with concurrency={concurrency}")

    return _tester_semaphore

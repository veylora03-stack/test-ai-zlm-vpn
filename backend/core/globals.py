import asyncio

_tester_semaphore = None

def get_tester_semaphore(concurrency=5):
    global _tester_semaphore
    if _tester_semaphore is None:
        _tester_semaphore = asyncio.Semaphore(concurrency)
    return _tester_semaphore

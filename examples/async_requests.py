"""AsyncSession: concurrent requests, a concurrency limit, timeouts and cancellation.

    python examples/async_requests.py
"""
import asyncio
import os
import time

from yumeclient import AsyncSession, Timeout

BASE = os.environ.get("HTTPBIN", "https://httpbin.org")


async def main() -> None:
    async with AsyncSession(timeout=20) as s:
        # Many requests at once; the session reuses its connections.
        start = time.perf_counter()
        responses = await asyncio.gather(*(s.get(f"{BASE}/get", params={"n": i}) for i in range(10)))
        print("10 requests:", [r.status_code for r in responses], f"{time.perf_counter() - start:.2f} s")

        # Limit the concurrency yourself: at most 3 requests in flight.
        limit = asyncio.Semaphore(3)

        async def fetch(i: int) -> str:
            async with limit:
                r = await s.get(f"{BASE}/get", params={"i": i})
                return r.json()["args"]["i"]

        print("with a limit:", await asyncio.gather(*(fetch(i) for i in range(6))))

        # A timeout for one request (seconds for the whole request).
        try:
            await s.get(f"{BASE}/delay/3", timeout=1)
        except Timeout as e:
            print(f"timed out: kind={e.kind} stage={e.stage} after {e.elapsed:.1f} s")

        # Cancelling the task cancels the request in the native layer too.
        task = asyncio.create_task(s.get(f"{BASE}/delay/3"))
        await asyncio.sleep(0.5)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            print("cancelled")

        # asyncio.wait_for works the same way.
        try:
            await asyncio.wait_for(s.get(f"{BASE}/delay/3"), timeout=0.5)
        except asyncio.TimeoutError:
            print("wait_for gave up")


asyncio.run(main())

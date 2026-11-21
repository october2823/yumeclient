"""Errors: the exception types, what they carry, built-in retries (retries=) and a
hand-written retry loop for rules of your own.

    python examples/errors_and_retries.py
"""
import os
import random
import time

import yumeclient
from yumeclient import ConnectError, RequestError, Retry, Session, Timeout, TimeoutConfig, TooManyRedirects

BASE = os.environ.get("HTTPBIN", "https://httpbin.org")

IDEMPOTENT = {"GET", "HEAD", "OPTIONS", "PUT", "DELETE"}


# Built-in retries: timeouts, dropped connections (EOF) and connection failures are repeated
# with exponential backoff; a POST only when it failed before being sent. statuses= repeats
# these response codes too, honouring Retry-After.
with Session(timeout=10, retries=Retry(total=2, backoff=0.2, statuses={429, 503})) as s:
    r = s.get(f"{BASE}/status/503")
    print("built-in retries:", r.status_code, "after", r.attempts, "attempts")
    try:
        s.get("http://127.0.0.1:9/")
    except ConnectError as e:
        print(f"built-in retries: {type(e).__name__} after {e.attempts} attempts")


def request_with_retries(session: Session, method: str, url: str, attempts: int = 3, **kwargs):
    """The same by hand, for rules retries= does not cover (here: printing every attempt).
    Retry network errors marked retryable, only for idempotent methods, with exponential
    backoff and jitter; also retry 429/503 responses, honouring a numeric Retry-After."""
    for attempt in range(1, attempts + 1):
        try:
            r = session.request(method, url, **kwargs)
        except RequestError as e:
            if attempt == attempts or not e.retryable or method.upper() not in IDEMPOTENT:
                raise
            print(f"  attempt {attempt}: {type(e).__name__} ({e.kind}), retrying")
        else:
            if r.status_code not in (429, 503) or attempt == attempts:
                return r
            print(f"  attempt {attempt}: HTTP {r.status_code}, retrying")
            retry_after = r.headers.get("Retry-After", [""])[0]
            if retry_after.isdigit():
                time.sleep(min(int(retry_after), 30))
                continue
        time.sleep(min(0.2 * 2 ** (attempt - 1), 5) * (0.5 + random.random()))


# Split timeouts: 5 s to connect, 10 s between bytes, 30 s for the whole request.
with Session(timeout=TimeoutConfig(total=30, connect=5, read=10)) as s:
    # A refused connection: ConnectError, retryable.
    try:
        request_with_retries(s, "GET", "http://127.0.0.1:9/", attempts=2)
    except ConnectError as e:
        print(f"ConnectError: kind={e.kind} stage={e.stage} retryable={e.retryable}")
        print("  url:", e.url, "| native cause:", e.__cause__)

    # A slow response: ReadTimeout (a subclass of Timeout and of the built-in TimeoutError).
    try:
        s.get(f"{BASE}/delay/3", timeout=(5, 1))  # (connect, read)
    except Timeout as e:
        print(f"{type(e).__name__}: stage={e.stage} after {e.elapsed:.1f} s, TimeoutError: {isinstance(e, TimeoutError)}")

    # Too many redirects (more than 20, the browsers' limit).
    try:
        s.get(f"{BASE}/redirect/25")
    except TooManyRedirects as e:
        print("TooManyRedirects:", e.kind)

    # A configuration mistake is raised before anything is sent.
    try:
        Session(client_identifier="chrome_999")
    except yumeclient.SessionConfigurationError as e:
        print("SessionConfigurationError:", e)

    # Statuses are not exceptions; raise_for_status() for 4xx/5xx.
    r = request_with_retries(s, "GET", f"{BASE}/status/503", attempts=2)
    print("final status:", r.status_code)

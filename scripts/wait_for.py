"""Wait until every URL given on the command line answers with HTTP < 500 (demo helper)."""

from __future__ import annotations

import sys
import time

import httpx


def main(urls: list[str], timeout: float = 60.0) -> int:
    """Poll ``urls`` until they respond or ``timeout`` seconds pass."""
    deadline = time.monotonic() + timeout
    pending = set(urls)
    while pending and time.monotonic() < deadline:
        for url in sorted(pending):
            try:
                if httpx.get(url, timeout=2.0).status_code < 500:
                    pending.discard(url)
            except httpx.HTTPError:
                pass
        if pending:
            time.sleep(1)
    if pending:
        print(f"Timed out waiting for: {', '.join(sorted(pending))}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

"""Load generator: many clients at once, latency percentiles, CSV, breaking point.

Usage:
    python tools/load_test.py --proxy 127.0.0.1:8080 --url http://127.0.0.1:9000/
        --clients 10 50 100 200 --requests 20 --out docs/results/load.csv
    add  --mode connect  to tunnel through CONNECT to the TLS echo server instead.

Every client is a thread; all threads of one round start together (Barrier).
Each request uses a fresh connection. Only standard library modules are used.
"""
from __future__ import annotations

import argparse
import csv
import http.client
import math
import socket
import ssl
import sys
import threading
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import partial
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

# Seconds we wait for one network step before that request counts as failed.
TIMEOUT = 10.0

# Breaking point rule from the brief: success rate below 99 percent ...
BREAK_SUCCESS_PCT = 99.0
# ... or the slowest 1 percent of requests taking longer than 5 seconds.
BREAK_P99_MS = 5000.0

# Longest CONNECT reply head we accept.
MAX_HEAD = 16384

# Bytes sent through a tunnel in --mode connect; the echo server returns them.
PAYLOAD = b"load-test-echo"

# CSV columns, in the exact order and spelling required by the brief.
CSV_COLUMNS = ["timestamp", "clients", "requests_total", "success", "fail",
               "success_rate", "p50_ms", "p95_ms", "p99_ms", "max_ms", "rps"]


class BadReply(Exception):
    """The proxy answered, but not the way a healthy request should be answered."""


@dataclass
class Sample:
    """One request: how long it took and, if it failed, the exception type name."""

    latency_ms: float
    error: Optional[str] = None


def parse_hostport(text: str) -> Tuple[str, int]:
    """Split 'host:port' into (host, port); raise ValueError if malformed."""
    host, sep, port = text.rpartition(":")  # split on the LAST colon
    if not sep or not host or not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError(f"expected host:port, got {text!r}")
    return host, int(port)


def percentile(values: Sequence[float], pct: float) -> float:
    """Nearest-rank percentile: the smallest value that covers pct% of the data."""
    if not values:
        return 0.0
    ordered = sorted(values)
    # Example: 100 values, pct=95 -> rank 95 -> the 95th smallest value.
    rank = math.ceil(pct * len(ordered) / 100)
    # Clamp so pct=0 or rounding never points outside the list.
    return ordered[min(max(rank, 1), len(ordered)) - 1]


def read_head(sock: socket.socket) -> bytes:
    """Read one byte at a time up to the blank line that ends an HTTP head."""
    # One byte at a time so we never swallow the start of the TLS handshake.
    data = b""
    while not data.endswith(b"\r\n\r\n"):
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("proxy closed the connection before replying")
        data += chunk
        if len(data) > MAX_HEAD:
            raise BadReply("reply head too large")
    return data


def recv_exact(sock: socket.socket, count: int) -> bytes:
    """Receive up to `count` bytes, stopping early only if the peer closes."""
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            break
        data += chunk
    return data


def http_request(proxy: Tuple[str, int], url: str) -> None:
    """One plain HTTP GET through the proxy on a fresh connection; must return 200."""
    conn = http.client.HTTPConnection(proxy[0], proxy[1], timeout=TIMEOUT)
    try:
        conn.request("GET", url)  # full URL: how a browser talks to a proxy
        resp = conn.getresponse()
        resp.read()  # read the whole body so the timing includes the download
        if resp.status != 200:
            raise BadReply(f"HTTP {resp.status}")
    finally:
        conn.close()


def connect_request(proxy: Tuple[str, int], target: Tuple[str, int]) -> None:
    """One CONNECT tunnel to the TLS echo server, with handshake and echo check."""
    where = f"{target[0]}:{target[1]}"
    request = f"CONNECT {where} HTTP/1.1\r\nHost: {where}\r\n\r\n".encode("ascii")
    with socket.create_connection(proxy, timeout=TIMEOUT) as raw:
        raw.sendall(request)
        status_line = read_head(raw).split(b"\r\n", 1)[0].decode("latin-1")
        if " 200" not in status_line:
            raise BadReply(status_line)
        # The test certificate is self-signed, so verification is switched off.
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with context.wrap_socket(raw, server_hostname="localhost") as tls:
            tls.sendall(PAYLOAD)
            if recv_exact(tls, len(PAYLOAD)) != PAYLOAD:
                raise BadReply("echo mismatch")


def worker(action: Callable[[], None], requests: int, barrier: threading.Barrier,
           out: List[Sample]) -> None:
    """One client thread: wait for the start signal, then make its requests."""
    barrier.wait()  # every client leaves the starting line at the same moment
    for _ in range(requests):
        start = time.perf_counter()  # perf_counter is the most precise stopwatch
        error: Optional[str] = None
        try:
            action()
        except Exception as exc:  # noqa: BLE001 - every failure kind is recorded
            error = type(exc).__name__  # e.g. "TimeoutError", "ConnectionResetError"
        out.append(Sample((time.perf_counter() - start) * 1000, error))  # seconds -> ms


def run_level(action: Callable[[], None], clients: int,
              requests: int) -> Tuple[List[Sample], float]:
    """Run `clients` threads together; return all samples and the elapsed seconds."""
    # clients + 1 parties: the main thread joins the barrier too, so the stopwatch
    # starts exactly when the clients are released.
    barrier = threading.Barrier(clients + 1)
    buckets: List[List[Sample]] = [[] for _ in range(clients)]  # one list per thread
    threads = [threading.Thread(target=worker, args=(action, requests, barrier, bucket),
                                daemon=True) for bucket in buckets]
    for thread in threads:
        thread.start()
    barrier.wait()
    began = time.perf_counter()
    for thread in threads:
        thread.join()
    elapsed = max(time.perf_counter() - began, 1e-9)  # never zero: we divide by it
    return [sample for bucket in buckets for sample in bucket], elapsed


def summarize(clients: int, samples: List[Sample],
              elapsed: float) -> Tuple[Dict[str, object], Counter]:
    """Turn raw samples into one CSV row plus a count of failures by exception type."""
    # Latency statistics use successful requests only: a request that failed in
    # 1 ms (connection refused) must not make the proxy look fast.
    good = [s.latency_ms for s in samples if s.error is None]
    failures = Counter(s.error for s in samples if s.error is not None)
    total = len(samples)
    row: Dict[str, object] = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "clients": clients,
        "requests_total": total,
        "success": len(good),
        "fail": total - len(good),
        "success_rate": round(100 * len(good) / total, 2) if total else 0.0,  # percent
        "p50_ms": round(percentile(good, 50), 2),
        "p95_ms": round(percentile(good, 95), 2),
        "p99_ms": round(percentile(good, 99), 2),
        "max_ms": round(max(good, default=0.0), 2),
        "rps": round(len(good) / elapsed, 2),  # successful requests per second
    }
    return row, failures


def find_breaking_point(rows: List[Dict[str, object]]) -> Optional[Tuple[int, str]]:
    """First client count that fails the brief's rule, with the reason; else None."""
    for row in rows:  # rows are in the order the client counts were run
        if float(row["success_rate"]) < BREAK_SUCCESS_PCT:  # type: ignore[arg-type]
            return int(row["clients"]), f"success rate {row['success_rate']}%"  # type: ignore
        if float(row["p99_ms"]) > BREAK_P99_MS:  # type: ignore[arg-type]
            return int(row["clients"]), f"p99 latency {row['p99_ms']} ms"  # type: ignore
    return None


def write_csv(path: Path, rows: List[Dict[str, object]]) -> None:
    """Write the header and one line per client count (creates the folder)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    # newline="" and lineterminator="\n" give the same file on Windows and Linux.
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def build_parser() -> argparse.ArgumentParser:
    """Command-line options."""
    parser = argparse.ArgumentParser(description="Load test a running proxy")
    parser.add_argument("--proxy", default="127.0.0.1:8080", help="proxy host:port")
    parser.add_argument("--url", default="http://127.0.0.1:9000/", help="URL to fetch")
    parser.add_argument("--clients", type=int, nargs="+", default=[10, 50, 100, 200],
                        help="client counts to test, one round each")
    parser.add_argument("--requests", type=int, default=20, help="requests per client")
    parser.add_argument("--out", default="docs/results/load.csv", help="CSV output file")
    parser.add_argument("--mode", choices=["http", "connect"], default="http")
    parser.add_argument("--tls-target", default="127.0.0.1:9443",
                        help="TLS echo server used by --mode connect")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Command-line entry point; returns the process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        proxy = parse_hostport(args.proxy)
        target = parse_hostport(args.tls_target)
    except ValueError as exc:
        parser.error(str(exc))  # prints usage and exits with code 2
    parts = urlsplit(args.url)
    if parts.scheme != "http" or not parts.hostname:
        parser.error("--url must look like http://host:port/path")
    if args.requests < 1 or any(c < 1 for c in args.clients):
        parser.error("--clients and --requests must be at least 1")

    action = (partial(http_request, proxy, args.url) if args.mode == "http"
              else partial(connect_request, proxy, target))
    rows: List[Dict[str, object]] = []
    all_failures: Counter = Counter()
    for clients in args.clients:
        samples, elapsed = run_level(action, clients, args.requests)
        row, failures = summarize(clients, samples, elapsed)
        rows.append(row)
        all_failures.update(failures)
        print(f"clients={clients:<5} ok={row['success']}/{row['requests_total']}  "
              f"p50={row['p50_ms']}ms  p95={row['p95_ms']}ms  p99={row['p99_ms']}ms  "
              f"rps={row['rps']}")
    write_csv(Path(args.out), rows)
    print(f"Wrote {args.out}")
    if all_failures:
        print("Failures by type: " + ", ".join(f"{name} x{n}" for name, n
                                                in all_failures.most_common()))
    point = find_breaking_point(rows)
    if point:
        print(f"Breaking point: {point[0]} clients ({point[1]})")
    else:
        print(f"No breaking point up to {max(args.clients)} clients")
    return 0


if __name__ == "__main__":
    sys.exit(main())
"""Run every proxy test start to finish and print what each one shows.

Usage:  python tools/run_all_tests.py
For Me(talha)= py -3.13 tools/run_all_tests.py

Self-contained: starts its own origin (ports 19000/19443) and two proxies
(18080 = no login, 18090 = login on) from a temp config. Your configs/ files
are never read or changed. Exit code 0 only if nothing failed.
"""
from __future__ import annotations

import base64
import json
import socket
import ssl
import statistics
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from proxy.control.mkuser import generate_credentials  # noqa: E402

HOST = "127.0.0.1"
ORIGIN, TLS, DEAD = 19000, 19443, 19999
OPEN_PORT, AUTH_PORT = 18080, 18090          # proxy without / with login
USER, PASSWORD = "tester", "Test-Pass-123"   # throwaway, exists only for this run
TMP = Path(tempfile.mkdtemp(prefix="proxytest_"))
procs: list = []
results: list = []


# ---------------------------------------------------------------- helpers
def config(port: int, auth: bool) -> dict:
    return {
        "proxy": {"host": HOST, "port": port, "max_threads": 200, "backlog": 1024,
                  "connect_timeout": 3, "read_timeout": 2, "idle_timeout": 3,
                  "max_header_bytes": 16384},
        "admin": {"host": HOST, "port": port + 1},
        "filter": {"mode": "denylist", "deny_domains": ["blocked.example.com"],
                   "allow_domains": [], "blocked_ports": [25], "allowed_ports": [],
                   "deny_url_regex": [], "block_private_ips": True,
                   "private_allow": [f"{HOST}:{ORIGIN}", f"{HOST}:{TLS}", f"{HOST}:{DEAD}"]},
        "auth": {"enabled": auth, "realm": "proxy",
                 "users": {USER: generate_credentials(PASSWORD)} if auth else {},
                 "max_failures": 5, "lockout_seconds": 60, "failure_window_seconds": 300},
        "logging": {"file": str(TMP / f"{port}.jsonl"), "max_bytes": 5000000, "backups": 1,
                    "console": False, "level": "INFO", "ring_size": 2000, "log_query": False},
    }


def spawn(args: list, name: str):
    p = subprocess.Popen([sys.executable, *args], cwd=ROOT, stdout=subprocess.DEVNULL,
                         stderr=open(TMP / f"{name}.err", "w"))
    procs.append(p)
    return p


def wait_port(port: int) -> None:
    for _ in range(100):
        try:
            socket.create_connection((HOST, port), 0.2).close()
            return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"nothing listening on port {port}")


def start_proxy(port: int, auth: bool) -> None:
    cfg = TMP / f"{port}.json"
    cfg.write_text(json.dumps(config(port, auth)))
    spawn(["-m", "proxy", "--config", str(cfg)], f"proxy{port}")
    wait_port(port)


def talk(port: int, data: bytes, timeout: float = 10, stop_after: int = 0) -> bytes:
    """Send raw bytes to the proxy, read the reply (to EOF, or until stop_after bytes)."""
    out = b""
    with socket.create_connection((HOST, port), timeout) as s:
        s.settimeout(timeout)
        s.sendall(data)
        try:
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                out += chunk
                if stop_after and len(out) >= stop_after:
                    break
        except socket.timeout:
            pass
    return out


def status(reply: bytes) -> int:
    parts = reply.split(b" ", 2)
    return int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0


def get(port: int, target: str, auth: str = "", timeout: float = 10) -> int:
    """GET through the proxy, return the status code (0 = no valid answer)."""
    hdr = f"Proxy-Authorization: Basic {base64.b64encode(auth.encode()).decode()}\r\n" if auth else ""
    host = target.split("/")[0]
    req = f"GET http://{target} HTTP/1.1\r\nHost: {host}\r\n{hdr}Connection: close\r\n\r\n"
    return status(talk(port, req.encode(), timeout))


def connect(port: int, target: str) -> int:
    return status(talk(port, f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode(),
                       stop_after=12))


def log_events(port: int) -> list:
    time.sleep(1.5)  # the logger writes in the background
    path = TMP / f"{port}.jsonl"
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()] if path.exists() else []


def alive(port: int) -> bool:
    return get(port, f"{HOST}:{ORIGIN}/") == 200


# ---------------------------------------------------------------- runner
def check(group: str, name: str, shows: str):
    """Decorator: run the function, print PASS/FAIL, the proof, and what it shows."""
    def wrap(fn):
        try:
            detail, ok = fn(), True
        except AssertionError as e:
            detail, ok = str(e), False
        except Exception as e:  # noqa: BLE001
            detail, ok = f"{type(e).__name__}: {e}", False
        results.append(ok)
        print(f"[{'PASS' if ok else 'FAIL'}] {group}: {name}")
        print(f"       got  : {detail}")
        print(f"       shows: {shows}\n")
        return fn
    return wrap


def expect(cond: bool, msg: str) -> str:
    assert cond, msg
    return msg


# ---------------------------------------------------------------- tests
def run_unit_tests():
    try:
        import pytest  # noqa: F401
    except ImportError:
        results.append(True)
        print("[SKIP] Unit tests: pytest not installed (pip install -r requirements-dev.txt)\n")
        return
    print("Running pytest (live output)...\n", flush=True)
    try:
        code = subprocess.run([sys.executable, "-m", "pytest"], cwd=ROOT,
                              timeout=300).returncode
    except subprocess.TimeoutExpired:
        code = -1
    results.append(code == 0)
    print(f"\n[{'PASS' if code == 0 else 'FAIL'}] Unit + integration tests (pytest)")
    print(f"       got  : exit code {code}" + (" (timed out after 300 s)" if code == -1 else ""))
    print("       shows: each module (core, filter, auth, logging) works alone and together.\n")


def run_filtering(p: int):
    @check("Filtering", "allowed site is forwarded", "a normal request passes the filter and reaches the website.")
    def _():
        c = get(p, f"{HOST}:{ORIGIN}/")
        return expect(c == 200, f"status {c}, expected 200")

    @check("Filtering", "denied domain over HTTP", "the deny rule blocks the request before any connection to the website.")
    def _():
        c = get(p, "blocked.example.com/")
        return expect(c == 403, f"status {c}, expected 403")

    @check("Filtering", "denied domain over CONNECT (HTTPS)", "HTTPS is filtered by hostname too, without decrypting anything.")
    def _():
        c = connect(p, "blocked.example.com:443")
        return expect(c == 403, f"status {c}, expected 403")

    @check("Filtering", "blocked port 25", "port rules work: mail port refused with 403.")
    def _():
        c = get(p, f"{HOST}:25/")
        return expect(c == 403, f"status {c}, expected 403")

    @check("Filtering", "proxy's own admin port (SSRF guard)", "clients cannot use the proxy to reach private/internal addresses.")
    def _():
        c = get(p, f"{HOST}:{p + 1}/")
        return expect(c == 403, f"status {c}, expected 403")


def run_tunnel(p: int):
    @check("HTTPS tunnel", "CONNECT then TLS echo", "after '200 Connection established' the proxy just relays encrypted bytes.")
    def _():
        with socket.create_connection((HOST, p), 10) as s:
            s.sendall(f"CONNECT {HOST}:{TLS} HTTP/1.1\r\nHost: {HOST}:{TLS}\r\n\r\n".encode())
            head = s.recv(4096)
            assert status(head) == 200, f"CONNECT status {status(head)}"
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            with ctx.wrap_socket(s, server_hostname="localhost") as tls:
                tls.sendall(b"hello-tunnel")
                echo = tls.recv(64)
        return expect(echo == b"hello-tunnel", f"echo {echo!r}")


def run_auth(p: int):
    good = f"{USER}:{PASSWORD}"

    @check("Auth", "no credentials", "login is enforced: the proxy asks for credentials (407) and connects nowhere.")
    def _():
        c = get(p, f"{HOST}:{ORIGIN}/")
        return expect(c == 407, f"status {c}, expected 407")

    @check("Auth", "wrong password", "a bad password is rejected, same 407 as no credentials.")
    def _():
        c = get(p, f"{HOST}:{ORIGIN}/", f"{USER}:wrong")
        return expect(c == 407, f"status {c}, expected 407")

    @check("Auth", "correct password", "valid credentials get through and the request is forwarded.")
    def _():
        c = get(p, f"{HOST}:{ORIGIN}/", good)
        return expect(c == 200, f"status {c}, expected 200")

    @check("Auth", "lockout after 5 failures", "brute-force guard: after max_failures even the right password is refused (429).")
    def _():
        codes = [get(p, f"{HOST}:{ORIGIN}/", f"{USER}:bad{i}") for i in range(5)]
        c = get(p, f"{HOST}:{ORIGIN}/", good)
        return expect(c == 429, f"5 bad tries {codes}, then correct password -> {c}, expected 429")

    @check("Auth", "password not written to the log", "logs record who failed and why, never the secret itself.")
    def _():
        text = (TMP / f"{p}.jsonl").read_text() if log_events(p) else ""
        token = base64.b64encode(good.encode()).decode()
        bad = [s for s in (PASSWORD, token, "bad0") if s in text]
        return expect(not bad and "auth_fail" in text, f"auth_fail logged, leaked strings: {bad or 'none'}")


def run_load(p: int):
    def one(port: int) -> float:
        t = time.perf_counter()
        if port == p:
            ok = get(port, f"{HOST}:{ORIGIN}/") == 200
        else:
            ok = status(talk(port, b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")) == 200
        return (time.perf_counter() - t) * 1000 if ok else -1

    def run(port: int) -> tuple:
        with ThreadPoolExecutor(50) as ex:
            lat = list(ex.map(lambda _: one(port), range(500)))
        ok = [x for x in lat if x >= 0]
        ok.sort()
        return len(ok) / len(lat) * 100, statistics.median(ok), ok[int(len(ok) * 0.95) - 1]

    @check("Load", "50 parallel clients, 500 requests, direct vs proxy",
           "the proxy handles concurrency; the latency gap is its added cost per request.")
    def _():
        d, v = run(ORIGIN), run(p)
        msg = (f"direct: {d[0]:.0f}% ok, p50 {d[1]:.0f} ms, p95 {d[2]:.0f} ms | "
               f"proxy: {v[0]:.0f}% ok, p50 {v[1]:.0f} ms, p95 {v[2]:.0f} ms")
        return expect(v[0] >= 99, msg)


def run_failures(p: int):
    @check("Failure", "malformed request", "garbage input gets a clean 400, not a crash.")
    def _():
        c = status(talk(p, b"THIS IS NOT HTTP\r\n\r\n"))
        return expect(c == 400 and alive(p), f"status {c}, proxy still answers: {alive(p)}")

    @check("Failure", "dead website (connection refused)", "an unreachable upstream becomes 502 to the client.")
    def _():
        c = get(p, f"{HOST}:{DEAD}/")
        return expect(c == 502, f"status {c}, expected 502")

    @check("Failure", "DNS failure", "a name that does not resolve becomes 502, not a hang.")
    def _():
        c = get(p, "no-such-host.invalid/")
        return expect(c in (502, 504), f"status {c}, expected 502")

    @check("Failure", "website too slow (timeout)", "a stalled upstream is cut off with 504 after read_timeout (2 s here).")
    def _():
        c = get(p, f"{HOST}:{ORIGIN}/slow?ms=6000")
        return expect(c == 504, f"status {c}, expected 504")

    @check("Failure", "client drops mid-download", "a client vanishing mid-transfer frees the sockets and the proxy keeps serving.")
    def _():
        talk(p, f"GET http://{HOST}:{ORIGIN}/big?mb=50 HTTP/1.1\r\nHost: x\r\n\r\n".encode(),
             stop_after=65536)
        time.sleep(1)
        return expect(alive(p), "proxy still answers after the drop")


def run_logs(p: int):
    ev = log_events(p)
    kinds = {e.get("kind") for e in ev}

    @check("Logs", "every key event is recorded", "each lifecycle step (open, forward, block, tunnel, close) leaves a JSON line.")
    def _():
        need = {"conn_open", "req_forward", "req_blocked", "tunnel_open", "tunnel_close", "conn_close"}
        return expect(need <= kinds, f"{len(ev)} events, missing: {sorted(need - kinds) or 'none'}")

    @check("Logs", "no leaked connections", "every conn_open has a conn_close: no session left a socket behind.")
    def _():
        time.sleep(3)  # let the last timeouts finish
        ev2 = log_events(p)
        o = sum(e.get("kind") == "conn_open" for e in ev2)
        c = sum(e.get("kind") == "conn_close" for e in ev2)
        return expect(o == c, f"conn_open {o}, conn_close {c}")

    @check("Logs", "no credentials or payloads in the log", "logs carry metadata only: no auth headers, no body data.")
    def _():
        text = (TMP / f"{p}.jsonl").read_text().lower()
        bad = [s for s in ("proxy-authorization", "basic ", "hello-tunnel") if s in text]
        return expect(not bad, f"leaked: {bad or 'nothing'}")

    @check("Proxy health", "proxy process never crashed", "after all abuse above, the proxy processes are still running.")
    def _():
        dead = [pr.args for pr in procs if pr.poll() is not None]
        return expect(not dead, "all processes still running" if not dead else f"exited: {dead}")


# ---------------------------------------------------------------- main
def main() -> int:
    print(f"Temp files: {TMP}\n")
    try:
        run_unit_tests()
        spawn(["tools/origin.py", "--http-port", str(ORIGIN), "--tls-port", str(TLS)], "origin")
        wait_port(ORIGIN)
        start_proxy(OPEN_PORT, auth=False)
        start_proxy(AUTH_PORT, auth=True)
        run_filtering(OPEN_PORT)
        run_tunnel(OPEN_PORT)
        run_auth(AUTH_PORT)
        run_load(OPEN_PORT)
        run_failures(OPEN_PORT)
        run_logs(OPEN_PORT)
    finally:
        for pr in procs:
            pr.terminate()
    print(f"{sum(results)} passed, {len(results) - sum(results)} failed.")
    print("Not automated: Wireshark capture (handshake + encrypted tunnel) - do it by hand on loopback.")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())

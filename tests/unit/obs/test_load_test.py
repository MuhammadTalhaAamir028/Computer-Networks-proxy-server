"""Unit tests for tools/load_test.py (maths, CSV, breaking point, end-to-end runs)."""
from __future__ import annotations

import socket
import threading

import pytest

from tools import load_test
from tools.load_test import Sample
from tools.origin import OriginServers

HEADER = ("timestamp,clients,requests_total,success,fail,success_rate,"
          "p50_ms,p95_ms,p99_ms,max_ms,rps")


def make_row(clients, success_rate=100.0, p99_ms=10.0):
    """A synthetic result row; only the fields the breaking-point rule reads matter."""
    return {"clients": clients, "success_rate": success_rate, "p99_ms": p99_ms}


def test_percentile_maths_on_a_known_list():
    values = list(range(1, 101))  # 1..100, so the p-th percentile is exactly p
    assert load_test.percentile(values, 50) == 50
    assert load_test.percentile(values, 95) == 95
    assert load_test.percentile(values, 99) == 99
    assert load_test.percentile(values, 100) == 100
    assert load_test.percentile(list(reversed(values)), 50) == 50  # order does not matter
    assert load_test.percentile([], 50) == 0.0  # empty list must not crash
    assert load_test.percentile([7.5], 99) == 7.5  # single value


def test_summarize_counts_rates_and_failure_types():
    samples = [Sample(float(ms)) for ms in range(10, 90, 10)]  # 8 ok: 10..80 ms
    samples += [Sample(5000.0, "TimeoutError"), Sample(1.0, "ConnectionResetError")]
    row, failures = load_test.summarize(4, samples, elapsed=2.0)
    assert (row["requests_total"], row["success"], row["fail"]) == (10, 8, 2)
    assert row["success_rate"] == 80.0
    assert row["p50_ms"] == 40.0 and row["max_ms"] == 80.0  # failures do not count
    assert row["rps"] == 4.0  # 8 successes in 2 seconds
    assert dict(failures) == {"TimeoutError": 1, "ConnectionResetError": 1}


def test_csv_header_and_rows(tmp_path):
    row, _ = load_test.summarize(2, [Sample(12.0), Sample(20.0)], elapsed=1.0)
    out = tmp_path / "nested" / "load.csv"  # parent folder does not exist yet
    load_test.write_csv(out, [row])
    lines = out.read_text(encoding="utf-8").splitlines()
    assert lines[0] == HEADER
    assert len(lines) == 2 and lines[1].split(",")[1] == "2"  # clients column


def test_breaking_point_detection_on_synthetic_data():
    healthy = [make_row(10), make_row(50), make_row(100)]
    assert load_test.find_breaking_point(healthy) is None
    slow = healthy + [make_row(200, p99_ms=5001.0)]  # p99 over 5 seconds
    assert load_test.find_breaking_point(slow)[0] == 200
    lossy = [make_row(10), make_row(50, success_rate=98.9), make_row(100, p99_ms=9999.0)]
    assert load_test.find_breaking_point(lossy)[0] == 50  # the FIRST failing count
    edge = [make_row(10, success_rate=99.0, p99_ms=5000.0)]  # exactly at the limits
    assert load_test.find_breaking_point(edge) is None  # limits are not "below/over"


@pytest.fixture(scope="module")
def origin():
    """Real test origin servers on free ports."""
    servers = OriginServers(http_port=0, tls_port=0)
    servers.start()
    yield servers
    servers.stop()


def read_csv_rows(path):
    """Return the CSV as a list of dicts."""
    lines = path.read_text(encoding="utf-8").splitlines()
    names = lines[0].split(",")
    return [dict(zip(names, line.split(","))) for line in lines[1:]]


def test_http_mode_end_to_end(origin, tmp_path, capsys):
    # The origin also understands "GET http://host/path", so it can play the proxy here.
    out = tmp_path / "http.csv"
    code = load_test.main(["--proxy", f"127.0.0.1:{origin.http_port}",
                           "--url", f"http://127.0.0.1:{origin.http_port}/",
                           "--clients", "2", "5", "--requests", "3", "--out", str(out)])
    assert code == 0
    rows = read_csv_rows(out)
    assert [r["requests_total"] for r in rows] == ["6", "15"]
    assert all(r["success_rate"] == "100.0" for r in rows)
    assert "No breaking point up to 5 clients" in capsys.readouterr().out


class TunnelProxy:
    """Minimal CONNECT tunnel so --mode connect can be tested. TEST ONLY."""

    def __init__(self):
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self.port = self._sock.getsockname()[1]
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def stop(self):
        self._sock.close()

    def _accept_loop(self):
        while True:
            try:
                client, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(client,), daemon=True).start()

    def _serve(self, client):
        try:
            client.settimeout(10)
            head = b""
            while not head.endswith(b"\r\n\r\n"):
                head += client.recv(1)
            host, port = head.split(b" ")[1].decode().rsplit(":", 1)
            with socket.create_connection((host, int(port))) as upstream:
                client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                back = threading.Thread(target=self._pipe, args=(upstream, client),
                                        daemon=True)
                back.start()
                self._pipe(client, upstream)
                back.join(timeout=5)
        except (OSError, ValueError, IndexError):
            pass
        finally:
            client.close()

    @staticmethod
    def _pipe(src, dst):
        try:
            while True:
                data = src.recv(4096)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def test_connect_mode_end_to_end(origin, tmp_path):
    tunnel = TunnelProxy()
    try:
        out = tmp_path / "connect.csv"
        code = load_test.main(["--proxy", f"127.0.0.1:{tunnel.port}", "--mode", "connect",
                               "--tls-target", f"127.0.0.1:{origin.tls_port}",
                               "--clients", "3", "--requests", "2", "--out", str(out)])
    finally:
        tunnel.stop()
    assert code == 0
    row = read_csv_rows(out)[0]
    assert (row["requests_total"], row["success"]) == ("6", "6")


def test_dead_proxy_groups_failures_and_reports_breaking_point(tmp_path, capsys):
    with socket.socket() as sock:  # a free port that nothing listens on
        sock.bind(("127.0.0.1", 0))
        dead = sock.getsockname()[1]
    out = tmp_path / "dead.csv"
    code = load_test.main(["--proxy", f"127.0.0.1:{dead}", "--clients", "2",
                           "--requests", "1", "--out", str(out)])
    text = capsys.readouterr().out
    assert code == 0  # the tool itself worked; it just reports the failures
    assert "ConnectionRefusedError x2" in text
    assert "Breaking point: 2 clients" in text
    assert read_csv_rows(out)[0]["success_rate"] == "0.0"


@pytest.mark.parametrize("args", [
    ["--clients", "0"], ["--requests", "0"], ["--proxy", "nohost"],
    ["--url", "https://example.com/"], ["--tls-target", "x:99999"],
])
def test_bad_arguments_exit_with_code_2(args):
    with pytest.raises(SystemExit) as info:
        load_test.main(args)
    assert info.value.code == 2
"""Unit tests for proxy/obs/logger.py."""
from __future__ import annotations

import json
import re
import threading
import time

import pytest

from proxy.obs.logger import JsonLogger, build_logger
from proxy.obs.stats import build_stats
from proxy.stubs import DictConfig


@pytest.fixture
def make_logger(tmp_path):
    """Build loggers that write into a temp folder and are always closed at the end."""
    created = []

    def factory(**kwargs):
        path = tmp_path / "logs" / "proxy.jsonl"  # parent folder does not exist yet
        options = {"console": False, **kwargs}  # keep test output quiet
        logger = JsonLogger(path, **options)
        created.append(logger)
        return logger, path

    yield factory
    for logger in created:
        logger.close()  # closing releases the file (important on Windows)


def read_lines(logger, path):
    """Wait for the writer, then return the raw text lines of the log file."""
    assert logger.flush()
    return path.read_text(encoding="utf-8").splitlines()


def read_events(logger, path):
    """Return every log line parsed as JSON (fails if any line is not valid JSON)."""
    return [json.loads(line) for line in read_lines(logger, path)]


def test_ten_threads_thousand_events_exact_lines(make_logger):
    logger, path = make_logger()
    threads_count, per_thread = 10, 1000
    barrier = threading.Barrier(threads_count)  # releases all threads at once

    def worker(thread_id: int) -> None:
        barrier.wait()  # every thread starts at the same instant
        for i in range(per_thread):
            logger.event("req_forward", t=thread_id, i=i)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(threads_count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    events = read_events(logger, path)  # json.loads fails on any corrupt line
    assert len(events) == threads_count * per_thread  # exactly 10,000 lines
    # Every (thread, counter) pair appears exactly once: nothing lost, nothing doubled.
    assert {(e["t"], e["i"]) for e in events} == {
        (t, i) for t in range(threads_count) for i in range(per_thread)}
    assert logger.dropped == 0


def test_timestamp_format_key_order_and_compact_json(make_logger):
    logger, path = make_logger()
    logger.event("conn_open", conn_id=1, client_ip="1.2.3.4", client_port=5000)
    raw = read_lines(logger, path)[0]
    record = json.loads(raw)
    # Example: 2026-09-29T14:05:09.042Z (UTC, milliseconds, ends with Z)
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", record["ts"])
    # ts first, kind second, then the caller's fields in the order they were given.
    assert list(record) == ["ts", "kind", "conn_id", "client_ip", "client_port"]
    assert ", " not in raw and '": ' not in raw  # compact separators, no spaces


REDACT_NAMES = ["authorization", "proxy_authorization", "password", "passwd",
                "secret", "token", "cookie", "set_cookie", "api_key"]


def spellings(name: str) -> list:
    """Different ways a caller might write the same key name."""
    dashed = name.replace("_", "-")
    return [name, name.upper(), dashed, dashed.title()]  # e.g. Proxy-Authorization


@pytest.mark.parametrize(
    "key", [spelling for name in REDACT_NAMES for spelling in spellings(name)])
def test_secret_keys_are_redacted(make_logger, key):
    logger, path = make_logger()
    logger.event("auth_fail", **{key: "hunter2"})
    text = "\n".join(read_lines(logger, path))
    assert json.loads(text)[key] == "[REDACTED]"
    assert "hunter2" not in text  # the secret never reaches the file


def test_redaction_works_at_any_depth(make_logger):
    logger, path = make_logger()
    logger.event("req_forward", headers={"Proxy-Authorization": "Basic abc", "host": "x"},
                 extra=[{"deep": {"Cookie": "sid=SECRET1"}}])
    text = "\n".join(read_lines(logger, path))
    record = json.loads(text)
    assert record["headers"]["Proxy-Authorization"] == "[REDACTED]"
    assert record["headers"]["host"] == "x"  # normal fields are untouched
    assert record["extra"][0]["deep"]["Cookie"] == "[REDACTED]"
    assert "SECRET1" not in text


def test_basic_and_bearer_credentials_are_scrubbed(make_logger):
    logger, path = make_logger()
    logger.event("error", where="forward",
                 message="upstream sent Bearer abc.def.ghi and Basic dXNlcjpwYXNz failed")
    record = read_events(logger, path)[0]
    assert record["message"] == "upstream sent Bearer [REDACTED] and Basic [REDACTED] failed"


def test_body_fields_are_never_logged(make_logger):
    logger, path = make_logger()
    logger.event("req_forward", body="SECRET-BODY", request_body="a",
                 response_body="b", status=200)
    text = "\n".join(read_lines(logger, path))
    record = json.loads(text)
    assert record["status"] == 200  # other fields stay
    assert not {"body", "request_body", "response_body"} & set(record)
    assert "SECRET-BODY" not in text


def test_query_is_stripped_from_paths_by_default(make_logger):
    logger, path = make_logger()
    logger.event("req_forward", path="/a?token=abc&x=1", meta={"path": "/b?q=1"}, other=None)
    record = read_events(logger, path)[0]
    assert record["path"] == "/a"  # everything after "?" is gone
    assert record["meta"]["path"] == "/b"  # also inside nested dicts
    logger.event("req_blocked", path=None)  # CONNECT has no path: must stay null
    assert read_events(logger, path)[-1]["path"] is None


def test_query_is_kept_when_log_query_is_true(make_logger):
    logger, path = make_logger(log_query=True)
    logger.event("req_forward", path="/a?x=1")
    assert read_events(logger, path)[0]["path"] == "/a?x=1"


KINDS = ["conn_open", "auth_fail", "req_blocked", "error"]  # INFO, WARNING, WARNING, ERROR


@pytest.mark.parametrize("level, expected", [
    ("DEBUG", KINDS),
    ("INFO", KINDS),
    ("WARNING", ["auth_fail", "req_blocked", "error"]),
    ("ERROR", ["error"]),
    ("bogus", KINDS),  # unknown level name falls back to INFO
])
def test_level_filtering(make_logger, level, expected):
    logger, path = make_logger(level=level)
    for kind in KINDS:
        logger.event(kind)
    kinds = [e["kind"] for e in read_events(logger, path)] if expected else []
    assert kinds == expected


def test_file_rotates_and_keeps_only_the_backup_limit(make_logger):
    logger, path = make_logger(max_bytes=2000, backups=2)
    for i in range(100):
        logger.event("req_forward", i=i, note="x" * 100)  # about 170 bytes per line
    logger.flush()
    names = sorted(p.name for p in path.parent.iterdir())
    assert names == ["proxy.jsonl", "proxy.jsonl.1", "proxy.jsonl.2"]  # no .3
    for name in names:  # every line in every file is still valid JSON
        for line in (path.parent / name).read_text(encoding="utf-8").splitlines():
            json.loads(line)
    newest = json.loads(path.read_text(encoding="utf-8").splitlines()[-1])
    assert newest["i"] == 99  # the latest event is in the main file


def test_full_queue_drops_events_counts_them_and_never_blocks(make_logger):
    stats = build_stats()
    logger, path = make_logger(queue_size=5, stats=stats)
    started, release = threading.Event(), threading.Event()
    real_write = logger._write

    def blocked_write(item):
        started.set()  # tell the test the writer has taken its first event
        release.wait(timeout=5)  # hold the writer so the queue cannot drain
        real_write(item)

    logger._write = blocked_write
    logger.event("req_forward", n=0)
    assert started.wait(timeout=2)  # writer holds event 0; queue is now empty
    begin = time.monotonic()
    for n in range(1, 11):  # 5 fit in the queue, the other 5 must be dropped
        logger.event("req_forward", n=n)
    assert time.monotonic() - begin < 1.0  # callers were never made to wait
    assert logger.dropped == 5
    assert stats.snapshot()["log_dropped"] == 5
    release.set()
    assert len(read_lines(logger, path)) == 6  # 1 in flight + 5 queued were written


def test_tail_order_clamp_and_copies(make_logger):
    logger, path = make_logger(ring_size=5)
    for i in range(8):
        logger.event("req_forward", i=i)
    logger.flush()
    assert [e["i"] for e in logger.tail(100)] == [3, 4, 5, 6, 7]  # clamped, newest last
    assert [e["i"] for e in logger.tail(2)] == [6, 7]
    assert logger.tail(0) == [] and logger.tail("bad") == []  # bad n never raises
    copy_of_last = logger.tail(1)[0]
    copy_of_last["i"] = 999  # editing our copy...
    assert logger.tail(1)[0]["i"] == 7  # ...does not change the stored event


class BrokenRepr:
    """Object whose repr() raises."""

    def __repr__(self):
        raise RuntimeError("boom")


class BrokenStr:
    """Object whose str() raises (used as a dict key below)."""

    def __str__(self):
        raise RuntimeError("boom")


def test_weird_values_never_raise_and_stay_valid_json(make_logger):
    logger, path = make_logger()
    cyclic: dict = {}
    cyclic["self"] = cyclic  # a dict that contains itself
    logger.event(
        "error", raw=b"\xff\xfe", obj=object(), broken=BrokenRepr(), cyc=cyclic,
        nan=float("nan"), inf=float("inf"), huge="x" * 1_000_000,
        keys={1: "a", (2, 3): "b", BrokenStr(): "c"}, tags={1, 2},
        deep=[[[[[[[[[[1]]]]]]]]]])
    logger.event(None)  # kind that is not text
    logger.event(123, x=1)
    events = read_events(logger, path)  # every line must parse as JSON
    first = events[0]
    assert len(first["huge"]) == 500  # cut to the limit
    assert first["nan"] == "nan" and first["inf"] == "inf"  # not invalid JSON tokens
    assert set(first["keys"]) == {"1", "(2, 3)", "<unprintable>"}
    assert "<max depth>" in json.dumps(first)  # self-reference and deep nesting stopped
    assert [e["kind"] for e in events[1:]] == ["None", "123"]


def test_close_writes_everything_and_ignores_later_events(make_logger):
    logger, path = make_logger()
    for i in range(500):
        logger.event("req_forward", i=i)
    logger.close()  # no flush() call: close must do it
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 500
    logger.event("req_forward", late=True)  # after close: silently ignored
    logger.close()  # closing twice is harmless
    assert len(path.read_text(encoding="utf-8").splitlines()) == 500


def test_bad_log_path_does_not_crash(tmp_path, capsys):
    blocker = tmp_path / "blocker"
    blocker.write_text("i am a file, not a folder")
    logger = JsonLogger(blocker / "sub" / "x.jsonl", console=False)  # cannot mkdir
    try:
        logger.event("error", where="test")
        assert logger.flush()
        assert logger.tail(1)[0]["kind"] == "error"  # ring buffer still works
    finally:
        logger.close()
    assert "cannot use log file" in capsys.readouterr().err


def test_console_output_goes_to_stderr(tmp_path, capsys):
    logger = JsonLogger(tmp_path / "c.jsonl", console=True)
    try:
        logger.event("conn_open", conn_id=1)
        assert logger.flush()
    finally:
        logger.close()
    assert '"kind":"conn_open"' in capsys.readouterr().err


def test_build_logger_reads_the_config_keys(tmp_path):
    config = DictConfig({"logging": {"file": str(tmp_path / "cfg.jsonl"), "console": False,
                                     "level": "ERROR", "ring_size": 3}})
    logger = build_logger(config, build_stats())
    try:
        logger.event("conn_open")  # INFO: below ERROR, so ignored
        logger.event("error", where="cfg")
        assert logger.flush()
        assert [e["kind"] for e in logger.tail(10)] == ["error"]
    finally:
        logger.close()
    assert (tmp_path / "cfg.jsonl").exists()
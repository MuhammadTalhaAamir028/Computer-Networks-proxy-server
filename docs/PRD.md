# PRD — Custom Multi-Feature Proxy Server (Python)

Computer Networks (CS3001) capstone project. Three-person team. 8-week schedule.
This document is the **full shared context**. Role-specific build instructions for
each member follow separately, after this is loaded.

Team: **Talha** (Networking/core), **Sufyan** (Rules/security), **Abdur Rehman** (Logs/tests/dashboard).

---

## 1. What we are building

A **custom forward proxy server in Python, built from raw sockets** — not a proxy
framework. It sits between browsers and websites: receives a request, checks login
and rules, forwards allowed traffic, and records what happened.

- **Plain HTTP:** parse the request, rewrite the first line from a full URL to a
  path, forward it, return the reply.
- **HTTPS:** the browser sends `CONNECT host:443`. The proxy replies
  `200 Connection established` and then copies bytes both ways without reading
  them. It never decrypts HTTPS. Filtering on HTTPS therefore works on **host and
  port only**.
- **Concurrency:** one thread per client connection, from a capped thread pool.
  When the pool is full the proxy answers `503`. Asyncio is out of scope.
- **Rules and login:** domain and port rules, an SSRF guard (block localhost and
  private IPs), Basic proxy login with lockout, `403` and `407` responses.
- **Observability:** JSON-lines logs, thread-safe counters, an admin API on port
  8081, and a small web dashboard that polls it.
- **Out of scope:** HTTPS interception, proxy clusters, enterprise login, content
  inspection, caching, asyncio.

Two ideas run through everything:

1. **Rules run before any connection to the website.**
2. **Every module hides behind a frozen contract** so three people build in
   parallel and merge without surprises.

**Goal:** understand the project while building it — real-world skills, not just
a passing grade.

---

## 2. Team and ownership

| Member | Area | Owns (only this member edits these paths) |
|---|---|---|
| Talha | Networking / core | `proxy/core/`, `proxy/__main__.py`, `tests/unit/core/`, `README.md` |
| Sufyan | Rules and security | `proxy/control/`, `configs/`, `tests/unit/control/`, `docs/rules-syntax.md`, `ui/panels/rules.js`, `ui/panels/auth.js` |
| Abdur Rehman | Logs, tests, dashboard | `proxy/obs/`, `tools/`, `tests/unit/obs/`, `tests/fixtures/`, `ui/index.html`, `ui/app.js`, `ui/style.css`, `ui/panels/stats.js`, `ui/panels/logs.js`, `Makefile`, `.github/`, `requirements-dev.txt` |
| Shared | Contract and layout | `proxy/interfaces.py`, `proxy/stubs.py`, `.gitignore`, `tests/integration/` (one file per member: `test_it_<area>.py`) |

Talha's core code calls the other two modules **only** through the contract in
Section 6. Sufyan and Abdur Rehman never open client or website sockets. Talha
never edits rules, login, logging or admin code.

> **Middleman rule.** If a spec is unclear or a contract change is needed, do not
> guess and do not edit someone else's folder. Stop and flag it back to the human
> team. The contract changes only when all three agree.

---

## 3. Hard rules for all code

1. **Python 3.10+. Standard library only at runtime.** Dev-only extras: `pytest`, `pytest-cov`.
2. **Cross-platform:** Windows, macOS, Linux. No `fcntl`. Guard `signal.SIGHUP`
   with `hasattr(signal, "SIGHUP")`. Use `pathlib`. Open text files with
   `encoding="utf-8"`. Don't assume `bash`.
3. **Thread-safe.** Every contract object is called from many threads at once.
   Protect shared state with a lock. No unguarded globals.
4. **Never crash the server.** Public methods must not raise on bad input. Return
   a `Decision`, `AuthResult`, or documented value. Only `ConfigError` may escape,
   and only at startup.
5. **No secrets in output.** Never log, print or return passwords, hashes, salts,
   `Authorization`/`Proxy-Authorization` values, cookies, or request/response bodies.
6. **Contract is frozen.** Don't rename or re-sign anything in Section 6.
7. **Stay in your folders** (Section 2). Read other folders freely. Never edit them.
8. **Tests are part of the work.** Unit tests pass with no proxy running. Coverage
   on your package ≥ 70%.
9. **Code quality.** Type hints, short docstrings, small functions, line length ≤
   100, no dead code, no leftover `TODO` in merged code, no bare `print` outside
   command-line tools.
10. **No invented features.** Items marked OPTIONAL are optional. Anything unlisted
    is out of scope.
11. **Show evidence.** Every pull request pastes test output and lists exit-gate
    commands run.

---

## 4. Repository layout

```
proxy/
  interfaces.py        # FROZEN contract (shared)
  stubs.py              # fake modules for solo testing (shared)
  __main__.py           # wires everything, starts server   [Talha]
  core/                  # sockets, parser, forwarding, tunnel [Talha]
  control/               # config, filter, auth, responses     [Sufyan]
  obs/                    # logger, stats, admin server         [Abdur Rehman]
tools/                   # origin servers, load/soak tools     [Abdur Rehman]
tests/
  unit/{core,control,obs}/
  integration/           # test_it_core.py, test_it_control.py, test_it_obs.py
  fixtures/               # test-only TLS cert and key          [Abdur Rehman]
ui/                       # index.html, app.js, style.css, panels/*.js
configs/                  # config.example.json, config.dev.json [Sufyan]
docs/                     # rules-syntax.md, results/, captures/
Makefile  requirements-dev.txt  .gitignore  README.md  .github/workflows/ci.yml
```

Run: `python -m proxy --config configs/config.dev.json`
Test: `python -m pytest`
Makefile targets are a convenience only — `python -m` commands are canonical
(Windows has no `make` by default).

---

## 5. Git workflow

- **Branches:** `feat/core` (Talha), `feat/control` (Sufyan), `feat/obs` (Abdur
  Rehman). Never commit straight to `main`.
- **Commits:** small, frequent. Format `area: what changed`, e.g.
  `control: add wildcard matching`.
- **Pull requests into `main`.** One cross-review each: Talha reviews Sufyan,
  Sufyan reviews Abdur Rehman, Abdur Rehman reviews Talha. Checklist: contract
  respected, tests pass, no secrets, thread safety, no edits outside owned folders.
- **Days 1–2:** Talha opens one contract PR with `interfaces.py`, `stubs.py`, the
  layout skeleton, `.gitignore`, `requirements-dev.txt`. All three approve. Tag
  `contract-v1`. Nothing else merges before this.
- **Never commit:** `config.json`, anything in `logs/`, `.venv/`, `__pycache__/`,
  `.coverage`. Only `configs/config.example.json` and `configs/config.dev.json`
  (no real credentials) are committed. `tests/fixtures/` is allowed (test-only).
- **Phase 3 merge order:** Abdur Rehman first, Sufyan second, Talha last (replaces
  stubs with real modules). Tag `v0.9-integrated`. Code freeze mid-week 7. Tag
  `v1.0` in week 8.

---

## 6. The frozen contract

Copy these files exactly. They are the only coupling between the three modules.

### 6.1 `proxy/interfaces.py`

```python
"""proxy/interfaces.py -- FROZEN CONTRACT. Change only by PR approved by all three."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Optional, Protocol

EVENT_KINDS = ("conn_open", "conn_close", "req_forward", "req_blocked",
               "auth_fail", "tunnel_open", "tunnel_close", "error")
STAT_KEYS = ("requests_total", "requests_blocked", "active_conns",
             "bytes_up", "bytes_down", "errors")

@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str = ""              # human-readable, safe to show the client
    rule: Optional[str] = None    # machine id, e.g. "deny:domain:*.ads.com"

@dataclass(frozen=True)
class AuthResult:
    ok: bool
    user: Optional[str] = None
    locked: bool = False          # True when the client IP is in lockout
    retry_after: int = 0          # seconds, valid when locked
    reason: str = ""              # missing | malformed | bad_creds | locked | ""

class FilterEngine(Protocol):
    def check(self, host: str, port: int, path: Optional[str], method: str) -> Decision: ...
    def check_ip(self, ip: str, port: int) -> Decision: ...      # resolved address
    def describe(self) -> dict: ...                              # rules, for the UI
    def forbidden_response(self, decision: Decision) -> bytes: ...   # full 403 reply

class Auth(Protocol):
    def check(self, headers: dict, client_ip: str) -> AuthResult: ...  # keys lowercase
    def challenge_response(self) -> bytes: ...                   # full 407 reply
    def locked_response(self, retry_after: int) -> bytes: ...    # full 429 reply
    def recent_failures(self, limit: int = 50) -> list: ...      # redacted dicts

class Logger(Protocol):
    def event(self, kind: str, **fields: Any) -> None: ...       # never raises
    def tail(self, n: int = 100) -> list: ...                    # newest last

class Stats(Protocol):
    def inc(self, name: str, n: int = 1) -> None: ...            # n may be negative
    def snapshot(self) -> dict: ...

class Config(Protocol):
    last_error: Optional[str]
    def get(self, key: str, default: Any = None) -> Any: ...     # dotted: "proxy.port"
    def reload(self) -> bool: ...
    def as_dict(self, redact: bool = True) -> dict: ...
```

### 6.2 `proxy/stubs.py`

```python
"""proxy/stubs.py -- fake modules so any member can run and test alone."""
import threading
from .interfaces import AuthResult, Decision, STAT_KEYS

class AllowAllFilter:
    def check(self, host, port, path, method): return Decision(True)
    def check_ip(self, ip, port): return Decision(True)
    def describe(self): return {"mode": "stub"}
    def forbidden_response(self, decision):
        return b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"

class NoAuth:
    def check(self, headers, client_ip): return AuthResult(ok=True)
    def challenge_response(self):
        return (b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                b"Proxy-Authenticate: Basic realm=\"proxy\"\r\n"
                b"Content-Length: 0\r\nConnection: close\r\n\r\n")
    def locked_response(self, retry_after):
        return b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    def recent_failures(self, limit=50): return []

class NullLogger:
    def event(self, kind, **fields): pass
    def tail(self, n=100): return []

class MemoryStats:
    def __init__(self):
        self._lock = threading.Lock()
        self._c = {k: 0 for k in STAT_KEYS}
    def inc(self, name, n=1):
        with self._lock: self._c[name] = self._c.get(name, 0) + n
    def snapshot(self):
        with self._lock: return dict(self._c)

class DictConfig:
    def __init__(self, data=None):
        self._d, self.last_error = data or {}, None
    def get(self, key, default=None):
        cur = self._d
        for part in key.split("."):
            if not isinstance(cur, dict) or part not in cur: return default
            cur = cur[part]
        return cur
    def reload(self): return True
    def as_dict(self, redact=True): return dict(self._d)
```

### 6.3 Factory functions (fixed names)

Talha's `__main__.py` builds the app by calling exactly these. Each owner
implements their own.

| Function | Owner | Returns |
|---|---|---|
| `proxy.control.config.load_config(argv=None) -> Config` | Sufyan | Loaded, validated config. Raises `ConfigError` on invalid input. |
| `proxy.control.build_filter(config) -> FilterEngine` | Sufyan | Filter engine, rules compiled from config. |
| `proxy.control.build_auth(config) -> Auth` | Sufyan | Auth object. When `auth.enabled` is false, `check` always returns ok. |
| `proxy.control.config.install_sighup(config) -> bool` | Sufyan | Installs a SIGHUP reload handler if the OS has SIGHUP. Returns whether it did. |
| `proxy.obs.build_stats() -> Stats` | Abdur Rehman | Thread-safe counters. |
| `proxy.obs.build_logger(config, stats=None) -> Logger` | Abdur Rehman | Non-blocking JSON-lines logger. Counts drops in `stats` as `log_dropped` if given. |
| `proxy.obs.start_admin(config, stats, logger, filter_engine, auth, tunnels_provider) -> AdminHandle` | Abdur Rehman | Running admin server. `handle.port` and `handle.stop()`. `tunnels_provider` is a callable returning a list of dicts. |

### 6.4 Event conventions

Talha calls `logger.event(kind, **fields)`. The logger adds `ts` (UTC ISO-8601
with milliseconds, ending `Z`) and `kind`. Field names are fixed so the
dashboard and tests can rely on them.

| Kind | Fields | When |
|---|---|---|
| `conn_open` | `conn_id, client_ip, client_port` | Client TCP connection accepted |
| `conn_close` | `conn_id, duration_ms, bytes_up, bytes_down, outcome` | Session over. outcome: ok, error, timeout, blocked, client_closed |
| `req_forward` | `conn_id, method, host, port, path, status, duration_ms` | Plain HTTP request answered |
| `req_blocked` | `conn_id, method, host, port, path, rule, reason` | Filter said no. `path` is null for CONNECT |
| `auth_fail` | `conn_id, client_ip, user, reason` | Login failed. `user` is the attempted name only, never the password |
| `tunnel_open` | `conn_id, host, port, ip` | CONNECT tunnel established |
| `tunnel_close` | `conn_id, host, port, bytes_up, bytes_down, duration_ms, reason` | Tunnel ended |
| `error` | `conn_id (optional), where, error, message` | Caught failure. `error` is the exception type name |

**Counters (`stats.inc`):** `requests_total` once per parsed request.
`requests_blocked` once per 403. `active_conns` is a gauge: +1 on open, -1 on
close. `bytes_up` is client→website. `bytes_down` is website→client. `errors`
once per `error` event. Extra names are allowed and never crash. `snapshot()`
always contains all six frozen keys, defaulting to 0.

### 6.5 Config file schema

One JSON file. Read with dotted keys, e.g. `config.get("proxy.port")`. Sufyan
owns loading and validation of the whole file. Each reader uses only its own
section.

| Key | Type | Default | Reader | Notes |
|---|---|---|---|---|
| `proxy.host` | str | 127.0.0.1 | core | Listen address |
| `proxy.port` | int | 8080 | core | 1–65535 |
| `proxy.max_threads` | int | 100 | core | Pool cap. Overflow gets 503 |
| `proxy.backlog` | int | 128 | core | |
| `proxy.connect_timeout` | float | 10 | core | Seconds to reach the website |
| `proxy.read_timeout` | float | 30 | core | Seconds waiting for data |
| `proxy.idle_timeout` | float | 60 | core | Tunnel idle limit, seconds |
| `proxy.max_header_bytes` | int | 16384 | core | Larger requests get 400 |
| `admin.host` | str | 127.0.0.1 | obs | Keep on loopback |
| `admin.port` | int | 8081 | obs | 0 means pick a free port (tests) |
| `filter.mode` | str | denylist | control | denylist or allowlist |
| `filter.deny_domains` | list[str] | [] | control | Exact or `*.example.com` |
| `filter.allow_domains` | list[str] | [] | control | Used in allowlist mode |
| `filter.blocked_ports` | list[int] | [25] | control | Always blocked |
| `filter.allowed_ports` | list[int] | [] | control | Empty means no port restriction |
| `filter.deny_url_regex` | list[str] | [] | control | Plain HTTP only. Matched on host+path |
| `filter.block_private_ips` | bool | true | control | The SSRF guard |
| `filter.private_allow` | list[str] | [] | control | `host:port` exceptions, for test origins |
| `auth.enabled` | bool | false | control | |
| `auth.realm` | str | proxy | control | |
| `auth.users` | dict | {} | control | name → `{salt, hash}` in hex |
| `auth.max_failures` | int | 5 | control | Failures before lockout |
| `auth.lockout_seconds` | int | 60 | control | |
| `auth.failure_window_seconds` | int | 300 | control | Window failures count in |
| `logging.file` | str | logs/proxy.jsonl | obs | |
| `logging.max_bytes` | int | 5000000 | obs | Rotate above this |
| `logging.backups` | int | 3 | obs | |
| `logging.console` | bool | true | obs | Also print to stderr |
| `logging.level` | str | INFO | obs | DEBUG, INFO, WARNING, ERROR |
| `logging.ring_size` | int | 2000 | obs | Events kept in memory for `tail` |
| `logging.log_query` | bool | false | obs | When false, strip `?query` from logged paths |

> **Test origins live on localhost, and the SSRF guard blocks localhost.** So
> `configs/config.dev.json` sets `filter.private_allow` to
> `["127.0.0.1:9000", "127.0.0.1:9443"]`. The default `config.example.json`
> leaves it empty.

### 6.6 Admin API (port 8081, loopback only)

Built by Abdur Rehman. Handlers call the other members' objects through the
contract. All bodies are UTF-8 JSON. Errors: `{"error": "..."}` with a correct
status code.

| Route | Method | Returns | Backed by |
|---|---|---|---|
| `/` | GET | Dashboard `ui/index.html` | static file |
| `/ui/<file>` | GET | Static dashboard assets | static file, no path traversal |
| `/health` | GET | `{status, uptime_s, open_fds, threads}` | obs |
| `/stats` | GET | `stats.snapshot()` plus `uptime_s` | Stats |
| `/logs?tail=N` | GET | `logger.tail(N)`. N 1–1000, default 100 | Logger |
| `/config` | GET | `config.as_dict(redact=True)` | Config |
| `/rules` | GET | `filter.describe()` | FilterEngine |
| `/rules/test` | POST | Body `{host, port, path, method}`. Returns the `Decision` as a dict | FilterEngine |
| `/auth/failures?limit=N` | GET | `auth.recent_failures(N)` | Auth |
| `/tunnels` | GET | `tunnels_provider()` | core (Talha) |
| `/reload` | POST | `{reloaded: bool, error: str or null}` | Config |

> **CSRF protection.** Any web page in the user's browser can send a request to
> `localhost:8081`. Every POST must carry `X-Requested-With: dashboard` and
> `Content-Type: application/json`. The server rejects anything else with 403
> and never answers CORS preflight with an allow. The dashboard adds the header.

### 6.7 Dashboard panel API

The dashboard is one page. Abdur Rehman owns the shell. Each panel is its own
file so nobody edits the same file. The shell tries to load
`ui/panels/{stats,logs,rules,auth,core}.js` and ignores any that are missing.

```js
Dashboard.register({
  id: "rules",          // must match the file name
  title: "Rules",
  order: 30,            // panels render in ascending order
  mount(el, api) {},    // build the DOM once
  refresh(el, api) {},  // called every 1000 ms
});
// api.get(path)        -> Promise of parsed JSON
// api.post(path, body) -> Promise of parsed JSON (shell adds the CSRF header)
```

> **XSS rule.** Log lines, hostnames and usernames are attacker-controlled.
> Panels must write them with `textContent` or `createTextNode`. Never use
> `innerHTML` with dynamic data. No external scripts, fonts or CDNs — the demo
> must work offline.

---

## 7. Phases (overview)

| Phase | Weeks | Mode | Result |
|---|---|---|---|
| 1. Foundations | 1–2 | Independent | Contract frozen, first pieces |
| 2. Features | 3–5 | Independent | Each area tested alone, 70% coverage |
| 3. Integration | 6–7 | All three | One working proxy, merged in order Abdur Rehman → Sufyan → Talha |
| 4. UI + demo | 8 | All three | Dashboard, GitHub polish, instructor demo |

Full per-role deliverables, specs, test lists and exit gates are in each
member's own role brief (given separately, after this PRD is loaded).

---

## 8. Known decisions (do not re-litigate these)

| Issue | Decision |
|---|---|
| Concurrency model | Thread per connection, capped pool. Asyncio is future work. |
| HTTPS filtering | Host and port only — state this in the report. |
| Auth scope | Login must cover CONNECT, not just plain HTTP. |
| SSRF | Block localhost and private IPs; explicit exceptions for test origins. |
| Observability | Admin API on port 8081 feeds the dashboard. |
| Workload balance | Networking (Talha) is heaviest; others support it early, esp. Abdur Rehman's test origin servers needed in week 1. |

---

## 9. Out of scope (do not build)

HTTPS interception / MITM · enterprise identity systems · distributed proxy
clusters · deep content inspection · Internet-scale optimization · response
caching · load balancing · asyncio · chunked **request** bodies (chunked
**responses** are passed through raw, not parsed).

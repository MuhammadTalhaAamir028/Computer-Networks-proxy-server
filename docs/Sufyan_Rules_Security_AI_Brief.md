<!-- Running page header (repeated on every page of the original): CN Proxy Capstone | AI Build Brief | Sufyan | Rules and Security -->

# AI Build Brief: Rules and Security

For Sufyan's AI assistant. CN Proxy Capstone, custom Python proxy server.

### How to use this document

Give this **whole document** to your AI assistant before it writes any code. It has two parts. **Part A** is shared context and the frozen contract. It is identical in all three members' briefs. **Part B** is your own assignment.

1. Read Part A fully. Do not skip the contract in A6.
2. Read Part B. Build in the order of the phase table in B8.
3. Copy `interfaces.py` and `stubs.py` from A6 exactly. Do not improve them.
4. Work on your branch. Write tests as you go. Run them before saying anything is done.
5. If anything is unclear or needs a contract change, **stop and ask your human**. Do not guess and do not edit other people's folders.

> **Your human is the middleman.** The three members coordinate through Talha's contract. Your AI only sees this brief. Anything that must be agreed with another member goes through your human.

## Part A. Shared context (identical in every member's brief)

### A1. The project in one page

We are building a **custom forward proxy server in Python from raw sockets**. It is a Computer Networks capstone for three students over 8 weeks. It sits between browsers and websites. It receives a request, checks login and rules, forwards allowed traffic, and records what happened.

- **Plain HTTP:** the proxy parses the request, rewrites the first line from a full URL to a path, forwards it, and returns the reply.
- **HTTPS:** the browser sends `CONNECT host:443`. The proxy replies `200 Connection established` and then copies bytes both ways without reading them. It never decrypts HTTPS. Filtering on HTTPS therefore works on **host and port only**.
- **Concurrency:** one thread per client connection, from a capped thread pool. When the pool is full the proxy answers `503`. Asyncio is out of scope.
- **Rules and login:** domain and port rules, an SSRF guard (block localhost and private IPs), Basic proxy login with lockout, `403` and `407` responses.
- **Observability:** JSON-lines logs, thread-safe counters, an admin API on port 8081, and a small web dashboard that polls it.
- **Out of scope:** HTTPS interception, proxy clusters, enterprise login, content inspection, caching, asyncio.

Two ideas run through everything. **Rules run before any connection to the website.** **Every module hides behind a frozen contract** so three people can build in parallel and merge without surprises.

### A2. Team and ownership

| Member | Area | Owns (only this member edits these paths) |
| --- | --- | --- |
| Talha | Networking / core | `proxy/core/`, `proxy/__main__.py`, `tests/unit/core/`, `README.md` |
| Sufyan | Rules and security | `proxy/control/`, `configs/`, `tests/unit/control/`, `docs/rules-syntax.md`, `ui/panels/rules.js`, `ui/panels/auth.js` |
| Abdur Rehman | Logs, tests, dashboard | `proxy/obs/`, `tools/`, `tests/unit/obs/`, `tests/fixtures/`, `ui/index.html`, `ui/app.js`, `ui/style.css`, `ui/panels/stats.js`, `ui/panels/logs.js`, `Makefile`, `.github/`, `requirements-dev.txt` |
| Shared | Contract and layout | `proxy/interfaces.py`, `proxy/stubs.py`, `.gitignore`, `tests/integration/` (one file per member: `test_it_<area>.py`) |

Talha's core code calls the other two modules only through the contract in A6. Sufyan and Abdur Rehman never open client or website sockets. Talha never edits the rules, login, logging or admin code.

> **Middleman rule.** If your spec is unclear or you need a contract change, do not guess and do not edit someone else's folder. Stop and tell your human. They raise it with Talha and the other member. The contract changes only when all three agree.

### A3. Hard rules for all code

1. **Python 3.10 or newer. Standard library only at runtime.** Dev-only extras are `pytest` and `pytest-cov`.
2. **Cross-platform: Windows, macOS, Linux.** No `fcntl`. Guard `signal.SIGHUP` with `hasattr(signal, "SIGHUP")`. Use `pathlib`. Open text files with `encoding="utf-8"`. Do not assume `bash`.
3. **Thread-safe.** Every contract object is called from many threads at once. Protect shared state with a lock. No unguarded globals.
4. **Never crash the server.** Public methods must not raise on bad input. Return a `Decision`, `AuthResult` or documented value. Only `ConfigError` may escape, and only at startup.
5. **No secrets in output.** Never log, print or return passwords, hashes, salts, `Authorization` or `Proxy-Authorization` values, cookies, or request and response bodies.
6. **Contract is frozen.** Do not rename or re-sign anything in A6: functions, event kinds, stat keys, config keys, admin routes, panel API.
7. **Stay in your folders** (A2). Read other folders freely. Never edit them.
8. **Tests are part of the work.** Unit tests must pass with no proxy running. Coverage on your package must be at least 70 percent. Run the tests yourself before you say something is done.
9. **Code quality.** Type hints, short docstrings, small functions, line length at most 100, no dead code, no leftover `TODO` in merged code, no `print` outside command-line tools.
10. **No invented features.** Items marked OPTIONAL are optional. Everything else unlisted is out of scope.
11. **Show evidence.** Every pull request description pastes the test output and lists the exit-gate commands you ran.

### A4. Repository layout

```
proxy/
  interfaces.py        # FROZEN contract (shared)
  stubs.py             # fake modules for solo testing (shared)
  __main__.py          # wires everything, starts server   [Talha]
  core/                # sockets, parser, forwarding, tunnel [Talha]
  control/             # config, filter, auth, responses     [Sufyan]
  obs/                 # logger, stats, admin server         [Abdur Rehman]
tools/                 # origin servers, load/soak tools     [Abdur Rehman]
tests/
  unit/{core,control,obs}/
  integration/         # test_it_core.py, test_it_control.py, test_it_obs.py
  fixtures/            # test-only TLS cert and key          [Abdur Rehman]
ui/                    # index.html, app.js, style.css, panels/*.js
configs/               # config.example.json, config.dev.json [Sufyan]
docs/                  # rules-syntax.md, results/, captures/
Makefile  requirements-dev.txt  .gitignore  README.md  .github/workflows/ci.yml
```

Run the proxy with `python -m proxy --config configs/config.dev.json`. Run tests with `python -m pytest`. Makefile targets are a convenience only. The `python -m` commands are canonical because Windows has no `make` by default.

### A5. Git workflow

- **Branches:** `feat/core` (Talha), `feat/control` (Sufyan), `feat/obs` (Abdur Rehman). Never commit straight to `main`.
- **Commits:** small and frequent. Message format `area: what changed`, for example `control: add wildcard matching`.
- **Pull requests into `main`.** Each needs one cross-review: Talha reviews Sufyan, Sufyan reviews Abdur Rehman, Abdur Rehman reviews Talha. Reviewer checklist: contract respected, tests pass, no secrets, thread safety, no edits outside owned folders.
- **Days 1 and 2:** Talha opens one contract pull request with `interfaces.py`, `stubs.py`, the layout skeleton, `.gitignore` and `requirements-dev.txt`. All three approve. Tag `contract-v1`. Nothing else merges before this.
- **Never commit:** `config.json`, anything in `logs/`, `.venv/`, `__pycache__/`, `.coverage`. Only `configs/config.example.json` and `configs/config.dev.json` (no real credentials) are committed. Test fixtures under `tests/fixtures/` are allowed because they are test-only.
- **Phase 3 merge order:** Abdur Rehman first, Sufyan second, Talha last (Talha replaces stubs with the real modules). Tag `v0.9-integrated`. Code freeze in the middle of week 7. Tag `v1.0` in week 8.

## A6. The frozen contract

Copy these files exactly. They are the only coupling between the three modules.

### A6.1 proxy/interfaces.py

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

### A6.2 proxy/stubs.py

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

### A6.3 Factory functions (fixed names)

Talha's `__main__.py` builds the app by calling exactly these. Each owner implements their own.

| Function | Owner | Returns |
| --- | --- | --- |
| `proxy.control.config.load_config(argv=None) -> Config` | Sufyan | Loaded, validated config. Raises `ConfigError` on invalid input. |
| `proxy.control.build_filter(config) -> FilterEngine` | Sufyan | Filter engine, rules compiled from config. |
| `proxy.control.build_auth(config) -> Auth` | Sufyan | Auth object. When `auth.enabled` is false, `check` always returns ok. |
| `proxy.control.config.install_sighup(config) -> bool` | Sufyan | Installs a SIGHUP reload handler if the OS has SIGHUP. Returns whether it did. |
| `proxy.obs.build_stats() -> Stats` | Abdur Rehman | Thread-safe counters. |
| `proxy.obs.build_logger(config, stats=None) -> Logger` | Abdur Rehman | Non-blocking JSON-lines logger. Counts drops in `stats` as `log_dropped` if given. |
| `proxy.obs.start_admin(config, stats, logger, filter_engine, auth, tunnels_provider) -> AdminHandle` | Abdur Rehman | Running admin server. `handle.port` and `handle.stop()`. `tunnels_provider` is a callable returning a list of dicts. |

### A6.4 Event conventions

Talha calls `logger.event(kind, **fields)`. The logger adds `ts` (UTC ISO-8601 with milliseconds, ending in `Z`) and `kind`. Field names below are fixed so the dashboard and the tests can rely on them.

| Kind | Fields | When |
| --- | --- | --- |
| `conn_open` | `conn_id, client_ip, client_port` | Client TCP connection accepted |
| `conn_close` | `conn_id, duration_ms, bytes_up, bytes_down, outcome` | Session over. outcome: ok, error, timeout, blocked, client_closed |
| `req_forward` | `conn_id, method, host, port, path, status, duration_ms` | Plain HTTP request answered |
| `req_blocked` | `conn_id, method, host, port, path, rule, reason` | Filter said no. `path` is null for CONNECT |
| `auth_fail` | `conn_id, client_ip, user, reason` | Login failed. `user` is the attempted name only, never the password |
| `tunnel_open` | `conn_id, host, port, ip` | CONNECT tunnel established |
| `tunnel_close` | `conn_id, host, port, bytes_up, bytes_down, duration_ms, reason` | Tunnel ended |
| `error` | `conn_id (optional), where, error, message` | Caught failure. `error` is the exception type name |

**Counters (`stats.inc`):** `requests_total` once per parsed request. `requests_blocked` once per 403. `active_conns` is a gauge: plus 1 on open, minus 1 on close. `bytes_up` is client to website. `bytes_down` is website to client. `errors` once per `error` event. Extra names are allowed and never crash. `snapshot()` always contains all six frozen keys, defaulting to 0.

### A6.5 Config file schema

One JSON file. Read with dotted keys, for example `config.get("proxy.port")`. Sufyan owns loading and validation of the whole file. Each reader uses only its own section.

| Key | Type | Default | Reader | Notes |
| --- | --- | --- | --- | --- |
| `proxy.host` | str | 127.0.0.1 | core | Listen address |
| `proxy.port` | int | 8080 | core | 1 to 65535 |
| `proxy.max_threads` | int | 100 | core | Pool cap. Overflow gets 503 |
| `proxy.backlog` | int | 128 | core |  |
| `proxy.connect_timeout` | float | 10 | core | Seconds to reach the website |
| `proxy.read_timeout` | float | 30 | core | Seconds waiting for data |
| `proxy.idle_timeout` | float | 60 | core | Tunnel idle limit, seconds |
| `proxy.max_header_bytes` | int | 16384 | core | Larger requests get 400 |
| `admin.host` | str | 127.0.0.1 | obs | Keep on loopback |
| `admin.port` | int | 8081 | obs | 0 means pick a free port (tests) |
| `filter.mode` | str | denylist | control | denylist or allowlist |
| `filter.deny_domains` | list\[str\] | \[\] | control | Exact or `*.example.com` |
| `filter.allow_domains` | list\[str\] | \[\] | control | Used in allowlist mode |
| `filter.blocked_ports` | list\[int\] | \[25\] | control | Always blocked |
| `filter.allowed_ports` | list\[int\] | \[\] | control | Empty means no port restriction |
| `filter.deny_url_regex` | list\[str\] | \[\] | control | Plain HTTP only. Matched on host+path |
| `filter.block_private_ips` | bool | true | control | The SSRF guard |
| `filter.private_allow` | list\[str\] | \[\] | control | `host:port` exceptions, for test origins |
| `auth.enabled` | bool | false | control |  |
| `auth.realm` | str | proxy | control |  |
| `auth.users` | dict | {} | control | name to `{salt, hash}` in hex |
| `auth.max_failures` | int | 5 | control | Failures before lockout |
| `auth.lockout_seconds` | int | 60 | control |  |
| `auth.failure_window_seconds` | int | 300 | control | Window that failures count in |
| `logging.file` | str | logs/proxy.jsonl | obs |  |
| `logging.max_bytes` | int | 5000000 | obs | Rotate above this |
| `logging.backups` | int | 3 | obs |  |
| `logging.console` | bool | true | obs | Also print to stderr |
| `logging.level` | str | INFO | obs | DEBUG, INFO, WARNING, ERROR |
| `logging.ring_size` | int | 2000 | obs | Events kept in memory for `tail` |
| `logging.log_query` | bool | false | obs | When false, strip `?query` from logged paths |

> **Test origins live on localhost, and the SSRF guard blocks localhost.** So `configs/config.dev.json` sets `filter.private_allow` to `["127.0.0.1:9000", "127.0.0.1:9443"]`. The default `config.example.json` leaves it empty.

### A6.6 Admin API (port 8081, loopback only)

Built by Abdur Rehman. Handlers call the other members' objects through the contract. All bodies are UTF-8 JSON. Errors look like `{"error": "..."}` with a correct status code.

| Route | Method | Returns | Backed by |
| --- | --- | --- | --- |
| `/` | GET | Dashboard `ui/index.html` | static file |
| `/ui/<file>` | GET | Static dashboard assets | static file, no path traversal |
| `/health` | GET | `{status, uptime_s, open_fds, threads}` | obs |
| `/stats` | GET | `stats.snapshot()` plus `uptime_s` | Stats |
| `/logs?tail=N` | GET | `logger.tail(N)`. N from 1 to 1000, default 100 | Logger |
| `/config` | GET | `config.as_dict(redact=True)` | Config |
| `/rules` | GET | `filter.describe()` | FilterEngine |
| `/rules/test` | POST | Body `{host, port, path, method}`. Returns the `Decision` as a dict | FilterEngine |
| `/auth/failures?limit=N` | GET | `auth.recent_failures(N)` | Auth |
| `/tunnels` | GET | `tunnels_provider()` | core (Talha) |
| `/reload` | POST | `{reloaded: bool, error: str or null}` | Config |

> **CSRF protection.** Any web page in the user's browser can send a request to `localhost:8081`. Every POST must carry the header `X-Requested-With: dashboard` and `Content-Type: application/json`. The server rejects anything else with 403 and never answers CORS preflight with an allow. The dashboard adds the header.

### A6.7 Dashboard panel API

The dashboard is one page. Abdur Rehman owns the shell. Each panel is its own file, so nobody edits the same file. The shell tries to load `ui/panels/{stats,logs,rules,auth,core}.js` and ignores any that are missing.

```javascript
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

> **XSS rule.** Log lines, hostnames and usernames are attacker-controlled. Panels must write them with `textContent` or `createTextNode`. Never use `innerHTML` with dynamic data. No external scripts, fonts or CDNs, because the demo must work offline.

## Part B. Your assignment: Rules and Security (Sufyan)

### B1. Mission

You own everything that decides **whether a request is allowed and who may make it**, plus the **configuration system for the whole app**. You write pure logic. **You never open a socket and never call DNS.** Talha's core calls you; you return decisions and ready-to-send HTTP reply bytes.

Your code is the security boundary of the project. Correct and boring beats clever. When the spec is ambiguous, choose the safer behaviour and say so in the pull request.

### B2. Deliverables

| File | What it is | Phase |
| --- | --- | --- |
| `proxy/control/__init__.py` | Exports `build_filter`, `build_auth` and the config helpers exactly as in A6.3 | 1 |
| `proxy/control/config.py` | `load_config`, `ConfigError`, config class, validation, defaults, redaction, reload, `install_sighup` | 1, 2 |
| `proxy/control/hostnorm.py` | Host normalization and IP parsing helpers used by the filter | 1 |
| `proxy/control/filter_engine.py` | The filter engine | 1, 2 |
| `proxy/control/auth.py` | Basic-auth verifier, lockout, credential cache | 1, 2 |
| `proxy/control/responses.py` | Builders for the 403, 407 and 429 reply bytes | 1 |
| `proxy/control/mkuser.py` | CLI: `python -m proxy.control.mkuser <name>` prints a `{salt, hash}` entry for the config | 1 |
| `configs/config.example.json`, `configs/config.dev.json` | Full example config with all keys. The dev config adds `private_allow` for the test origins | 1 |
| `tests/unit/control/` | At least 50 test cases (target list in B7) | 1, 2 |
| `tests/integration/test_it_control.py` | Your rows of the integration matrix (B8) | 3 |
| `docs/rules-syntax.md` | One page: rule syntax, evaluation order, worked examples | 2 |
| `ui/panels/rules.js`, `ui/panels/auth.js` | Dashboard panels using the API in A6.7 | 4 |

### B3. Specification: configuration

- **Sources, lowest to highest priority:** defaults in code, then the JSON file, then the environment variable `PROXY_CONFIG` (path only), then command line. Deep-merge dictionaries.
- **Command line (`argparse`):** `--config PATH`, `--port`, `--host`, `--admin-port`, `--log-file`, and a generic `--set key=value` (repeatable, dotted key, JSON-parsed value). `load_config(argv)` parses `argv`, defaulting to `sys.argv[1:]`.
- **Validation:** check every key in A6.5 for type and range. Unknown keys produce a warning list, not an error. On failure raise `ConfigError` with **all** problems listed, one per line. Error text must never contain secrets.
- **Immutability:** the loaded config is one immutable snapshot. `get()` is lock-free. `reload()` builds a new snapshot and swaps the reference atomically. Readers never see a half-loaded config.
- **`reload() -> bool`:** re-read the file, validate, swap. On any failure keep the old snapshot, set `last_error` to a safe message, return False. On success set `last_error = None`, return True.
- **`as_dict(redact=True)`:** deep copy. When redacting, replace every `salt`, `hash` and any key containing `password`, `secret` or `token` with `"[REDACTED]"`.
- **`install_sighup(config)`:** if `hasattr(signal, "SIGHUP")`, register a handler that calls `config.reload()`, return True. Otherwise return False. On Windows the `/reload` admin route is the only reload path.
- **Rule changes apply on reload:** the filter and auth objects read the config lazily or rebuild their compiled rules when `reload()` succeeds. Provide a small internal listener list so `build_filter` and `build_auth` re-compile on reload. Swapping compiled rules must be atomic and lock-free for readers.

### B4. Specification: filter engine

#### B4.1 Inputs

- `check(host, port, path, method)`. `path` is `None` for CONNECT because HTTPS paths are encrypted. `method` is upper-case.
- `check_ip(ip, port)`. Talha resolves the name, then calls this for **every** resolved address before connecting, and connects only to an address you allowed. This defeats DNS tricks where a public name resolves to a private IP. Never call `getaddrinfo` yourself.
- `describe()` returns a JSON-safe dict: mode, compiled rule lists as strings, flags, counts. No secrets exist here, but keep it small.
- `forbidden_response(decision)` returns the full 403 reply bytes (B4.4).

#### B4.2 Host normalization (do this first, always)

1. Reject empty hosts, hosts longer than 253 characters, and any host containing whitespace, control characters or NUL. Reject means `Decision(False, reason, rule="invalid:host")`.
2. Lower-case. Strip one trailing dot. Strip square brackets from IPv6 literals.
3. Convert internationalized names with `encodings.idna`. If that fails, reject.
4. If the host looks like an IP, parse it with `ipaddress`. Also parse the legacy forms attackers use: decimal `2130706433`, hex `0x7f000001`, octal `0177.0.0.1`, short `127.1`. Use `socket.inet_aton` for the legacy forms and convert the result. Treat IPv4-mapped IPv6 such as `::ffff:127.0.0.1` as the embedded IPv4 address.

#### B4.3 Evaluation order (first match wins)

| Step | Rule | Detail |
| --- | --- | --- |
| 1 | Normalize host | B4.2. Invalid host is blocked. |
| 2 | SSRF guard | If `block_private_ips` is true, block loopback, private, link-local, reserved, multicast and unspecified addresses (`ipaddress` properties). Block the names `localhost`, `*.localhost` and `0.0.0.0`. Exempt exactly the `host:port` pairs in `private_allow`. Rule id `ssrf:private_ip`. |
| 3 | Port rules | Block if `port` is in `blocked_ports`. If `allowed_ports` is non-empty, block any other port. Rule ids `port:blocked:N`, `port:not_allowed:N`. |
| 4 | Domain rules | **denylist mode:** block if the host matches any `deny_domains`. **allowlist mode:** block unless the host matches `allow_domains`. Rule ids `deny:domain:<pattern>`, `allow:none`. |
| 5 | URL regex | Only when `path` is not None (plain HTTP). Match each `deny_url_regex` against `host + path`, case-insensitive, on at most the first 2048 characters. Rule id `deny:url:<pattern>`. |
| 6 | Allow | `Decision(True)`. |

**Wildcard semantics.** `example.com` matches only itself. `*.example.com` matches any subdomain at any depth but **not** `example.com` itself. `evilexample.com` must **not** match `*.example.com`. To block both, list both. Only a leading `*.` is a wildcard. Reject other wildcard shapes at config validation.

**Regex safety.** Python's `re` has no timeout. Compile patterns at load time. Reject patterns longer than 200 characters or that fail to compile. Reject patterns containing nested quantifiers such as `(a+)+` or `(.*)*`. Truncate the matched text as in step 5.

**Concurrency.** The compiled rule set is immutable. A reload builds a new one and swaps the reference. `check` takes no lock.

#### B4.4 Block page

`forbidden_response` returns `HTTP/1.1 403 Forbidden` with `Content-Type: text/html; charset=utf-8`, an exact `Content-Length`, `Connection: close`, and a short HTML body naming the reason. HTML-escape every dynamic value with `html.escape`. Do not reveal rule internals beyond `decision.reason`.

### B5. Specification: authentication

- **Header:** read `headers.get("proxy-authorization")`. Keys are lower-case already. The scheme match is case-insensitive (`Basic`, `basic`).
- **Parsing:** reject headers over 512 characters, non-Basic schemes, invalid base64, non-UTF-8 payloads, and payloads without a colon. Split on the **first** colon only, because passwords may contain colons. Return `AuthResult(False, reason="malformed")` or `reason="missing"`.
- **Attempted user:** on `bad_creds` and `locked`, set `AuthResult.user` to the attempted username once it is parsed (before any password check). Talha logs it as `auth_fail.user` and `recent_failures` shows it. Never set, return or log the password. Leave `user` as `None` for `missing` and `malformed`.
- **Storage:** `auth.users` maps a name to `{"salt": hex, "hash": hex}`. Hash with `hashlib.scrypt(password, salt=salt, n=2**14, r=8, p=1, dklen=32)`. Salt is 16 random bytes from `secrets`. Never store plaintext.
- **Comparison:** `hmac.compare_digest` on the digests. For an **unknown user**, still compute a hash against a dummy salt so the timing does not reveal which usernames exist.
- **Credential cache:** hashing costs tens of milliseconds and every request carries the header. Keep a small cache of **successful** verifications keyed by `sha256(raw_header_value)`, time-to-live 300 seconds, at most 1024 entries, guarded by a lock. **Never cache failures.** Clear the cache on config reload.
- **Lockout:** track failures per `client_ip`. After `max_failures` failures inside `failure_window_seconds`, lock that IP for `lockout_seconds`. While locked return `AuthResult(False, locked=True, retry_after=<seconds left>, reason="locked")` without verifying anything. A success clears that IP's counter. Bound the tracking table to 10,000 IPs and evict the oldest. Take the clock as a constructor argument (default `time.monotonic`) so tests can fake time.
- **`recent_failures(limit)`:** newest last, each item `{ts, client_ip, user, reason}`. Never the password, never the header. Keep the last 200.
- **Disabled:** when `auth.enabled` is false, `check` returns `AuthResult(True)` immediately.
- **Replies:** `challenge_response()` is `407 Proxy Authentication Required` with `Proxy-Authenticate: Basic realm="<realm>"`, an exact `Content-Length`, `Connection: close`. `locked_response(retry_after)` is `429 Too Many Requests` with `Retry-After`. Both are complete byte strings.

> **Auth must protect CONNECT too.** Talha calls `auth.check` before he calls `filter.check`, for every request type. Your code does not need to know the request type. Make sure nothing in your design assumes one.

### B6. Order Talha's code calls you

```
1  parse request line + headers  -> method, host, port, path (None for CONNECT)
2  auth.check(headers, client_ip)
     not ok and locked -> send auth.locked_response(retry_after); log auth_fail; close
     not ok            -> send auth.challenge_response();          log auth_fail; close
3  filter.check(host, port, path, method)
     not allowed       -> send filter.forbidden_response(d); log req_blocked;
                          stats requests_blocked; close       (no upstream connect yet)
4  resolve host -> addresses; for each: filter.check_ip(ip, port);
     connect only to an allowed address; none allowed -> 403
```

### B7. Tests you must write

Use `pytest`. Plain functions or `unittest.TestCase` both work. Use `random.Random(seed)` for any randomness so failures reproduce. Target: **at least 50 cases**, coverage of `proxy.control` at least 70 percent.

| Group | Cases | Must cover |
| --- | --- | --- |
| Filter: domains | 12 | exact, case-insensitive, trailing dot, wildcard subdomain, wildcard does not match apex, suffix trap `evilexample.com`, deep subdomain, denylist mode, allowlist mode allow and block, precedence order, unknown mode rejected at load |
| Filter: ports and URL | 6 | blocked port, allowed-ports list, URL regex on plain HTTP, URL regex ignored when `path` is None, invalid regex rejected, catastrophic regex rejected |
| Filter: SSRF | 10 | 127.0.0.1, 10.x, 172.16.x, 192.168.x, 169.254.169.254, `::1`, `fc00::`, `::ffff:127.0.0.1`, `2130706433`, `0x7f000001`, `127.1`, `0177.0.0.1`, `localhost`, `a.localhost`, `private_allow` exception works, `check_ip` blocks resolved private IP, public IP allowed |
| Filter: bad input | 5 | empty host, spaces, NUL, 300-character host, IDNA host; none raise |
| Auth | 14 | valid login, wrong password, unknown user, missing header, Bearer scheme, bad base64, no colon, colon inside password, non-ASCII password, oversized header, lower-case `basic`, lockout after N, success resets counter, lockout expires (fake clock), per-IP isolation, failures never cached, dummy hash runs for unknown user, disabled auth passes, reply headers and `Content-Length` are exact |
| Config | 10 | defaults, file load, dotted `get`, command-line override, `--set`, invalid port lists all errors, unknown key warns, reload success, reload failure keeps old and sets `last_error`, `as_dict(redact=True)` hides hashes and salts, reads during reload never see partial state |
| Responses | 3 | 403 body is HTML-escaped, `Content-Length` matches, 407 and 429 are well-formed |
| Fuzz | 1 | 10,000 random hostnames including garbage bytes and long strings through `check`: never raises, always returns a `Decision`, whole run under 5 seconds |

### B8. Phases and exit gates

| Phase | Weeks | You deliver | Exit gate (you run these) |
| --- | --- | --- | --- |
| 1. Foundations | 1 to 2 | Config loader, filter engine, auth verifier, responses, `mkuser`, config files, first 30 tests | `python -m pytest tests/unit/control` all green with no proxy running |
| 2. Features | 3 to 5 | Lockout, credential cache, hot reload, `install_sighup`, regex safety, fuzz test, `docs/rules-syntax.md`, 50 tests, 70 percent coverage | `python -m pytest tests/unit/control --cov=proxy.control --cov-fail-under=70` |
| 3. Integration | 6 to 7 | Merge second (after Abdur Rehman). Run your integration rows against the real proxy. Bug-bash Abdur Rehman's code. Cross-teach your module | Your rows in `tests/integration/test_it_control.py` green |
| 4. UI and demo | 8 | `ui/panels/rules.js` and `ui/panels/auth.js`, README rules section, demo rehearsal | Panels load in the dashboard and show live data |

#### Integration rows you own (Phase 3)

| Test | Pass condition |
| --- | --- |
| HTTP blocked | Client gets 403. `req_blocked` is in the log. `requests_blocked` went up. |
| CONNECT blocked | Client gets 403 **before any upstream connection**. Confirm with the origin's `/__stats` connection counter, which must not change. |
| No credentials | Client gets 407 with `Proxy-Authenticate`. |
| Bad credentials | 407 and an `auth_fail` event. After `max_failures` the client gets 429 with `Retry-After`. |
| Good credentials | Request succeeds and the counter for that IP resets. |
| Reload | `POST /reload` after editing rules changes behaviour with no restart. Invalid edit keeps the old rules. |

### B9. Dashboard panels (Phase 4)

- **`rules.js`:** show mode, deny and allow lists, blocked ports, SSRF flag (from `GET /rules`). Add a **block-test box**: host, port, path, method fields and a Test button that calls `POST /rules/test` and shows allowed or blocked with the rule id. Rule **editing** is OPTIONAL and off by default.
- **`auth.js`:** show whether auth is enabled and the failed-login list from `GET /auth/failures`. Show lockout status where the data allows.
- Follow A6.7 exactly, including the XSS rule.

### B10. Do not

- Open sockets, resolve DNS, read files other than the config, or print anything.
- Use third-party packages.
- Log or return passwords, hashes or salts. Not even in error messages.
- Edit `proxy/core/`, `proxy/obs/`, `tools/` or anyone's tests.
- Change the contract. Ask your human to raise it.
"""proxy/__main__.py -- starts the proxy: builds every module and wires them together.

Run:  python -m proxy --stubs --port 8080      (Phases 1-2: fake teammates)
      python -m proxy --config configs/config.dev.json   (real modules)
"""
import argparse
import signal
import sys

from .core import ProxyServer
from .stubs import AllowAllFilter, DictConfig, MemoryStats, NoAuth, NullLogger

STUB_DEFAULTS = {
    "proxy": {"host": "127.0.0.1", "port": 8080, "max_threads": 100, "backlog": 128,
              "connect_timeout": 10, "read_timeout": 30, "idle_timeout": 60,
              "max_header_bytes": 16384},
    "admin": {"host": "127.0.0.1", "port": 8081},
}


def _stub_parts(port):
    """Fake teammates, so the core can run alone."""
    data = {k: dict(v) for k, v in STUB_DEFAULTS.items()}
    if port is not None:
        data["proxy"]["port"] = port
    return DictConfig(data), AllowAllFilter(), NoAuth(), NullLogger(), MemoryStats()


def _real_parts(argv):
    """Real modules from Sufyan and Abdur. Returns (config, flt, auth, logger, stats, admin_fn)."""
    from .control import build_auth, build_filter
    from .control.config import ConfigError, install_sighup, load_config
    from .obs import build_logger, build_stats, start_admin
    try:
        config = load_config(argv)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        raise SystemExit(2)
    install_sighup(config)
    stats = build_stats()
    logger = build_logger(config, stats)
    flt, auth = build_filter(config), build_auth(config)
    return config, flt, auth, logger, stats, start_admin


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="proxy", add_help=False)
    parser.add_argument("--stubs", action="store_true")
    parser.add_argument("--port", type=int, default=None)
    args, _ = parser.parse_known_args(argv)

    admin_fn = None
    if args.stubs:
        config, flt, auth, logger, stats = _stub_parts(args.port)
    else:
        config, flt, auth, logger, stats, admin_fn = _real_parts(argv)

    server = ProxyServer(config, flt, auth, logger, stats)
    admin = None
    if admin_fn is not None:
        admin = admin_fn(config, stats, logger, flt, auth, server.active_tunnels)

    def _stop(_signum, _frame):
        server.shutdown()

    signal.signal(signal.SIGINT, _stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _stop)

    print(f"proxy listening on {config.get('proxy.host')}:{server.port}", flush=True)
    try:
        server.serve_forever()
    finally:
        if admin is not None:
            admin.stop()
        if hasattr(logger, "close"):
            logger.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
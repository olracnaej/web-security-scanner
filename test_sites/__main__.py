"""python -m test_sites bare | leaky | wordpress | all"""

from __future__ import annotations

import argparse
import threading
import time

from test_sites.server import HOST, make_server
from test_sites.sites import SITES

BANNER = "Intentionally insecure FAKE sites, listening on 127.0.0.1 only. Press Ctrl+C to stop."


def main() -> int:
    parser = argparse.ArgumentParser(prog="test_sites", description=BANNER)
    parser.add_argument("site", choices=[*SITES, "all"])
    args = parser.parse_args()
    names = list(SITES) if args.site == "all" else [args.site]

    servers = []
    try:
        for name in names:
            servers.append(make_server(name))
    except OSError as exc:
        for server in servers:
            server.server_close()
        print(f"Could not start (is something already using that port?): {exc}")
        return 1

    print(BANNER)
    for name, server in zip(names, servers):
        site = SITES[name]
        print(f"  {name:<10} http://{HOST}:{site.port}   {site.summary}")
    print()

    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping.")
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

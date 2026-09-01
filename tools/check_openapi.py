#!/usr/bin/env python3
"""Fail if docs/openapi.yaml and the server's route table disagree.

The published contract is hand-written and is not served by the running
service, so nothing stops it drifting from the code except this. It compares
the two in both directions -- a route with no documented path, and a
documented path with no route -- and checks that each operation's security
matches whether the router demands an API key.

Needs PyYAML, which is a development dependency only: the service itself
never parses the spec, so its runtime stays free of a YAML parser.

Run it from the repository root: ``python3 tools/check_openapi.py``
"""
import pathlib
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ccd.server import ROUTES  # noqa: E402  (needs the path set up first)

SPEC_PATH = ROOT / "docs" / "openapi.yaml"
HTTP_METHODS = ("get", "put", "post", "delete", "patch", "options", "head", "trace")


def main() -> int:
    spec = yaml.safe_load(SPEC_PATH.read_text())

    documented = {}
    for path, item in spec.get("paths", {}).items():
        for method, operation in item.items():
            if method.lower() in HTTP_METHODS:
                documented[(method.upper(), path)] = operation

    implemented = {(r.method, r.template): r for r in ROUTES}

    problems = []

    for key in sorted(implemented.keys() - documented.keys()):
        problems.append(
            f"route {key[0]} {key[1]} is served but missing from docs/openapi.yaml"
        )
    for key in sorted(documented.keys() - implemented.keys()):
        problems.append(
            f"docs/openapi.yaml documents {key[0]} {key[1]}, which no route serves"
        )

    global_security = spec.get("security", [])
    for key, route in sorted(implemented.items()):
        operation = documented.get(key)
        if operation is None:
            continue
        security = operation.get("security", global_security)
        secured = any("bearerAuth" in entry for entry in security)
        if route.auth and not secured:
            problems.append(
                f"{key[0]} {key[1]} needs an API key but docs/openapi.yaml marks it public"
            )
        if not route.auth and secured:
            problems.append(
                f"{key[0]} {key[1]} is public but docs/openapi.yaml requires bearerAuth "
                '(set "security": [] on the operation)'
            )

    if problems:
        print("docs/openapi.yaml is out of sync with ccd/server.py ROUTES:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    print(f"docs/openapi.yaml matches all {len(implemented)} routes")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""The HTTP surface: a regex router over ``http.server``.

Deliberately dependency-free. The service answers a handful of requests per
day from other applications on the same host, so a threaded stdlib server is
the whole of what is warranted -- no WSGI server, no framework, one process.

Every route is declared once in ``ROUTES`` and nothing is dispatched outside
it. ``tools/check_openapi.py`` reads that table and fails CI if it and
``docs/openapi.yaml`` disagree, which is what keeps the published contract
honest. The spec is documentation, not a runtime artifact: it is not shipped
in the image and there is no endpoint serving it.
"""
import hmac
import json
import re
import signal
import sys
import threading
import urllib.parse
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, NamedTuple, Tuple

from . import client_config, service
from .errors import CcdError

# Set once by serve(); read only to build outbound URLs, never to route.
_PORT = 0


class Response(NamedTuple):
    status: int
    body: bytes
    content_type: str = "application/json; charset=utf-8"
    headers: Tuple[Tuple[str, str], ...] = ()


class Request(NamedTuple):
    method: str
    path: str
    query: Dict[str, List[str]]
    body: bytes

    def json_body(self) -> Dict[str, Any]:
        if not self.body:
            return {}
        try:
            data = json.loads(self.body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise CcdError(f"Request body is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise CcdError("Request body must be a JSON object.")
        return data

    def first(self, name: str, default: str = "") -> str:
        values = self.query.get(name) or []
        return values[0] if values else default


class Route(NamedTuple):
    method: str
    template: str
    pattern: Any
    handler: Callable[[Request, Dict[str, str]], Response]
    auth: bool


def _compile(template: str):
    """Turn ``/api/accounts/{provider}/{email}`` into an anchored regex."""
    parts = []
    for chunk in re.split(r"(\{[a-z_]+\})", template):
        if chunk.startswith("{") and chunk.endswith("}"):
            parts.append(f"(?P<{chunk[1:-1]}>[^/]+)")
        else:
            parts.append(re.escape(chunk))
    return re.compile("^" + "".join(parts) + "$")


def _json(payload: Any, status: int = 200) -> Response:
    return Response(status, json.dumps(payload, indent=2).encode("utf-8") + b"\n")


# --------------------------------------------------------------------------- #
# Handlers
# --------------------------------------------------------------------------- #

def h_health(req: Request, params: Dict[str, str]) -> Response:
    return _json({"status": "ok"})


def h_login_start(req: Request, params: Dict[str, str]) -> Response:
    provider = str(req.json_body().get("provider", "")).strip()
    if not provider:
        raise CcdError("Missing 'provider' in request body (google or microsoft).")
    return _json(service.start_login(provider, _PORT), 201)


def h_login_status(req: Request, params: Dict[str, str]) -> Response:
    return _json(service.login_status(params["login_id"]))


def h_accounts(req: Request, params: Dict[str, str]) -> Response:
    return _json(service.list_accounts(_PORT))


def _email(params: Dict[str, str]) -> str:
    return urllib.parse.unquote(params["email"])


def h_account(req: Request, params: Dict[str, str]) -> Response:
    return _json(service.get_account(params["provider"], _email(params), _PORT))


def h_account_status(req: Request, params: Dict[str, str]) -> Response:
    return _json(service.account_status(params["provider"], _email(params), _PORT))


def h_rotate_token(req: Request, params: Dict[str, str]) -> Response:
    return _json(service.rotate_token(params["provider"], _email(params), _PORT))


def h_account_delete(req: Request, params: Dict[str, str]) -> Response:
    revoke = req.first("revoke", "false").lower() in ("1", "true", "yes")
    return _json(service.logout(params["provider"], _email(params), revoke))


def h_oauth_callback(req: Request, params: Dict[str, str]) -> Response:
    result = service.complete_google_callback(
        req.first("state"), req.first("code"), req.first("error")
    )
    status = 200 if result["ok"] else 400
    return Response(status, _callback_page(result), "text/html; charset=utf-8")


def h_download(req: Request, params: Dict[str, str], artifact: str = "") -> Response:
    body, content_type, filename = service.download(params["download_token"], artifact)
    disposition = 'attachment; filename="{0}"'.format(filename.replace('"', ""))
    return Response(
        200,
        body.encode("utf-8"),
        content_type,
        (("Content-Disposition", disposition), ("Cache-Control", "no-store")),
    )


def _callback_page(result: Dict[str, Any]) -> bytes:
    from html import escape

    title = "Account linked" if result["ok"] else "Sign-in failed"
    colour = "#1a7f37" if result["ok"] else "#b3261e"
    return (
        "<!doctype html><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        f"<title>{title}</title>"
        "<style>body{font:16px/1.5 system-ui,sans-serif;margin:4rem auto;max-width:34rem;"
        "padding:0 1rem}h1{font-size:1.3rem}</style>"
        f"<h1 style=\"color:{colour}\">{title}</h1>"
        f"<p>{escape(result['message'])}</p>"
        "<p>You can close this tab.</p>"
    ).encode("utf-8")


# --------------------------------------------------------------------------- #
# Route table -- the single source of truth the OpenAPI check validates against
# --------------------------------------------------------------------------- #

def _route(method: str, template: str, handler, auth: bool = True) -> Route:
    return Route(method, template, _compile(template), handler, auth)


ROUTES: Tuple[Route, ...] = (
    _route("GET", "/healthz", h_health, auth=False),
    _route("GET", "/oauth/callback", h_oauth_callback, auth=False),
    _route("GET", "/d/{download_token}/contacts.csv",
           partial(h_download, artifact="contacts.csv"), auth=False),
    _route("GET", "/d/{download_token}/contacts.json",
           partial(h_download, artifact="contacts.json"), auth=False),
    _route("GET", "/d/{download_token}/calendar.ics",
           partial(h_download, artifact="calendar.ics"), auth=False),
    _route("POST", "/api/login", h_login_start),
    _route("GET", "/api/login/{login_id}", h_login_status),
    _route("GET", "/api/accounts", h_accounts),
    _route("GET", "/api/accounts/{provider}/{email}", h_account),
    _route("GET", "/api/accounts/{provider}/{email}/status", h_account_status),
    _route("POST", "/api/accounts/{provider}/{email}/rotate-token", h_rotate_token),
    _route("DELETE", "/api/accounts/{provider}/{email}", h_account_delete),
)


# --------------------------------------------------------------------------- #
# Request handling
# --------------------------------------------------------------------------- #

class Handler(BaseHTTPRequestHandler):
    server_version = "ccd"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    api_key = ""

    def do_GET(self):  # noqa: N802 - name fixed by BaseHTTPRequestHandler
        self._dispatch("GET")

    def do_POST(self):  # noqa: N802
        self._dispatch("POST")

    def do_DELETE(self):  # noqa: N802
        self._dispatch("DELETE")

    # -- routing ---------------------------------------------------------- #

    def _dispatch(self, method: str) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        query = urllib.parse.parse_qs(parsed.query)

        matched_path = False
        for route in ROUTES:
            match = route.pattern.match(path)
            if not match:
                continue
            matched_path = True
            if route.method != method:
                continue
            self._run(route, Request(method, path, query, self._read_body()), match.groupdict())
            return

        if matched_path:
            self._send(_json({"error": f"{method} is not allowed here.", "code": "error"}, 405))
        else:
            self._send(_json({"error": "Not found.", "code": "no_accounts"}, 404))

    def _run(self, route: Route, req: Request, params: Dict[str, str]) -> None:
        if route.auth and not self._authorized():
            self._send(
                Response(
                    401,
                    json.dumps({"error": "Missing or invalid API key.", "code": "error"}).encode() + b"\n",
                    headers=(("WWW-Authenticate", 'Bearer realm="ccd"'),),
                )
            )
            return
        try:
            self._send(route.handler(req, params))
        except CcdError as exc:
            self._send(_json({"error": str(exc), "code": exc.wire_code}, exc.http_status))
        except Exception as exc:  # noqa: BLE001 - one bad request must not kill the server
            print(f"error: unhandled {type(exc).__name__}: {exc}", file=sys.stderr)
            self._send(_json({"error": "Internal server error.", "code": "internal"}, 500))

    def _authorized(self) -> bool:
        header = self.headers.get("Authorization", "")
        scheme, _, presented = header.partition(" ")
        if scheme.lower() != "bearer" or not presented:
            return False
        return hmac.compare_digest(presented.strip(), self.api_key)

    def _read_body(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return b""
        # A request body here is only ever a tiny JSON object.
        return self.rfile.read(min(length, 1 << 20)) if length > 0 else b""

    def _send(self, response: Response) -> None:
        self.send_response(response.status)
        self.send_header("Content-Type", response.content_type)
        self.send_header("Content-Length", str(len(response.body)))
        for name, value in response.headers:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(response.body)

    # -- logging ----------------------------------------------------------- #

    def log_message(self, fmt: str, *args: Any) -> None:
        """Log to stderr with download tokens stripped.

        A ``/d/<token>/...`` path *is* the credential for that account, so it
        must never reach the journal, where it would outlive any rotation.
        """
        message = fmt % args
        message = re.sub(r"/d/[^/\s]+/", "/d/<token>/", message)
        print(f"{self.address_string()} {message}", file=sys.stderr)


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def serve(listen: str = "") -> int:
    """Run the service until interrupted."""
    global _PORT

    host, port = client_config.listen_address(listen)
    _PORT = port

    api_key, created = client_config.ensure_api_key()
    Handler.api_key = api_key

    base = client_config.base_url(port)
    try:
        httpd = ThreadingHTTPServer((host, port), Handler)
    except OSError as exc:
        raise CcdError(f"Cannot listen on {host}:{port}: {exc}") from exc
    httpd.daemon_threads = True

    # As PID 1 in a container, a process receives no default signal
    # disposition: without this handler SIGTERM is discarded and the runtime
    # waits out its stop timeout before SIGKILLing us. shutdown() has to run
    # off the serving thread, or it deadlocks against serve_forever().
    def _stop(signum, frame):
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _stop)

    print(f"ccd listening on http://{host}:{port}", file=sys.stderr)
    print(f"base URL: {base}", file=sys.stderr)
    print(f"Google redirect URI (register this): {client_config.redirect_uri(port)}", file=sys.stderr)
    if created:
        print(f"generated API key: {api_key}", file=sys.stderr)
    if not base.startswith("https://") and not _is_loopback(base):
        print(
            "warning: CCD_BASE_URL is not https. OAuth authorization codes and "
            "per-account download tokens travel over this URL -- put TLS in front of it.",
            file=sys.stderr,
        )

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("", file=sys.stderr)
    finally:
        httpd.server_close()
    return 0


def _is_loopback(base: str) -> bool:
    hostname = urllib.parse.urlparse(base).hostname or ""
    return hostname in ("localhost", "127.0.0.1", "::1")

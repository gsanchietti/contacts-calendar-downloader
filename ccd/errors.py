"""Exception types shared by the CLI, the service and the HTTP layer.

Each class fixes two things at once: the process exit code the CLI returns
for it, and the HTTP status plus machine-readable ``code`` the server sends
for it. Keeping both on the class is what lets the CLI -- now a plain HTTP
client -- map a JSON error body back to exactly the exit code the local
implementation used to return.
"""


class CcdError(Exception):
    """Base class for expected, user-facing failures."""

    exit_code = 1
    http_status = 400
    wire_code = "error"


class NoAccountsError(CcdError):
    """No account is linked, or the requested one is not linked."""

    exit_code = 2
    http_status = 404
    wire_code = "no_accounts"


class AuthExpiredError(CcdError):
    """Stored credentials can no longer be refreshed; the user must log in again."""

    exit_code = 3
    http_status = 409
    wire_code = "auth_expired"


class ProviderApiError(CcdError):
    """The provider's API rejected or failed a data request."""

    exit_code = 4
    http_status = 502
    wire_code = "provider_api"


# Wire code -> exception class, for the CLI to rebuild a server-side error.
BY_WIRE_CODE = {
    cls.wire_code: cls
    for cls in (CcdError, NoAccountsError, AuthExpiredError, ProviderApiError)
}


def from_wire(code, message):
    """Rebuild the local exception a server-sent error ``code`` stands for."""
    return BY_WIRE_CODE.get(code, CcdError)(message)

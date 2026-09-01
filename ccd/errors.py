"""Exception types shared by the CLI, mapped to process exit codes."""


class CcdError(Exception):
    """Base class for expected, user-facing failures."""

    exit_code = 1


class NoAccountsError(CcdError):
    """No account is linked, or the requested one is not linked."""

    exit_code = 2


class AuthExpiredError(CcdError):
    """Stored credentials can no longer be refreshed; the user must log in again."""

    exit_code = 3


class ProviderApiError(CcdError):
    """The provider's API rejected or failed a data request."""

    exit_code = 4

"""Infrastructure layer exceptions."""


class InfrastructureError(Exception):
    """Base infrastructure error."""
    pass


class DatabaseError(InfrastructureError):
    """Database operation error."""
    pass


class ConnectionError(DatabaseError):
    """Database connection error."""
    pass


class FilesystemError(InfrastructureError):
    """Filesystem operation error."""
    pass


class PathSecurityError(FilesystemError):
    """Path security violation."""
    pass


class HTTPError(InfrastructureError):
    """HTTP operation error."""
    pass


class ParseError(HTTPError):
    """Request parsing error."""
    pass
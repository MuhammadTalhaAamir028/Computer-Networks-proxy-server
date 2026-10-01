"""proxy/core/errors.py -- error types and the plain-text error replies we send to clients.

Every error reply is short, complete, has an exact Content-Length and closes the connection.
Only send one if no response byte has reached the client yet.
"""

REASONS = {
    400: "Bad Request",
    403: "Forbidden",
    408: "Request Timeout",
    500: "Internal Server Error",
    501: "Not Implemented",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
}


class HttpError(Exception):
    """Any failure that maps to an HTTP status reply.

    status  = code we reply with
    message = short reason shown to the client (never contains secrets)
    """

    def __init__(self, status: int = 500, message: str = ""):
        super().__init__(message or REASONS.get(status, "Error"))
        self.status = status
        self.message = message or REASONS.get(status, "Error")


def build_error(status: int, message: str = "", retry_after: int = 0) -> bytes:
    """Build a complete error response (status line, headers, body)."""
    reason = REASONS.get(status, "Error")
    body = ((message or reason) + "\n").encode("ascii", "replace")
    head = [f"HTTP/1.1 {status} {reason}",
            "Content-Type: text/plain; charset=utf-8",
            f"Content-Length: {len(body)}",
            "Connection: close"]
    if retry_after:
        head.append(f"Retry-After: {retry_after}")
    return ("\r\n".join(head) + "\r\n\r\n").encode("ascii") + body
from ..runtime import RequestSession, SessionOptions
from ..errors import RedirectSignal


class AuthwaveWSGI:
    """Expose Authenticator as environ['authwave.auth']; save before output."""

    def __init__(self, app, session_options: SessionOptions, **auth_options):
        self.app, self.session_options, self.auth_options = (
            app,
            session_options,
            auth_options,
        )

    def __call__(self, environ, start_response):
        context = RequestSession(environ.get("HTTP_COOKIE", ""), self.session_options)
        path = environ.get("SCRIPT_NAME", "") + environ.get("PATH_INFO", "/")
        if environ.get("QUERY_STRING"):
            path += "?" + environ["QUERY_STRING"]
        result = {}
        body = []

        def capture(status, headers, exc_info=None):
            result.update(status=status, headers=headers, exc_info=exc_info)
            return body.append

        try:
            try:
                environ["authwave.auth"] = context.authenticator(
                    path, self.auth_options
                )
                iterable = self.app(environ, capture)
                try:
                    for chunk in iterable:
                        body.append(chunk)
                finally:
                    close = getattr(iterable, "close", None)
                    if close:
                        close()
            except RedirectSignal as redirect:
                result = {
                    "status": f"{redirect.code} See Other",
                    "headers": [("Location", redirect.uri)],
                }
                body = [b""]
        finally:
            context.commit()
        headers = [(k, v) for k, v in result["headers"] if k.lower() != "cache-control"]
        headers.extend(
            [("Set-Cookie", context.cookie()), ("Cache-Control", "no-store")]
        )
        start_response(result["status"], headers, result.get("exc_info"))
        return body

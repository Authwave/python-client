from functools import wraps
from ..runtime import RequestSession, SessionOptions
from ..errors import RedirectSignal


def authwave_handler(session_options: SessionOptions, **auth_options):
    """Decorate every login, logout and callback view; inject auth as first argument."""

    def decorate(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            from flask import request, make_response, redirect

            context = RequestSession(request.headers.get("Cookie", ""), session_options)
            try:
                try:
                    path = request.path + (
                        "?" + request.query_string.decode("ascii")
                        if request.query_string
                        else ""
                    )
                    auth = context.authenticator(path, auth_options)
                    response = make_response(view(auth, *args, **kwargs))
                except RedirectSignal as signal:
                    response = redirect(signal.uri, code=signal.code)
            finally:
                context.commit()
            response.headers.add("Set-Cookie", context.cookie())
            response.headers["Cache-Control"] = "no-store"
            return response

        return wrapped

    return decorate

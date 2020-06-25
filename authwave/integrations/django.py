from functools import wraps
from ..runtime import RequestSession, SessionOptions
from ..errors import RedirectSignal


def authwave_handler(session_options: SessionOptions, **auth_options):
    """Decorate a synchronous view; exposes request.authwave."""

    def decorate(view):
        @wraps(view)
        def wrapped(request, *args, **kwargs):
            from django.http import HttpResponse

            context = RequestSession(
                request.META.get("HTTP_COOKIE", ""), session_options
            )
            try:
                try:
                    request.authwave = context.authenticator(
                        request.get_full_path(), auth_options
                    )
                    response = view(request, *args, **kwargs)
                except RedirectSignal as signal:
                    response = HttpResponse(status=signal.code)
                    response["Location"] = signal.uri
            finally:
                context.commit()
            # Django manages the response cookie collection separately.
            response.set_cookie(
                session_options.cookie_name,
                context.id,
                max_age=session_options.ttl_seconds,
                secure=session_options.secure_cookie,
                httponly=True,
                samesite="Lax",
            )
            response["Cache-Control"] = "no-store"
            return response

        return wrapped

    return decorate

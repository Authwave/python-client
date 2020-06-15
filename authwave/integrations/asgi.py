import asyncio
from ..runtime import RequestSession, SessionOptions
from ..errors import RedirectSignal


class AuthwaveASGI:
    """Expose Authenticator as request.state.authwave; HTTP responses are buffered."""

    def __init__(self, app, session_options: SessionOptions, **auth_options):
        self.app, self.session_options, self.auth_options = (
            app,
            session_options,
            auth_options,
        )

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        cookies = "; ".join(
            v.decode("latin1")
            for k, v in scope.get("headers", [])
            if k.lower() == b"cookie"
        )
        context = await asyncio.to_thread(RequestSession, cookies, self.session_options)
        path = scope.get("root_path", "") + scope["path"]
        if scope.get("query_string"):
            path += "?" + scope["query_string"].decode("ascii")
        messages = []

        async def capture(message):
            messages.append(dict(message))

        try:
            try:
                auth = await asyncio.to_thread(
                    context.authenticator, path, self.auth_options
                )
                scope.setdefault("state", {})["authwave"] = auth
                await self.app(scope, receive, capture)
            except RedirectSignal as redirect:
                messages = [
                    {
                        "type": "http.response.start",
                        "status": redirect.code,
                        "headers": [(b"location", redirect.uri.encode("ascii"))],
                    },
                    {"type": "http.response.body", "body": b""},
                ]
        finally:
            await asyncio.to_thread(context.commit)
        for message in messages:
            if message["type"] == "http.response.start":
                headers = [
                    (k, v)
                    for k, v in message.get("headers", [])
                    if k.lower() != b"cache-control"
                ]
                message["headers"] = headers + [
                    (b"set-cookie", context.cookie().encode("ascii")),
                    (b"cache-control", b"no-store"),
                ]
            await send(message)

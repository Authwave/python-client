# Authwave Python client

Connect Python applications to an [Authwave provider](https://github.com/Authwave/provider). Supports Flask, Django, FastAPI, WSGI and ASGI with server-side sessions and encrypted authentication exchanges.

```bash
pip install 'authwave[flask]'
```

```python
from authwave.integrations.flask import authwave_handler
from authwave.runtime import MemorySessionStore, SessionOptions

options = SessionOptions(MemorySessionStore(), secure_cookie=False)  # Local HTTP.

@app.route('/login')
@authwave_handler(options, client_key=client_key)
def login(auth):
    auth.set_return_uri('/')
    auth.login()
```

Wrap the return route too. It can read `auth.is_logged_in()` and `auth.get_auth_user().id` / `.email`. The full [examples](examples) include login, logout and callback handling. See the [wiki](https://github.com/Authwave/python-client/wiki) for setup and the API reference.

A token can encrypt only its first complete request. Repeating the same request is allowed; a different payload raises TokenReuseException. Create a fresh token for a different action or return query, and do not copy tokens or reuse supplied IVs. Session serialisation retains the binding. Tokens restored from older sessions without a binding can still decrypt responses, but require a fresh token to start another request.

The complete provider-issued key belongs on the server. The final underscore separates the deployment identifier from the raw 32-byte secret. `authwave_host` defaults to `login.authwave.com`.

`MemorySessionStore` is for development. Production applications need a shared persistent `SessionStore` and HTTPS; cookies are Secure by default. Authentication data stays in server-side storage; never put serialized tokens in browser cookies. Authentication callbacks are synchronous and run at most once per exchange under sequential session processing.

## Development

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
pytest
python -m build
```

Tests include 68 deterministic PHP-reference scenarios and complete framework login/logout flows using simulated provider responses. To also execute the PHP source and check the fixtures, set `AUTHWAVE_PHP_REFERENCE` to the PHP checkout with installed Composer dependencies.

[PARITY.md](PARITY.md) maps the PHP API to its Python equivalents.

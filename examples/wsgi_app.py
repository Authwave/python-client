import json
import os
from wsgiref.simple_server import make_server
from authwave.integrations.wsgi import AuthwaveWSGI
from authwave.runtime import MemorySessionStore, SessionOptions


def application(environ, start_response):
    auth = environ["authwave.auth"]
    if environ["PATH_INFO"] == "/login":
        auth.set_return_uri("/")
        auth.login()
    if environ["PATH_INFO"] == "/logout":
        auth.logout("/")
    result = (
        {"id": auth.get_auth_user().id, "email": auth.get_auth_user().email}
        if auth.is_logged_in()
        else {"login": "/login"}
    )
    start_response("200 OK", [("Content-Type", "application/json")])
    return [json.dumps(result).encode()]


app = AuthwaveWSGI(
    application,
    SessionOptions(MemorySessionStore(), secure_cookie=False),
    client_key=os.environ["AUTHWAVE_CLIENT_KEY"],
)
if __name__ == "__main__":
    make_server("127.0.0.1", 3000, app).serve_forever()

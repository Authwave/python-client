import os
from flask import Flask, request
from authwave.integrations.flask import authwave_handler
from authwave.runtime import MemorySessionStore, SessionOptions

app = Flask(__name__)
options = SessionOptions(MemorySessionStore(), secure_cookie=False)  # Local HTTP only.


@app.route("/")
@app.route("/login")
@app.route("/logout")
@authwave_handler(options, client_key=os.environ["AUTHWAVE_CLIENT_KEY"])
def index(auth):
    if request.path == "/login":
        auth.set_return_uri("/")
        auth.login()
    if request.path == "/logout":
        auth.logout("/")
    return (
        {"id": auth.get_auth_user().id, "email": auth.get_auth_user().email}
        if auth.is_logged_in()
        else {"login": "/login"}
    )


if __name__ == "__main__":
    app.run(port=3000)

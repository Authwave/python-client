import os
from fastapi import FastAPI, Request
from authwave.integrations.fastapi import AuthwaveMiddleware
from authwave.runtime import MemorySessionStore, SessionOptions

app = FastAPI()
app.add_middleware(
    AuthwaveMiddleware,
    session_options=SessionOptions(MemorySessionStore(), secure_cookie=False),
    client_key=os.environ["AUTHWAVE_CLIENT_KEY"],
)


@app.get("/")
@app.get("/login")
@app.get("/logout")
def index(request: Request):
    auth = request.state.authwave
    if request.url.path == "/login":
        auth.set_return_uri("/")
        auth.login()
    if request.url.path == "/logout":
        auth.logout("/")
    return (
        {"id": auth.get_auth_user().id, "email": auth.get_auth_user().email}
        if auth.is_logged_in()
        else {"login": "/login"}
    )

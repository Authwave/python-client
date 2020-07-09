import os
from django.conf import settings
from django.http import JsonResponse
from django.urls import path
from authwave.integrations.django import authwave_handler
from authwave.runtime import MemorySessionStore, SessionOptions

if not settings.configured:
    settings.configure(
        ROOT_URLCONF=__name__,
        ALLOWED_HOSTS=["localhost", "127.0.0.1"],
        DEBUG=True,
        SECRET_KEY=os.environ.get("DJANGO_SECRET_KEY", "local-development-only"),
    )
options = SessionOptions(MemorySessionStore(), secure_cookie=False)


@authwave_handler(options, client_key=os.environ["AUTHWAVE_CLIENT_KEY"])
def index(request):
    auth = request.authwave
    if request.path == "/login":
        auth.set_return_uri("/")
        auth.login()
    if request.path == "/logout":
        auth.logout("/")
    return JsonResponse(
        {"id": auth.get_auth_user().id, "email": auth.get_auth_user().email}
        if auth.is_logged_in()
        else {"login": "/login"}
    )


urlpatterns = [path("", index), path("login", index), path("logout", index)]

if __name__ == "__main__":
    from django.core.wsgi import get_wsgi_application
    from wsgiref.simple_server import make_server

    make_server("127.0.0.1", 3000, get_wsgi_application()).serve_forever()

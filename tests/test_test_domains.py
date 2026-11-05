import pytest
from authwave import AdminUri, InsecureProtocolException


@pytest.mark.parametrize(
    "host,allowed",
    [
        ("http://login.realtest.authwave.test:9090", True),
        ("http://app.test", True),
        ("http://LOGIN.EXAMPLE.TEST:9090", True),
        ("http://login.example.test.:9090", True),
        ("http://localhost:9090", True),
        ("http://127.0.0.127:9090", True),
        ("https://login.authwave.com", True),
        ("http://login.realtest.authwave-test:9090", False),
        ("http://example.test.attacker.com", False),
        ("http://exampletest", False),
        ("http://test", False),
        ("http://login.authwave.com", False),
        ("ftp://example.test", False),
    ],
)
def test_provider_protocol_policy(host, allowed):
    if not allowed:
        with pytest.raises(InsecureProtocolException):
            AdminUri(host)
        return
    uri = AdminUri(host)
    assert uri.get_path() == "/admin/"
    if host.startswith("http://"):
        assert uri.get_scheme() == "http"
    if ":9090" in host:
        assert uri.get_port() == 9090

"""Unit tests for HTTP security assessment."""

import ipaddress
import socket
import ssl

import httpcore
import httpx
import pytest

from domasentrix.checks import http as http_module
from domasentrix.checks.http import audit_http
from domasentrix.core.target import TargetValidationError

_SECURE_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
}


def _response(
    request: httpx.Request,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
    content: bytes = b"",
) -> httpx.Response:
    return httpx.Response(
        status_code,
        headers=headers,
        content=content,
        request=request,
    )


def _mock_http(
    monkeypatch: pytest.MonkeyPatch,
    handler,
) -> None:
    def create_client(timeout: float) -> httpx.Client:
        return httpx.Client(
            transport=httpx.MockTransport(handler),
            verify=True,
            follow_redirects=False,
            timeout=httpx.Timeout(timeout),
            trust_env=False,
        )

    monkeypatch.setattr(http_module, "_create_client", create_client)


def _codes(result) -> set[str]:
    return {finding.code for finding in result.findings}


def _address_info(address: str, port: int):
    ip_address = ipaddress.ip_address(address)
    if isinstance(ip_address, ipaddress.IPv6Address):
        family = socket.AF_INET6
        sockaddr = (address, port, 0, 0)
    else:
        family = socket.AF_INET
        sockaddr = (address, port)
    return family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr


class _BareSocket:
    def setsockopt(self, *args) -> None:
        return None

    def close(self) -> None:
        return None


class _HTTPResponseStream:
    def __init__(self, response: bytes) -> None:
        self._response = response
        self._offset = 0
        self.closed = False
        self.tls_server_name: str | None = None
        self.tls_context_verified = False
        self.request_bytes = b""

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        chunk = self._response[self._offset : self._offset + max_bytes]
        self._offset += len(chunk)
        return chunk

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self.request_bytes += buffer

    def close(self) -> None:
        self.closed = True

    def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> "_HTTPResponseStream":
        self.tls_server_name = server_hostname
        self.tls_context_verified = (
            ssl_context.check_hostname and ssl_context.verify_mode == ssl.CERT_REQUIRED
        )
        return self

    def get_extra_info(self, info: str):
        if info == "ssl_object" and self.tls_server_name is not None:
            return self
        return None

    def selected_alpn_protocol(self) -> None:
        return None


def test_audit_http_detects_https_redirect_and_availability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same-domain HTTP redirects to HTTPS should be followed and reported."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.scheme == "http":
            return _response(
                request,
                301,
                {"Location": "https://example.com/secure"},
            )
        return _response(request, headers=_SECURE_HEADERS)

    _mock_http(monkeypatch, handler)

    result = audit_http("example.com")

    assert result.http_to_https_redirect is True
    assert result.https_available is True
    assert result.http_response is not None
    assert result.http_response.status_code == 200
    assert result.http_response.url == "https://example.com/secure"
    assert result.http_response.redirect_count == 1
    assert result.https_response is not None
    assert result.https_response.status_code == 200
    assert "HTTP_HTTPS_REDIRECT_MISSING" not in _codes(result)
    assert result.errors == {}


def test_audit_http_reports_missing_https_redirect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An HTTP response that remains on HTTP should report missing enforcement."""
    _mock_http(
        monkeypatch,
        lambda request: _response(
            request,
            headers=_SECURE_HEADERS if request.url.scheme == "https" else None,
        ),
    )

    result = audit_http("example.com")

    assert result.http_to_https_redirect is False
    assert "HTTP_HTTPS_REDIRECT_MISSING" in _codes(result)


def test_audit_http_reports_missing_security_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing headers produce measured findings rather than critical alerts."""
    _mock_http(monkeypatch, lambda request: _response(request))

    result = audit_http("example.com")
    codes = _codes(result)

    assert {
        "HTTP_HSTS_MISSING",
        "HTTP_CSP_MISSING",
        "HTTP_X_CONTENT_TYPE_OPTIONS_MISSING",
        "HTTP_FRAME_PROTECTION_MISSING",
        "HTTP_REFERRER_POLICY_MISSING",
        "HTTP_PERMISSIONS_POLICY_MISSING",
    } <= codes
    assert all(finding.severity != "critical" for finding in result.findings)


def test_audit_http_accepts_configured_security_headers_and_csp_frames(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CSP frame-ancestors can replace X-Frame-Options."""
    headers = {
        key: value for key, value in _SECURE_HEADERS.items() if key != "X-Frame-Options"
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.scheme == "http":
            return _response(
                request,
                301,
                {"Location": "https://example.com/"},
            )
        return _response(request, headers=headers)

    _mock_http(
        monkeypatch,
        handler,
    )

    result = audit_http("example.com")

    assert result.findings == []


def test_audit_http_reports_weak_and_malformed_header_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Invalid directives and weak policy values should be visible."""
    headers = {
        "Strict-Transport-Security": "max-age=soon",
        "Content-Security-Policy": ("script-src * 'unsafe-inline'; frame-ancestors *"),
        "X-Content-Type-Options": "invalid",
        "X-Frame-Options": "ALLOW-FROM https://other.example",
        "Referrer-Policy": "unsafe-url",
        "Permissions-Policy": "geolocation",
    }
    _mock_http(
        monkeypatch,
        lambda request: _response(
            request,
            headers=headers if request.url.scheme == "https" else None,
        ),
    )

    result = audit_http("example.com")
    codes = _codes(result)

    assert "HTTP_HSTS_INVALID" in codes
    assert "HTTP_CSP_WEAK_POLICY" in codes
    assert "HTTP_FRAME_PROTECTION_INVALID" in codes
    assert "HTTP_X_CONTENT_TYPE_OPTIONS_INVALID" in codes
    assert "HTTP_REFERRER_POLICY_WEAK" in codes
    assert "HTTP_PERMISSIONS_POLICY_INVALID" in codes


def test_audit_http_assesses_hsts_only_on_https(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An HSTS header on plain HTTP must not satisfy the HTTPS check."""

    def handler(request: httpx.Request) -> httpx.Response:
        headers = (
            {"Strict-Transport-Security": "max-age=31536000"}
            if request.url.scheme == "http"
            else {}
        )
        return _response(request, headers=headers)

    _mock_http(monkeypatch, handler)

    result = audit_http("example.com")

    assert "HTTP_HSTS_MISSING" in _codes(result)


def test_audit_http_reports_disabled_hsts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A zero HSTS max-age is not treated as an enabled policy."""
    headers = {
        **_SECURE_HEADERS,
        "Strict-Transport-Security": "max-age=0",
    }
    _mock_http(
        monkeypatch,
        lambda request: _response(
            request,
            headers=headers if request.url.scheme == "https" else None,
        ),
    )

    result = audit_http("example.com")

    assert "HTTP_HSTS_DISABLED" in _codes(result)


def test_audit_http_handles_very_large_hsts_max_age(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A syntactically numeric HSTS value cannot crash integer parsing."""
    headers = {
        **_SECURE_HEADERS,
        "Strict-Transport-Security": "max-age=" + ("9" * 5000),
    }
    _mock_http(
        monkeypatch,
        lambda request: _response(
            request,
            headers=headers if request.url.scheme == "https" else None,
        ),
    )

    result = audit_http("example.com")

    assert "HTTP_HSTS_INVALID" not in _codes(result)
    assert "HTTP_HSTS_SHORT_MAX_AGE" not in _codes(result)


def test_audit_http_does_not_accept_wildcard_csp_frame_ancestors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A scheme-wide frame-ancestors source is not meaningful protection."""
    headers = {
        name: value
        for name, value in _SECURE_HEADERS.items()
        if name.casefold() not in {"content-security-policy", "x-frame-options"}
    }
    headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors https://*"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.scheme == "http":
            return _response(
                request,
                301,
                {"Location": "https://example.com/"},
            )
        return _response(request, headers=headers)

    _mock_http(monkeypatch, handler)

    result = audit_http("example.com")

    assert "HTTP_FRAME_PROTECTION_MISSING" in _codes(result)
    assert "HTTP_CSP_WEAK_POLICY" in _codes(result)


def test_audit_http_reports_server_technology_disclosure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Server and X-Powered-By values are recorded as low-severity findings."""
    headers = {"Server": "example-server/1.2", "X-Powered-By": "ExampleRuntime"}
    _mock_http(
        monkeypatch,
        lambda request: _response(request, headers=headers),
    )

    result = audit_http("example.com")
    disclosure_findings = [
        finding for finding in result.findings if "DISCLOSURE" in finding.code
    ]

    assert {finding.code for finding in disclosure_findings} == {
        "HTTP_SERVER_DISCLOSURE",
        "HTTP_X_POWERED_BY_DISCLOSURE",
    }
    assert all(finding.severity == "low" for finding in disclosure_findings)
    assert "example-server/1.2" in result.http_response.headers["server"]


def test_audit_http_detects_redirect_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    """A repeated same-domain redirect is stopped and reported."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.scheme == "http":
            return _response(request, 302, {"Location": "/"})
        return _response(request, headers=_SECURE_HEADERS)

    _mock_http(monkeypatch, handler)

    result = audit_http("example.com")

    assert "HTTP_REDIRECT_LOOP" in _codes(result)
    assert "http_redirect" in result.errors
    assert result.http_to_https_redirect is None
    assert "HTTP_HTTPS_REDIRECT_MISSING" not in _codes(result)


def test_audit_http_limits_redirect_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    """Redirects beyond the configured cap are not followed."""
    requested_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_paths.append(request.url.path)
        if request.url.scheme == "http":
            return _response(
                request,
                302,
                {"Location": f"/step-{len(requested_paths)}"},
            )
        return _response(request, headers=_SECURE_HEADERS)

    _mock_http(monkeypatch, handler)

    result = audit_http("example.com", max_redirects=1)

    assert "HTTP_REDIRECT_LIMIT_EXCEEDED" in _codes(result)
    assert "http_redirect" in result.errors
    assert result.http_to_https_redirect is None
    assert "HTTP_HTTPS_REDIRECT_MISSING" not in _codes(result)
    assert len([path for path in requested_paths if path.startswith("/step")]) == 1


def test_audit_http_records_https_redirect_when_limit_is_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A received upgrade redirect is known even if redirect following is disabled."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.scheme == "http":
            return _response(
                request,
                301,
                {"Location": "https://example.com/"},
            )
        return _response(request, headers=_SECURE_HEADERS)

    _mock_http(monkeypatch, handler)

    result = audit_http("example.com", max_redirects=0)

    assert result.http_to_https_redirect is True
    assert "HTTP_REDIRECT_LIMIT_EXCEEDED" in _codes(result)
    assert "HTTP_HTTPS_REDIRECT_MISSING" not in _codes(result)


def test_audit_http_does_not_follow_external_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """External redirect destinations are not requested."""
    requested_hosts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_hosts.append(request.url.host)
        if request.url.scheme == "http":
            return _response(
                request,
                302,
                {"Location": "http://127.0.0.1:8080/private"},
            )
        return _response(request, headers=_SECURE_HEADERS)

    _mock_http(monkeypatch, handler)

    result = audit_http("example.com")

    assert requested_hosts == ["example.com", "example.com"]
    assert "HTTP_REDIRECT_NOT_FOLLOWED" in _codes(result)
    assert "http_redirect" in result.errors


def test_audit_http_does_not_follow_https_downgrade(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A chain that upgrades to HTTPS cannot subsequently downgrade to HTTP."""
    requested_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        if request.url.scheme == "http":
            return _response(
                request,
                301,
                {"Location": "https://example.com/secure"},
            )
        if request.url.path == "/secure":
            return _response(
                request,
                302,
                {"Location": "http://example.com/downgrade"},
            )
        return _response(request, headers=_SECURE_HEADERS)

    _mock_http(monkeypatch, handler)

    result = audit_http("example.com")

    assert "http://example.com/downgrade" not in requested_urls
    assert "HTTP_REDIRECT_NOT_FOLLOWED" in _codes(result)
    assert "http_redirect" in result.errors


@pytest.mark.parametrize(
    "location",
    [
        "http://127.0.0.1:8080/private",
        "http://example.com:81/private",
        "https://user:password@example.com/private",
    ],
)
def test_audit_http_rejects_redirects_outside_scope(
    monkeypatch: pytest.MonkeyPatch,
    location: str,
) -> None:
    """Redirects to IPs, unconfigured ports, and credentialed URLs are blocked."""
    requested_hosts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_hosts.append(request.url.host)
        if request.url.scheme == "http":
            return _response(request, 302, {"Location": location})
        return _response(request, headers=_SECURE_HEADERS)

    _mock_http(monkeypatch, handler)

    result = audit_http("example.com")

    assert requested_hosts == ["example.com", "example.com"]
    assert "HTTP_REDIRECT_NOT_FOLLOWED" in _codes(result)


@pytest.mark.parametrize(
    ("exception", "expected_category"),
    [
        (httpx.ConnectError("connection refused"), "Connection failed"),
        (httpx.ConnectTimeout("connect timed out"), "timeout"),
        (httpx.ConnectError("certificate verify failed"), "TLS certificate"),
        (httpx.ConnectError("getaddrinfo failed"), "DNS resolution"),
    ],
)
def test_audit_http_records_request_failures(
    monkeypatch: pytest.MonkeyPatch,
    exception: httpx.HTTPError,
    expected_category: str,
) -> None:
    """Connection, timeout, TLS, and DNS failures are structured errors."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise exception

    _mock_http(monkeypatch, handler)

    result = audit_http("example.com")

    http_error = next(
        error for key, error in result.errors.items() if key.startswith("http_")
    )
    assert expected_category.casefold() in http_error.casefold()
    assert result.https_available is None


def test_audit_http_records_unexpected_status_safely(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unexpected status codes remain available as response metadata."""
    _mock_http(
        monkeypatch,
        lambda request: _response(
            request,
            503,
            headers=_SECURE_HEADERS if request.url.scheme == "https" else None,
        ),
    )

    result = audit_http("example.com")

    assert result.http_response is not None
    assert result.http_response.status_code == 503
    assert result.https_response is not None
    assert result.https_response.status_code == 503


def test_audit_http_records_client_setup_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TLS trust-store setup failures are reported without a traceback."""

    def raise_ssl_error(timeout: float) -> httpx.Client:
        raise ssl.SSLError("system trust store unavailable")

    monkeypatch.setattr(http_module, "_create_client", raise_ssl_error)

    result = audit_http("example.com")

    assert "client" in result.errors
    assert "system trust store unavailable" in result.errors["client"]
    assert result.http_response is None
    assert result.https_response is None


def test_audit_http_does_not_read_response_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Streaming responses are closed without consuming potentially large bodies."""

    class UnreadStream(httpx.SyncByteStream):
        def __iter__(self):
            raise AssertionError("Response body must not be read.")

        def close(self) -> None:
            return None

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.scheme == "http":
            return _response(request)
        return httpx.Response(
            200,
            headers=_SECURE_HEADERS,
            stream=UnreadStream(),
            request=request,
        )

    _mock_http(monkeypatch, handler)

    result = audit_http("example.com")

    assert result.https_response is not None
    assert result.https_response.status_code == 200


def test_audit_http_rejects_invalid_domain() -> None:
    with pytest.raises(TargetValidationError):
        audit_http("https://example.com")


@pytest.mark.parametrize("port", [0, -1, 65536, True])
def test_audit_http_rejects_invalid_ports(port: int) -> None:
    with pytest.raises(ValueError, match="port must be"):
        audit_http("example.com", http_port=port)


@pytest.mark.parametrize(
    "timeout",
    [0, -1, float("nan"), float("inf")],
)
def test_audit_http_rejects_invalid_timeout(timeout: float) -> None:
    with pytest.raises(ValueError, match="Timeout must be"):
        audit_http("example.com", timeout=timeout)


@pytest.mark.parametrize("max_redirects", [-1, 11, True])
def test_audit_http_rejects_invalid_redirect_limit(max_redirects: int) -> None:
    with pytest.raises(ValueError, match="Maximum redirects must be"):
        audit_http("example.com", max_redirects=max_redirects)


@pytest.mark.parametrize(
    "address",
    [
        "2002:0a00:0001::",
        "2001:0:0808:0808:0:0:f5ff:fffe",
        "64:ff9b::a00:1",
        "64:ff9b:1::a00:1",
    ],
)
def test_is_public_address_rejects_private_ipv4_transition_targets(
    address: str,
) -> None:
    assert not http_module._is_public_address(address)


@pytest.mark.parametrize(
    "address",
    ["93.184.216.34", "2606:4700:4700::1111"],
)
def test_backend_connects_to_validated_public_addresses(
    monkeypatch: pytest.MonkeyPatch,
    address: str,
) -> None:
    connected: list[tuple[str, int, float | None]] = []

    def resolve(host: str, port: int, **kwargs):
        assert host == "example.com"
        return [_address_info(address, port)]

    def connect(address_and_port, timeout=None, source_address=None, **kwargs):
        connected.append((*address_and_port, timeout))
        return _BareSocket()

    monkeypatch.setattr(http_module.socket, "getaddrinfo", resolve)
    monkeypatch.setattr(http_module.socket, "create_connection", connect)

    stream = http_module._PublicAddressBackend().connect_tcp(
        "example.com",
        443,
        timeout=2.5,
    )
    stream.close()

    assert connected == [(address, 443, 2.5)]


@pytest.mark.parametrize(
    "address",
    [
        "10.0.0.1",
        "127.0.0.1",
        "169.254.1.1",
        "192.0.2.1",
        "224.0.0.1",
        "240.0.0.1",
        "0.0.0.0",
        "::1",
        "fc00::1",
        "fe80::1",
        "2001:db8::1",
        "ff02::1",
        "::",
        "64:ff9b::a00:1",
        "::ffff:127.0.0.1",
        "::ffff:93.184.216.34",
    ],
)
def test_backend_rejects_non_global_addresses_without_connecting(
    monkeypatch: pytest.MonkeyPatch,
    address: str,
) -> None:
    connection_attempts: list[tuple[str, int]] = []

    monkeypatch.setattr(
        http_module.socket,
        "getaddrinfo",
        lambda host, port, **kwargs: [_address_info(address, port)],
    )
    monkeypatch.setattr(
        http_module.socket,
        "create_connection",
        lambda address_and_port, **kwargs: connection_attempts.append(address_and_port),
    )

    with pytest.raises(httpcore.ConnectError, match="Destination address rejected"):
        http_module._PublicAddressBackend().connect_tcp("example.com", 443)

    assert connection_attempts == []


def test_backend_rejects_mixed_public_and_private_answers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection_attempts: list[tuple[str, int]] = []

    monkeypatch.setattr(
        http_module.socket,
        "getaddrinfo",
        lambda host, port, **kwargs: [
            _address_info("93.184.216.34", port),
            _address_info("10.0.0.5", port),
        ],
    )
    monkeypatch.setattr(
        http_module.socket,
        "create_connection",
        lambda address_and_port, **kwargs: connection_attempts.append(address_and_port),
    )

    with pytest.raises(httpcore.ConnectError, match="Destination address rejected"):
        http_module._PublicAddressBackend().connect_tcp("example.com", 443)

    assert connection_attempts == []


def test_backend_fallback_uses_only_validated_addresses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempted: list[str] = []

    monkeypatch.setattr(
        http_module.socket,
        "getaddrinfo",
        lambda host, port, **kwargs: [
            _address_info("93.184.216.34", port),
            _address_info("1.1.1.1", port),
        ],
    )

    def connect_validated(
        backend,
        address,
        port,
        timeout,
        local_address,
        socket_options,
    ):
        attempted.append(address)
        if address == "93.184.216.34":
            raise httpcore.ConnectError("connection refused")
        return _BareSocket()

    monkeypatch.setattr(
        http_module._PublicAddressBackend,
        "_connect_validated",
        connect_validated,
    )

    stream = http_module._PublicAddressBackend().connect_tcp("example.com", 443)
    stream.close()

    assert attempted == ["93.184.216.34", "1.1.1.1"]


def test_backend_pins_connection_before_dns_can_rebind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolution_hosts: list[str] = []
    connected: list[tuple[str, int]] = []

    def resolve(host: str, port: int, **kwargs):
        resolution_hosts.append(host)
        if host == "example.com":
            address = (
                "93.184.216.34"
                if resolution_hosts.count("example.com") == 1
                else "127.0.0.1"
            )
        else:
            address = host
        return [_address_info(address, port)]

    def connect(address_and_port, timeout=None, source_address=None, **kwargs):
        connected.append(address_and_port)
        return _BareSocket()

    monkeypatch.setattr(http_module.socket, "getaddrinfo", resolve)
    monkeypatch.setattr(http_module.socket, "create_connection", connect)

    stream = http_module._PublicAddressBackend().connect_tcp("example.com", 443)
    stream.close()

    assert resolution_hosts == ["example.com"]
    assert connected == [("93.184.216.34", 443)]


def test_audit_http_reports_dns_and_destination_rejections(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        http_module.socket,
        "getaddrinfo",
        lambda host, port, **kwargs: [_address_info("127.0.0.1", port)],
    )

    result = audit_http("example.com")

    assert all(
        "Destination address rejected" in error for error in result.errors.values()
    )


def test_audit_http_reports_dns_resolution_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_resolution(host: str, port: int, **kwargs):
        raise socket.gaierror(socket.EAI_NONAME, "name not found")

    monkeypatch.setattr(http_module.socket, "getaddrinfo", fail_resolution)

    result = audit_http("example.com")

    assert result.errors
    assert all("DNS resolution failed" in error for error in result.errors.values())


def test_redirect_target_is_revalidated_and_never_uses_rebound_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolution_count = 0
    connected: list[tuple[str, int]] = []
    streams: list[_HTTPResponseStream] = []

    def resolve(host: str, port: int, **kwargs):
        nonlocal resolution_count
        resolution_count += 1
        address = "93.184.216.34" if resolution_count == 1 else "10.0.0.5"
        return [_address_info(address, port)]

    def connect_validated(
        backend,
        address,
        port,
        timeout,
        local_address,
        socket_options,
    ):
        connected.append((address, port))
        response = (
            b"HTTP/1.1 301 Moved Permanently\r\n"
            b"Location: https://example.com/redirected\r\n"
            b"Content-Length: 0\r\n"
            b"Connection: close\r\n\r\n"
        )
        stream = _HTTPResponseStream(response)
        streams.append(stream)
        return stream

    monkeypatch.setattr(http_module.socket, "getaddrinfo", resolve)
    monkeypatch.setattr(
        http_module._PublicAddressBackend,
        "_connect_validated",
        connect_validated,
    )

    result = audit_http("example.com")

    assert result.http_to_https_redirect is True
    assert any(
        "Destination address rejected" in error for error in result.errors.values()
    )
    assert connected == [("93.184.216.34", 80)]
    assert resolution_count >= 2


def test_transport_preserves_original_host_and_verified_tls_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    streams: list[_HTTPResponseStream] = []

    monkeypatch.setattr(
        http_module.socket,
        "getaddrinfo",
        lambda host, port, **kwargs: [_address_info("93.184.216.34", port)],
    )

    def connect_validated(
        backend,
        address,
        port,
        timeout,
        local_address,
        socket_options,
    ):
        stream = _HTTPResponseStream(
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        streams.append(stream)
        return stream

    monkeypatch.setattr(
        http_module._PublicAddressBackend,
        "_connect_validated",
        connect_validated,
    )

    with httpx.Client(
        transport=http_module._PinnedHTTPTransport(),
        timeout=1.0,
        trust_env=False,
    ) as client:
        response = client.get("https://example.com/")

    assert response.status_code == 200
    assert len(streams) == 1
    assert streams[0].tls_server_name == "example.com"
    assert streams[0].tls_context_verified
    assert b"Host: example.com" in streams[0].request_bytes


def test_pinned_transport_close_closes_its_connection_pool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class PoolSpy:
        def __init__(self, **kwargs) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    monkeypatch.setattr(http_module.httpcore, "ConnectionPool", PoolSpy)
    transport = http_module._PinnedHTTPTransport()
    pool = transport._pool

    transport.close()

    assert pool.closed


def test_httpx_client_close_invokes_pinned_transport_close(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = http_module._PinnedHTTPTransport()
    close_calls: list[bool] = []
    original_close = transport.close

    def close() -> None:
        close_calls.append(True)
        original_close()

    monkeypatch.setattr(transport, "close", close)
    client = httpx.Client(transport=transport)

    client.close()

    assert close_calls == [True]


def test_repeated_http_assessments_close_keep_alive_connections(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    streams: list[_HTTPResponseStream] = []

    monkeypatch.setattr(
        http_module.socket,
        "getaddrinfo",
        lambda host, port, **kwargs: [_address_info("93.184.216.34", port)],
    )

    def connect_validated(
        backend,
        address,
        port,
        timeout,
        local_address,
        socket_options,
    ):
        stream = _HTTPResponseStream(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        streams.append(stream)
        return stream

    monkeypatch.setattr(
        http_module._PublicAddressBackend,
        "_connect_validated",
        connect_validated,
    )

    for _ in range(3):
        audit_http("example.com")

    assert len(streams) == 6
    assert all(stream.closed for stream in streams)


def test_httpx_client_close_closes_pooled_keep_alive_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    streams: list[_HTTPResponseStream] = []

    monkeypatch.setattr(
        http_module.socket,
        "getaddrinfo",
        lambda host, port, **kwargs: [_address_info("93.184.216.34", port)],
    )

    def connect_validated(
        backend,
        address,
        port,
        timeout,
        local_address,
        socket_options,
    ):
        stream = _HTTPResponseStream(
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody"
        )
        streams.append(stream)
        return stream

    monkeypatch.setattr(
        http_module._PublicAddressBackend,
        "_connect_validated",
        connect_validated,
    )

    client = httpx.Client(
        transport=http_module._PinnedHTTPTransport(),
        timeout=1.0,
        trust_env=False,
    )
    response = client.get("http://example.com/")

    assert response.content == b"body"
    assert len(streams) == 1
    assert not streams[0].closed

    client.close()

    assert streams[0].closed


def test_http_assessment_closes_transport_after_request_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    close_calls: list[bool] = []
    original_close = http_module._PinnedHTTPTransport.close

    def close(transport) -> None:
        close_calls.append(True)
        original_close(transport)

    def fail_connect(
        backend,
        address,
        port,
        timeout,
        local_address,
        socket_options,
    ):
        raise httpcore.ConnectError("connection refused")

    monkeypatch.setattr(http_module._PinnedHTTPTransport, "close", close)
    monkeypatch.setattr(
        http_module._PublicAddressBackend,
        "_connect_validated",
        fail_connect,
    )
    monkeypatch.setattr(
        http_module.socket,
        "getaddrinfo",
        lambda host, port, **kwargs: [_address_info("93.184.216.34", port)],
    )

    result = audit_http("example.com")

    assert result.errors
    assert close_calls == [True]


def test_http_assessment_closes_keep_alive_connections_after_redirect_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    close_calls: list[bool] = []
    streams: list[_HTTPResponseStream] = []
    original_close = http_module._PinnedHTTPTransport.close

    def close(transport) -> None:
        close_calls.append(True)
        original_close(transport)

    def connect_validated(
        backend,
        address,
        port,
        timeout,
        local_address,
        socket_options,
    ):
        response = (
            b"HTTP/1.1 302 Found\r\n"
            b"Location: https://attacker.example/private\r\n"
            b"Content-Length: 0\r\n\r\n"
            if port == 80
            else b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        )
        stream = _HTTPResponseStream(response)
        streams.append(stream)
        return stream

    monkeypatch.setattr(http_module._PinnedHTTPTransport, "close", close)
    monkeypatch.setattr(
        http_module._PublicAddressBackend,
        "_connect_validated",
        connect_validated,
    )
    monkeypatch.setattr(
        http_module.socket,
        "getaddrinfo",
        lambda host, port, **kwargs: [_address_info("93.184.216.34", port)],
    )

    result = audit_http("example.com")

    assert "http_redirect" in result.errors
    assert close_calls == [True]
    assert len(streams) == 2
    assert all(stream.closed for stream in streams)

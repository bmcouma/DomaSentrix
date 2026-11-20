"""HTTP security configuration assessment."""

import ipaddress
import re
import socket
import ssl
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from math import isfinite
from typing import Literal, NoReturn

import certifi
import httpcore
import httpx

from domasentrix.core.target import TargetValidationError, normalize_domain

Severity = Literal["critical", "high", "medium", "low", "info"]

_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_NAT64_PREFIXES = (
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("64:ff9b:1::/48"),
)
_HTTPCORE_TRANSPORT_ERRORS: tuple[type[Exception], ...] = (
    httpcore.ConnectTimeout,
    httpcore.ReadTimeout,
    httpcore.WriteTimeout,
    httpcore.PoolTimeout,
    httpcore.ConnectError,
    httpcore.ReadError,
    httpcore.WriteError,
    httpcore.RemoteProtocolError,
    httpcore.LocalProtocolError,
    httpcore.ProxyError,
    httpcore.UnsupportedProtocol,
    httpcore.ConnectionNotAvailable,
)
_RESPONSE_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "server",
    "x-powered-by",
    "content-type",
    "content-length",
    "date",
)


@dataclass(frozen=True)
class HTTPFinding:
    """A security observation from an HTTP assessment."""

    code: str
    severity: Severity
    message: str
    evidence: str
    remediation: str


@dataclass(frozen=True)
class HTTPResponseInfo:
    """Metadata captured from an HTTP response without downloading its body."""

    url: str
    status_code: int
    http_version: str
    redirect_count: int
    headers: dict[str, tuple[str, ...]]


@dataclass
class HTTPAuditResult:
    """Structured results from an HTTP security assessment."""

    domain: str
    http_port: int
    https_port: int
    http_response: HTTPResponseInfo | None = None
    https_response: HTTPResponseInfo | None = None
    http_to_https_redirect: bool | None = None
    https_available: bool | None = None
    errors: dict[str, str] = field(default_factory=dict)
    findings: list[HTTPFinding] = field(default_factory=list)


@dataclass
class _FetchResult:
    """Internal response and redirect state for one starting URL."""

    response: HTTPResponseInfo | None = None
    error: str | None = None
    error_key: str = "request"
    findings: list[HTTPFinding] = field(default_factory=list)
    redirected_to_https: bool = False
    external_redirect: bool = False


def _is_public_address(address: str) -> bool:
    """Return whether an address is public, excluding IPv4 translation ranges."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False

    if isinstance(parsed, ipaddress.IPv6Address):
        if (
            parsed.ipv4_mapped is not None
            or parsed.sixtofour is not None
            or parsed.teredo is not None
            or any(parsed in prefix for prefix in _NAT64_PREFIXES)
        ):
            return False
    return (
        parsed.is_global
        and not parsed.is_private
        and not parsed.is_loopback
        and not parsed.is_link_local
        and not parsed.is_multicast
        and not parsed.is_reserved
        and not parsed.is_unspecified
    )


def _resolve_public_addresses(host: str, port: int) -> list[str]:
    """Resolve a host and reject the entire answer set if any address is unsafe."""
    try:
        resolved = socket.getaddrinfo(
            host,
            port,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except socket.gaierror as exc:
        raise httpcore.ConnectError(f"DNS resolution failed: {exc}") from exc
    except OSError as exc:
        raise httpcore.ConnectError(f"DNS resolution failed: {exc}") from exc

    if not resolved:
        raise httpcore.ConnectError("DNS resolution failed: no addresses returned.")

    addresses: list[str] = []
    for family, _, _, _, sockaddr in resolved:
        if family not in {socket.AF_INET, socket.AF_INET6} or not sockaddr:
            raise httpcore.ConnectError(
                "Destination address rejected: DNS returned an unsupported address."
            )
        address = sockaddr[0]
        if not isinstance(address, str) or not _is_public_address(address):
            raise httpcore.ConnectError(
                f"Destination address rejected: {address!s} is not globally routable."
            )
        if "%" in address:
            raise httpcore.ConnectError(
                "Destination address rejected: scoped IPv6 destinations are "
                "not allowed."
            )
        canonical_address = str(ipaddress.ip_address(address))
        if canonical_address not in addresses:
            addresses.append(canonical_address)
    return addresses


class _PublicAddressBackend(httpcore.SyncBackend):
    """Resolve, validate, and connect only to numeric public IP addresses."""

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:
        addresses = _resolve_public_addresses(host, port)
        last_error: httpcore.ConnectError | httpcore.ConnectTimeout | None = None

        for address in addresses:
            try:
                return self._connect_validated(
                    address,
                    port,
                    timeout,
                    local_address,
                    socket_options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last_error = exc

        if last_error is not None:
            raise last_error
        raise httpcore.ConnectError("DNS resolution failed: no usable addresses.")

    def _connect_validated(
        self,
        address: str,
        port: int,
        timeout: float | None,
        local_address: str | None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None,
    ) -> httpcore.NetworkStream:
        return super().connect_tcp(
            address,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )


def _raise_httpcore_error(exc: Exception, request: httpx.Request) -> NoReturn:
    """Map httpcore failures to the HTTPX exceptions handled by the assessor."""
    if isinstance(exc, httpcore.ConnectTimeout):
        raise httpx.ConnectTimeout(str(exc), request=request) from exc
    if isinstance(exc, httpcore.ReadTimeout):
        raise httpx.ReadTimeout(str(exc), request=request) from exc
    if isinstance(exc, httpcore.WriteTimeout):
        raise httpx.WriteTimeout(str(exc), request=request) from exc
    if isinstance(exc, httpcore.PoolTimeout):
        raise httpx.PoolTimeout(str(exc), request=request) from exc
    if isinstance(exc, httpcore.ConnectError):
        raise httpx.ConnectError(str(exc), request=request) from exc
    if isinstance(exc, httpcore.ReadError):
        raise httpx.ReadError(str(exc), request=request) from exc
    if isinstance(exc, httpcore.WriteError):
        raise httpx.WriteError(str(exc), request=request) from exc
    if isinstance(exc, httpcore.RemoteProtocolError):
        raise httpx.RemoteProtocolError(str(exc), request=request) from exc
    if isinstance(exc, httpcore.LocalProtocolError):
        raise httpx.LocalProtocolError(str(exc), request=request) from exc
    if isinstance(exc, httpcore.ProxyError):
        raise httpx.ProxyError(str(exc), request=request) from exc
    if isinstance(exc, httpcore.UnsupportedProtocol):
        raise httpx.UnsupportedProtocol(str(exc), request=request) from exc
    raise httpx.TransportError(str(exc), request=request) from exc


class _HTTPcoreResponseStream(httpx.SyncByteStream):
    """Adapt an httpcore response stream to HTTPX."""

    def __init__(self, stream: Iterable[bytes], request: httpx.Request) -> None:
        self._stream = stream
        self._request = request

    def __iter__(self) -> Iterator[bytes]:
        try:
            yield from self._stream
        except _HTTPCORE_TRANSPORT_ERRORS as exc:
            _raise_httpcore_error(exc, self._request)

    def close(self) -> None:
        close = getattr(self._stream, "close", None)
        if close is not None:
            close()


class _PinnedHTTPTransport(httpx.BaseTransport):
    """Use a validated numeric destination while preserving the original URL."""

    def __init__(self) -> None:
        self._pool = httpcore.ConnectionPool(
            ssl_context=ssl.create_default_context(cafile=certifi.where()),
            network_backend=_PublicAddressBackend(),
            max_connections=10,
            max_keepalive_connections=5,
            keepalive_expiry=5.0,
            http1=True,
            http2=False,
            retries=0,
        )

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if not isinstance(request.stream, httpx.SyncByteStream):
            raise TypeError("Synchronous HTTP requests require a synchronous body.")

        core_request = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )
        try:
            core_response = self._pool.handle_request(core_request)
        except _HTTPCORE_TRANSPORT_ERRORS as exc:
            _raise_httpcore_error(exc, request)

        assert isinstance(core_response.stream, Iterable)
        return httpx.Response(
            status_code=core_response.status,
            headers=core_response.headers,
            stream=_HTTPcoreResponseStream(core_response.stream, request),
            extensions=core_response.extensions,
            request=request,
        )

    def close(self) -> None:
        self._pool.close()


def _create_client(timeout: float) -> httpx.Client:
    """Create a verified client with pinned public destinations and no redirects."""
    return httpx.Client(
        transport=_PinnedHTTPTransport(),
        follow_redirects=False,
        timeout=httpx.Timeout(timeout),
        trust_env=False,
        headers={
            "User-Agent": "DomaSentrix/0.1.0",
            "Accept": "*/*",
            "Accept-Encoding": "identity",
        },
    )


def _response_info(
    response: httpx.Response,
    redirect_count: int,
) -> HTTPResponseInfo:
    """Capture status and selected headers without consuming the response body."""
    headers = {
        name: tuple(response.headers.get_list(name))
        for name in _RESPONSE_HEADERS
        if response.headers.get_list(name)
    }
    return HTTPResponseInfo(
        url=str(response.url),
        status_code=response.status_code,
        http_version=response.http_version,
        redirect_count=redirect_count,
        headers=headers,
    )


def _exception_category(exc: httpx.HTTPError) -> str:
    """Classify an HTTPX exception without exposing a traceback."""
    if isinstance(exc, httpx.TimeoutException):
        return "timeout"

    cause: BaseException | None = exc
    seen: set[int] = set()
    while cause is not None and id(cause) not in seen:
        seen.add(id(cause))
        if isinstance(cause, ssl.SSLCertVerificationError):
            return "TLS certificate verification failed"
        if isinstance(cause, ssl.SSLError):
            return "TLS connection failed"
        if isinstance(cause, socket.gaierror):
            return "DNS resolution failed"
        cause = cause.__cause__ or cause.__context__

    message = str(exc).casefold()
    if "getaddrinfo" in message or "name or service not known" in message:
        return "DNS resolution failed"
    if "destination address rejected" in message:
        return "Destination address rejected"
    if isinstance(exc, httpx.ConnectError):
        if "certificate verify" in message or "certificate verification" in message:
            return "TLS certificate verification failed"
        return "Connection failed"
    if isinstance(exc, httpx.RemoteProtocolError):
        return "HTTP protocol error"
    return "HTTP request failed"


def _redirect_is_allowed(
    target: httpx.URL,
    domain: str,
    http_port: int,
    https_port: int,
    current_scheme: str,
) -> bool:
    """Allow only same-domain redirects to the configured ports."""
    if target.scheme not in {"http", "https"}:
        return False
    if target.username or target.password:
        return False
    if current_scheme == "https" and target.scheme != "https":
        return False

    try:
        target_domain = normalize_domain(target.host.rstrip("."))
    except TargetValidationError:
        return False

    expected_port = http_port if target.scheme == "http" else https_port
    actual_port = target.port or (80 if target.scheme == "http" else 443)
    return target_domain == domain and actual_port == expected_port


def _fetch_endpoint(
    client: httpx.Client,
    url: httpx.URL,
    domain: str,
    http_port: int,
    https_port: int,
    max_redirects: int,
) -> _FetchResult:
    """Fetch one endpoint, manually following only approved redirects."""
    result = _FetchResult()
    starting_scheme = url.scheme
    current_url = url
    visited = {str(current_url)}
    redirect_count = 0

    while True:
        try:
            request = client.build_request("GET", current_url)
            response = client.send(
                request,
                follow_redirects=False,
                stream=True,
            )
        except httpx.HTTPError as exc:
            result.error = f"{_exception_category(exc)}: {exc}"
            return result

        try:
            result.response = _response_info(response, redirect_count)
            client.cookies.clear()

            location = response.headers.get("location")
            if response.status_code not in _REDIRECT_STATUSES or not location:
                return result

            try:
                target = current_url.join(location)
            except httpx.InvalidURL as exc:
                result.error_key = "redirect"
                result.error = f"Invalid redirect target: {exc}"
                return result

            if not _redirect_is_allowed(
                target,
                domain,
                http_port,
                https_port,
                current_url.scheme,
            ):
                result.error_key = "redirect"
                result.external_redirect = True
                target_port = target.port or (443 if target.scheme == "https" else 80)
                result.error = (
                    "Redirect was not followed because its host, scheme, or "
                    "port is outside the configured scope."
                )
                result.findings.append(
                    HTTPFinding(
                        code="HTTP_REDIRECT_NOT_FOLLOWED",
                        severity="low",
                        message=(
                            "A redirect outside the configured host, scheme, "
                            "or ports was not followed."
                        ),
                        evidence=(
                            f"Redirect target origin: {target.scheme}://"
                            f"{target.host}:{target_port}"
                        ),
                        remediation=(
                            "Verify the redirect destination is intentional "
                            "and assess it separately if authorized."
                        ),
                    )
                )
                return result

            if starting_scheme == "http" and target.scheme == "https":
                result.redirected_to_https = True

            target_url = str(target)
            if target_url in visited:
                result.error_key = "redirect"
                result.error = "A redirect loop was detected."
                result.findings.append(
                    HTTPFinding(
                        code="HTTP_REDIRECT_LOOP",
                        severity="medium",
                        message="The endpoint entered a redirect loop.",
                        evidence=f"Repeated URL: {target_url}",
                        remediation="Correct the redirect rules to terminate.",
                    )
                )
                return result

            if redirect_count >= max_redirects:
                result.error_key = "redirect"
                result.error = f"The redirect limit of {max_redirects} was reached."
                result.findings.append(
                    HTTPFinding(
                        code="HTTP_REDIRECT_LIMIT_EXCEEDED",
                        severity="medium",
                        message="The redirect chain exceeded the configured limit.",
                        evidence=f"Limit: {max_redirects} redirects.",
                        remediation="Reduce unnecessary redirect hops.",
                    )
                )
                return result

            redirect_count += 1
            visited.add(target_url)
            current_url = target
        finally:
            response.close()


def _add_finding(
    result: HTTPAuditResult,
    code: str,
    severity: Severity,
    message: str,
    evidence: str,
    remediation: str,
) -> None:
    result.findings.append(
        HTTPFinding(
            code=code,
            severity=severity,
            message=message,
            evidence=evidence,
            remediation=remediation,
        )
    )


def _assess_hsts(
    result: HTTPAuditResult,
    headers: Mapping[str, tuple[str, ...]],
) -> None:
    """Assess HSTS only on an HTTPS response."""
    values = headers.get("strict-transport-security", ())
    if not values:
        _add_finding(
            result,
            "HTTP_HSTS_MISSING",
            "medium",
            "The HTTPS response does not set Strict-Transport-Security.",
            "Strict-Transport-Security header is absent.",
            "Set an appropriate max-age over HTTPS; consider includeSubDomains "
            "only when all subdomains support HTTPS.",
        )
        return

    max_age_values: list[str] = []
    for directive in ", ".join(values).split(";"):
        name, separator, value = directive.strip().partition("=")
        if name.casefold() == "max-age" and separator:
            max_age_values.append(value.strip().strip('"'))

    if len(max_age_values) != 1 or not re.fullmatch(
        r"\d+",
        max_age_values[0] if max_age_values else "",
    ):
        _add_finding(
            result,
            "HTTP_HSTS_INVALID",
            "medium",
            "The HSTS header is missing a single valid max-age directive.",
            "; ".join(values),
            "Provide one non-negative integer max-age directive.",
        )
        return

    max_age = max_age_values[0].lstrip("0") or "0"
    if max_age == "0":
        _add_finding(
            result,
            "HTTP_HSTS_DISABLED",
            "medium",
            "HSTS is explicitly disabled by max-age=0.",
            "; ".join(values),
            "Use a positive max-age after verifying HTTPS works reliably.",
        )
    elif len(max_age) < 8 or (len(max_age) == 8 and max_age < "31536000"):
        _add_finding(
            result,
            "HTTP_HSTS_SHORT_MAX_AGE",
            "low",
            "The HSTS max-age is shorter than one year.",
            f"max-age={max_age}",
            "Consider a longer max-age after confirming HTTPS readiness.",
        )


def _parse_csp(
    values: tuple[str, ...],
) -> tuple[list[dict[str, list[str]]], bool]:
    """Parse CSP directives conservatively for common configuration checks."""
    policies: list[dict[str, list[str]]] = []
    malformed = False

    for value in values:
        if not value.strip():
            malformed = True
            continue

        directives: dict[str, list[str]] = {}
        for directive in value.split(";"):
            tokens = directive.strip().split()
            if not tokens:
                continue
            name = tokens[0].casefold()
            if not re.fullmatch(r"[a-z][a-z0-9-]*", name):
                malformed = True
                continue
            directives.setdefault(name, tokens[1:])
        policies.append(directives)

    return policies, malformed


def _csp_has_frame_restriction(
    policies: list[dict[str, list[str]]],
) -> bool:
    """Check for a non-wildcard frame-ancestors directive."""
    unrestricted_sources = {"*", "http:", "https:", "http://*", "https://*"}
    for policy in policies:
        if "frame-ancestors" not in policy:
            continue
        sources = policy["frame-ancestors"]
        if not sources or not any(
            source.casefold() in unrestricted_sources for source in sources
        ):
            return True
    return False


def _assess_security_headers(
    result: HTTPAuditResult,
    response: HTTPResponseInfo,
) -> None:
    headers = response.headers

    csp_values = headers.get("content-security-policy", ())
    policies, malformed_csp = _parse_csp(csp_values)
    if not csp_values:
        _add_finding(
            result,
            "HTTP_CSP_MISSING",
            "medium",
            "The HTTPS response does not set Content-Security-Policy.",
            "Content-Security-Policy header is absent.",
            "Define a policy appropriate to the site's resources and inline code.",
        )
    else:
        if malformed_csp:
            _add_finding(
                result,
                "HTTP_CSP_MALFORMED",
                "low",
                "One or more CSP values contain malformed directives.",
                "; ".join(csp_values),
                "Review directive names and syntax against the CSP specification.",
            )
        weak_tokens = {
            token.casefold()
            for policy in policies
            for sources in policy.values()
            for token in sources
            if token.casefold()
            in {
                "*",
                "http:",
                "https:",
                "http://*",
                "https://*",
                "'unsafe-inline'",
                "'unsafe-eval'",
            }
        }
        if weak_tokens:
            _add_finding(
                result,
                "HTTP_CSP_WEAK_POLICY",
                "medium",
                "The CSP contains broad or unsafe source expressions.",
                ", ".join(sorted(weak_tokens)),
                "Narrow source lists and avoid unsafe-inline/unsafe-eval where "
                "practical; this check does not fully validate CSP semantics.",
            )

    x_frame_values = headers.get("x-frame-options", ())
    valid_x_frame = len(x_frame_values) == 1 and x_frame_values[
        0
    ].strip().casefold() in {"deny", "sameorigin"}
    csp_frame_restriction = _csp_has_frame_restriction(policies)
    if not valid_x_frame and not csp_frame_restriction:
        if x_frame_values:
            _add_finding(
                result,
                "HTTP_FRAME_PROTECTION_INVALID",
                "medium",
                "X-Frame-Options is not set to DENY or SAMEORIGIN, and CSP "
                "does not provide a restrictive frame-ancestors directive.",
                "; ".join(x_frame_values),
                "Use X-Frame-Options: DENY or SAMEORIGIN, or a restrictive "
                "CSP frame-ancestors directive.",
            )
        else:
            _add_finding(
                result,
                "HTTP_FRAME_PROTECTION_MISSING",
                "medium",
                "Neither X-Frame-Options nor a restrictive CSP "
                "frame-ancestors directive provides framing protection.",
                "Both protections are absent or ineffective.",
                "Set X-Frame-Options or a restrictive CSP frame-ancestors directive.",
            )

    content_type_values = headers.get("x-content-type-options", ())
    if not content_type_values:
        _add_finding(
            result,
            "HTTP_X_CONTENT_TYPE_OPTIONS_MISSING",
            "low",
            "X-Content-Type-Options is absent.",
            "X-Content-Type-Options header is absent.",
            "Set X-Content-Type-Options: nosniff.",
        )
    elif len(content_type_values) != 1 or (
        content_type_values[0].strip().casefold() != "nosniff"
    ):
        _add_finding(
            result,
            "HTTP_X_CONTENT_TYPE_OPTIONS_INVALID",
            "low",
            "X-Content-Type-Options is not set to nosniff.",
            "; ".join(content_type_values),
            "Set X-Content-Type-Options: nosniff.",
        )

    referrer_values = headers.get("referrer-policy", ())
    if not referrer_values:
        _add_finding(
            result,
            "HTTP_REFERRER_POLICY_MISSING",
            "low",
            "Referrer-Policy is absent.",
            "Referrer-Policy header is absent.",
            "Set an explicit policy such as strict-origin-when-cross-origin.",
        )
    else:
        policies_in_header = [
            item.strip().casefold()
            for value in referrer_values
            for item in value.split(",")
            if item.strip()
        ]
        effective_policy = policies_in_header[-1] if policies_in_header else ""
        if effective_policy == "unsafe-url":
            _add_finding(
                result,
                "HTTP_REFERRER_POLICY_WEAK",
                "medium",
                "Referrer-Policy may disclose full URLs to other origins.",
                effective_policy,
                "Use a restrictive policy such as strict-origin-when-cross-origin.",
            )
        elif effective_policy not in {
            "no-referrer",
            "no-referrer-when-downgrade",
            "origin",
            "origin-when-cross-origin",
            "same-origin",
            "strict-origin",
            "strict-origin-when-cross-origin",
        }:
            _add_finding(
                result,
                "HTTP_REFERRER_POLICY_INVALID",
                "low",
                "Referrer-Policy does not contain a recognized policy value.",
                "; ".join(referrer_values),
                "Choose a recognized Referrer-Policy value.",
            )

    permissions_values = headers.get("permissions-policy", ())
    if not permissions_values:
        _add_finding(
            result,
            "HTTP_PERMISSIONS_POLICY_MISSING",
            "low",
            "Permissions-Policy is absent.",
            "Permissions-Policy header is absent.",
            "Consider explicitly restricting browser features the site does not use.",
        )
    elif not any(value.strip() for value in permissions_values):
        _add_finding(
            result,
            "HTTP_PERMISSIONS_POLICY_EMPTY",
            "low",
            "Permissions-Policy is present but empty.",
            "; ".join(permissions_values),
            "Provide valid feature policies or omit the empty header.",
        )
    elif any(
        not re.fullmatch(
            r"\s*[a-z][a-z0-9-]*\s*=\s*(?:\*|\([^)]*\))\s*",
            directive,
            flags=re.IGNORECASE,
        )
        for value in permissions_values
        for directive in value.split(",")
    ):
        _add_finding(
            result,
            "HTTP_PERMISSIONS_POLICY_INVALID",
            "low",
            "Permissions-Policy contains a malformed directive.",
            "; ".join(permissions_values),
            "Use feature directives with valid allowlists, such as geolocation=().",
        )


def _assess_disclosure(
    result: HTTPAuditResult,
    label: str,
    response: HTTPResponseInfo | None,
) -> None:
    if response is None:
        return

    server_values = response.headers.get("server", ())
    if server_values:
        _add_finding(
            result,
            "HTTP_SERVER_DISCLOSURE",
            "low",
            "The Server header discloses implementation information; this alone "
            "does not indicate a vulnerability.",
            f"{label}: {', '.join(server_values)}",
            "Remove or minimize unnecessary server identification.",
        )

    powered_values = response.headers.get("x-powered-by", ())
    if powered_values:
        _add_finding(
            result,
            "HTTP_X_POWERED_BY_DISCLOSURE",
            "low",
            "X-Powered-By discloses application technology information.",
            f"{label}: {', '.join(powered_values)}",
            "Remove X-Powered-By if it is not operationally required.",
        )


def audit_http(
    domain: str,
    http_port: int = 80,
    https_port: int = 443,
    timeout: float = 5.0,
    max_redirects: int = 5,
) -> HTTPAuditResult:
    """Assess HTTP-to-HTTPS behavior and headers using bounded safe requests.

    Request bodies are never consumed. Redirects are followed only to the same
    normalized domain and the configured HTTP/HTTPS ports.
    """
    normalized_domain = normalize_domain(domain)
    if isinstance(http_port, bool) or not 1 <= http_port <= 65535:
        raise ValueError("HTTP port must be between 1 and 65535.")
    if isinstance(https_port, bool) or not 1 <= https_port <= 65535:
        raise ValueError("HTTPS port must be between 1 and 65535.")
    if not isfinite(timeout) or timeout <= 0:
        raise ValueError("Timeout must be finite and greater than zero.")
    if (
        isinstance(max_redirects, bool)
        or not isinstance(max_redirects, int)
        or not 0 <= max_redirects <= 10
    ):
        raise ValueError("Maximum redirects must be between 0 and 10.")

    result = HTTPAuditResult(
        domain=normalized_domain,
        http_port=http_port,
        https_port=https_port,
    )
    http_url = httpx.URL(f"http://{normalized_domain}:{http_port}/")
    https_url = httpx.URL(f"https://{normalized_domain}:{https_port}/")

    try:
        client = _create_client(timeout)
    except httpx.HTTPError as exc:
        result.errors["client"] = f"{_exception_category(exc)}: {exc}"
        return result
    except ssl.SSLError as exc:
        result.errors["client"] = f"TLS client setup failed: {exc}"
        return result
    except (OSError, ValueError) as exc:
        result.errors["client"] = f"HTTP client setup failed: {exc}"
        return result

    with client:
        http_fetch = _fetch_endpoint(
            client,
            http_url,
            normalized_domain,
            http_port,
            https_port,
            max_redirects,
        )
        https_fetch = _fetch_endpoint(
            client,
            https_url,
            normalized_domain,
            http_port,
            https_port,
            max_redirects,
        )

    result.http_response = http_fetch.response
    result.https_response = https_fetch.response
    result.findings.extend(http_fetch.findings)
    result.findings.extend(https_fetch.findings)

    if http_fetch.error:
        result.errors[f"http_{http_fetch.error_key}"] = http_fetch.error
    if https_fetch.error:
        result.errors[f"https_{https_fetch.error_key}"] = https_fetch.error

    if http_fetch.redirected_to_https:
        result.http_to_https_redirect = True
    elif (
        http_fetch.response is not None
        and http_fetch.error is None
        and not http_fetch.external_redirect
    ):
        result.http_to_https_redirect = False
        _add_finding(
            result,
            "HTTP_HTTPS_REDIRECT_MISSING",
            "medium",
            "The HTTP endpoint did not redirect to HTTPS on the requested domain.",
            (
                f"Final URL: {http_fetch.response.url}; "
                f"status: {http_fetch.response.status_code}"
            ),
            "Redirect HTTP requests to the corresponding HTTPS endpoint.",
        )

    direct_https_is_available = (
        https_fetch.response is not None
        and httpx.URL(https_fetch.response.url).scheme == "https"
    )
    upgraded_https_is_available = (
        http_fetch.response is not None
        and httpx.URL(http_fetch.response.url).scheme == "https"
    )
    result.https_available = (
        True if direct_https_is_available or upgraded_https_is_available else None
    )

    header_response = (
        https_fetch.response
        if direct_https_is_available
        else http_fetch.response
        if upgraded_https_is_available
        else None
    )
    if header_response is not None:
        _assess_hsts(result, header_response.headers)
        _assess_security_headers(result, header_response)

    _assess_disclosure(result, "HTTP", http_fetch.response)
    if https_fetch.response != http_fetch.response:
        _assess_disclosure(result, "HTTPS", https_fetch.response)

    return result

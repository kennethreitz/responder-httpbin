# -*- coding: utf-8 -*-

"""
httpbin.core
~~~~~~~~~~~~

The core responder-httpbin experience: a faithful port of httpbin's endpoints
to the `responder <https://responder.kennethreitz.org/>`_ ASGI web framework.

This is a dogfooding fork — not httpbin.org — that exercises responder end to
end: native OpenAPI/Swagger, ASGI middleware, async streaming, templates,
typed path params, and the built-in httpx test client.
"""

import asyncio
import base64
import json
import os
import random
import re
import time
import uuid
from urllib.parse import urlencode

import responder
from responder.params import Query
from starlette.datastructures import MutableHeaders

from . import filters
from . import models
from .helpers import (
    ANGRY_ASCII,
    ROBOT_TXT,
    check_basic_auth,
    check_digest_auth,
    digest_challenge_header,
    get_dict,
    get_headers,
    get_request_range,
    get_url,
    http_date,
    next_stale_after_value,
    parse_authorization_header,
    parse_multi_value_header,
    query_has,
    query_multi,
    query_pairs,
    secure_cookie,
    set_status,
)
from .utils import weighted_choice

HERE = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(HERE, "VERSION")) as version_file:
    version = version_file.read().strip()

ENV_COOKIES = (
    "_gauges_unique",
    "_gauges_unique_year",
    "_gauges_unique_month",
    "_gauges_unique_day",
    "_gauges_unique_hour",
    "__utmz",
    "__utma",
    "__utmb",
)

TRACKING_ENABLED = "HTTPBIN_TRACKING" in os.environ

# ---
# App
# ---

api = responder.API(
    title="responder-httpbin",
    version=version,
    description=(
        "A simple HTTP Request &amp; Response Service — the httpbin API, "
        "running on the <a href='https://responder.kennethreitz.org/'>responder</a> "
        "web framework. A dogfooding fork; <b>not</b> httpbin.org."
    ),
    openapi="3.0.2",
    docs_route="/",
    openapi_route="/schema.yml",
    templates_dir=os.path.join(HERE, "templates"),
    static_dir=os.path.join(HERE, "static"),
    static_route="/static",
    auto_escape=False,
    gzip=False,  # /gzip /deflate /brotli encode explicitly; keep exact Content-Length
    secret_key=os.environ.get("SECRET_KEY", "responder-httpbin-not-secret"),
)


# ----------
# Middleware
# ----------


class HttpbinMiddleware:
    """A single ASGI middleware covering httpbin's cross-cutting behavior.

    Replaces Flask's ``before_request``/``after_request`` hooks:

    * ``Transfer-Encoding: chunked`` → ``501`` (httpbin rejects chunked bodies).
    * every response (including responder's automatic-``OPTIONS`` preflight) gets
      httpbin's permissive CORS headers — ``Access-Control-Allow-Origin`` echoes
      the Origin (defaulting to ``*``) and ``Access-Control-Allow-Credentials:
      true`` — emitted even when no Origin header is present, which Starlette's
      native CORS middleware will not do. ``OPTIONS`` additionally gets the
      preflight method/age/header fields.

    Because OPTIONS is routed (not short-circuited), undefined paths still 404
    and method-restricted routes never run a handler for a preflight.
    """

    cors_methods = "GET, POST, PUT, DELETE, PATCH, OPTIONS"

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        req_headers = {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in scope.get("headers", [])
        }
        method = scope["method"]
        origin = req_headers.get("origin", "*")

        if req_headers.get("transfer-encoding", "").lower() == "chunked":
            body = b"Chunked requests are not supported."
            await send(
                {
                    "type": "http.response.start",
                    "status": 501,
                    "headers": [
                        (b"content-type", b"text/html; charset=utf-8"),
                        (b"content-length", str(len(body)).encode("latin-1")),
                        (b"access-control-allow-origin", origin.encode("latin-1")),
                        (b"access-control-allow-credentials", b"true"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return

        async def send_with_cors(message):
            if message["type"] == "http.response.start":
                mutable = MutableHeaders(scope=message)
                mutable["Access-Control-Allow-Origin"] = origin
                mutable["Access-Control-Allow-Credentials"] = "true"
                # OPTIONS is routed normally (responder's automatic-OPTIONS gives
                # 200 for defined routes, 404 otherwise); we layer on the
                # preflight headers here so undefined paths still 404.
                if method == "OPTIONS":
                    mutable["Access-Control-Allow-Methods"] = self.cors_methods
                    mutable["Access-Control-Max-Age"] = "3600"
                    requested = req_headers.get("access-control-request-headers")
                    if requested is not None:
                        mutable["Access-Control-Allow-Headers"] = requested
            await send(message)

        await self.app(scope, receive, send_with_cors)


api.add_middleware(HttpbinMiddleware)


# -------
# Helpers
# -------

_ROUTE_PATTERNS = {}


def route(
    pattern,
    methods=None,
    name=None,
    extra_patterns=(),
    include_in_schema=True,
    response_model=None,
    request_model=None,
    params_model=None,
):
    """Register a responder route and remember its pattern for ``url_for``.

    Delegates to ``api.route`` so responder's pydantic schema features
    (``response_model`` / ``request_model`` / ``params_model``) and OpenAPI
    registration apply. ``include_in_schema=False`` keeps the route working but
    hides it from the schema/Swagger UI, matching httpbin.org (which documents 52
    endpoints but still serves a few undocumented helper routes).
    """

    def decorator(handler):
        endpoint = name or handler.__name__
        _ROUTE_PATTERNS.setdefault(endpoint, pattern)
        handler = api.route(
            pattern,
            methods=methods,
            include_in_schema=include_in_schema,
            response_model=response_model,
            request_model=request_model,
            params_model=params_model,
        )(handler)
        for extra in extra_patterns:
            api.add_route(extra, handler, methods=methods)
        return handler

    return decorator


def url_for(endpoint, **values):
    """Flask-style ``url_for``: fill path params, append the rest as a query string."""
    pattern = _ROUTE_PATTERNS.get(endpoint)
    if pattern is None:
        return "#"

    values = dict(values)

    def replace(match):
        key = match.group(1).split(":")[0]
        if key in values:
            return str(values.pop(key))
        return match.group(0)

    path = re.sub(r"\{([^}]+)\}", replace, pattern)
    if values:
        path += "?" + urlencode(values)
    return path


def host_url(req):
    """Scheme + host for building absolute URLs to our own endpoints."""
    return "{0}://{1}".format(req.url.scheme, req.headers.get("host", ""))


# Flask's jsonify (with JSONIFY_PRETTYPRINT_REGULAR) used these separators:
# indent=2 with a trailing space after each structural comma.
JSON_SEPARATORS = (", ", ": ")


def dumps(data):
    """JSON, formatted byte-for-byte like the original Flask httpbin output."""
    return json.dumps(data, indent=2, sort_keys=True, separators=JSON_SEPARATORS) + "\n"


def jsonify(resp, *args, **kwargs):
    """Pretty-printed JSON body with a trailing newline (matches httpbin)."""
    if kwargs:
        data = kwargs
    elif len(args) == 1:
        data = args[0]
    else:
        data = list(args)
    resp.content = dumps(data).encode("utf-8")
    resp.mimetype = "application/json"
    return resp


def resource(filename):
    path = os.path.join(HERE, "templates", filename)
    with open(path, "rb") as f:
        return f.read()


def text_resource(filename):
    return resource(filename).decode("utf-8")


# ------
# Routes
# ------


@route("/legacy", methods=["GET"], include_in_schema=False)
def view_landing_page(req, resp):
    """Generates the landing page in the classic httpbin manpage layout."""
    try:
        resp.html = api.template(
            "index.html", url_for=url_for, tracking_enabled=TRACKING_ENABLED
        )
    except Exception:
        resp.html = "<h1>responder-httpbin</h1><p>See <a href='/'>the docs</a>.</p>"


@route("/html", methods=["GET"])
def view_html_page(req, resp):
    """Returns a simple HTML document.
    ---
    get:
        tags: [Response formats]
        summary: Returns a simple HTML document.
    """
    resp.html = text_resource("moby.html")


@route("/robots.txt", methods=["GET"])
def view_robots_page(req, resp):
    """Returns some robots.txt rules.
    ---
    get:
        tags: [Response formats]
        summary: Returns some robots.txt rules.
    """
    resp.content = ROBOT_TXT.encode("utf-8")
    resp.mimetype = "text/plain"
    resp.encoding = None  # suppress responder's non-standard `Encoding:` header


@route("/deny", methods=["GET"])
def view_deny_page(req, resp):
    """Returns page denied by robots.txt rules.
    ---
    get:
        tags: [Response formats]
        summary: Returns a page denied by the robots.txt rules.
    """
    resp.content = ANGRY_ASCII.encode("utf-8")
    resp.mimetype = "text/plain"
    resp.encoding = None


@route("/ip", methods=["GET"], response_model=models.IPResponse)
def view_origin(req, resp):
    """Returns the requester's IP Address.
    ---
    get:
        tags: [Request inspection]
        summary: Returns the requester's IP address.
    """
    jsonify(resp, origin=req.headers.get("X-Forwarded-For", _remote_addr(req)))


def _remote_addr(req):
    return req.client.host if req.client else None


@route("/uuid", methods=["GET"], response_model=models.UUIDResponse)
def view_uuid(req, resp):
    """Return a UUID4.
    ---
    get:
        tags: [Dynamic data]
        summary: Returns a UUID4.
    """
    jsonify(resp, uuid=str(uuid.uuid4()))


@route("/headers", methods=["GET"], response_model=models.HeadersResponse)
def view_headers(req, resp):
    """Return the incoming request's HTTP headers.
    ---
    get:
        tags: [Request inspection]
        summary: Returns the request's HTTP headers.
    """
    jsonify(resp, headers=get_headers(req))


@route("/user-agent", methods=["GET"], response_model=models.UserAgentResponse)
def view_user_agent(req, resp):
    """Return the incoming request's User-Agent header.
    ---
    get:
        tags: [Request inspection]
        summary: Returns the request's User-Agent header.
    """
    headers = get_headers(req)
    jsonify(resp, {"user-agent": headers.get("User-Agent")})


@route("/get", methods=["GET"], response_model=models.GetResponse)
async def view_get(req, resp):
    """The request's query parameters.
    ---
    get:
        tags: [HTTP Methods]
        summary: The request's query parameters.
    """
    jsonify(resp, await get_dict(req, "url", "args", "headers", "origin"))


@route(
    "/anything",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "TRACE"],
    extra_patterns=("/anything/{anything:path}",),
    response_model=models.AnythingResponse,
)
async def view_anything(req, resp, *, anything=None):
    """Returns anything passed in request data.
    ---
    get: {tags: [Anything], summary: Returns anything passed in request data.}
    post: {tags: [Anything]}
    put: {tags: [Anything]}
    delete: {tags: [Anything]}
    patch: {tags: [Anything]}
    trace: {tags: [Anything]}
    """
    jsonify(
        resp,
        await get_dict(
            req,
            "url",
            "args",
            "headers",
            "origin",
            "method",
            "form",
            "data",
            "files",
            "json",
        ),
    )


@route("/post", methods=["POST"], response_model=models.MethodResponse)
async def view_post(req, resp):
    """The request's POST parameters.
    ---
    post:
        tags: [HTTP Methods]
        summary: The request's POST parameters.
    """
    jsonify(
        resp,
        await get_dict(
            req, "url", "args", "form", "data", "origin", "headers", "files", "json"
        ),
    )


@route("/put", methods=["PUT"], response_model=models.MethodResponse)
async def view_put(req, resp):
    """The request's PUT parameters.
    ---
    put:
        tags: [HTTP Methods]
        summary: The request's PUT parameters.
    """
    jsonify(
        resp,
        await get_dict(
            req, "url", "args", "form", "data", "origin", "headers", "files", "json"
        ),
    )


@route("/patch", methods=["PATCH"], response_model=models.MethodResponse)
async def view_patch(req, resp):
    """The request's PATCH parameters.
    ---
    patch:
        tags: [HTTP Methods]
        summary: The request's PATCH parameters.
    """
    jsonify(
        resp,
        await get_dict(
            req, "url", "args", "form", "data", "origin", "headers", "files", "json"
        ),
    )


@route("/delete", methods=["DELETE"], response_model=models.MethodResponse)
async def view_delete(req, resp):
    """The request's DELETE parameters.
    ---
    delete:
        tags: [HTTP Methods]
        summary: The request's DELETE parameters.
    """
    jsonify(
        resp,
        await get_dict(
            req, "url", "args", "form", "data", "origin", "headers", "files", "json"
        ),
    )


@route("/gzip", methods=["GET"], response_model=models.EncodedResponse)
async def view_gzip_encoded_content(req, resp):
    """Returns GZip-encoded data.
    ---
    get:
        tags: [Response formats]
        summary: Returns GZip-encoded data.
    """
    data = await get_dict(req, "origin", "headers", method=str(req.method), gzipped=True)
    payload = dumps(data).encode("utf-8")
    resp.content = filters.gzip_compress(payload)
    resp.mimetype = "application/json"
    resp.headers["Content-Encoding"] = "gzip"
    resp.headers["Content-Length"] = str(len(resp.content))


@route("/deflate", methods=["GET"], response_model=models.EncodedResponse)
async def view_deflate_encoded_content(req, resp):
    """Returns Deflate-encoded data.
    ---
    get:
        tags: [Response formats]
        summary: Returns Deflate-encoded data.
    """
    data = await get_dict(req, "origin", "headers", method=str(req.method), deflated=True)
    payload = dumps(data).encode("utf-8")
    resp.content = filters.deflate_compress(payload)
    resp.mimetype = "application/json"
    resp.headers["Content-Encoding"] = "deflate"
    resp.headers["Content-Length"] = str(len(resp.content))


@route("/brotli", methods=["GET"], response_model=models.EncodedResponse)
async def view_brotli_encoded_content(req, resp):
    """Returns Brotli-encoded data.
    ---
    get:
        tags: [Response formats]
        summary: Returns Brotli-encoded data.
    """
    data = await get_dict(req, "origin", "headers", method=str(req.method), brotli=True)
    payload = dumps(data).encode("utf-8")
    compressed = filters.brotli_compress(payload)
    if compressed is None:
        set_status(resp, 501)
        resp.content = b"brotli support is not installed (pip install brotli)"
        resp.mimetype = "text/plain"
        return
    resp.content = compressed
    resp.mimetype = "application/json"
    resp.headers["Content-Encoding"] = "br"
    resp.headers["Content-Length"] = str(len(resp.content))


@route("/redirect/{n:int}", methods=["GET"])
def redirect_n_times(req, resp, *, n):
    """302 Redirects n times.
    ---
    get:
        tags: [Redirects]
        summary: 302 redirects n times.
    """
    assert n > 0

    absolute = req.params.get("absolute", "false").lower() == "true"

    resp.status_code = 302
    if n == 1:
        resp.headers["Location"] = (host_url(req) + "/get") if absolute else "/get"
        return

    if absolute:
        resp.headers["Location"] = host_url(req) + url_for(
            "absolute_redirect_n_times", n=n - 1
        )
    else:
        resp.headers["Location"] = url_for("relative_redirect_n_times", n=n - 1)


@route("/redirect-to", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "TRACE"])
def redirect_to(req, resp):
    """302/3XX Redirects to the given URL.
    ---
    get: {tags: [Redirects], summary: 302/3XX redirects to the given URL.}
    post: {tags: [Redirects]}
    put: {tags: [Redirects]}
    delete: {tags: [Redirects]}
    patch: {tags: [Redirects]}
    trace: {tags: [Redirects]}
    """
    # The original wrapped args in a case-insensitive dict.
    args = {key.lower(): value for key, value in query_pairs(req)}

    resp.status_code = 302
    status_code = args.get("status_code")
    if status_code is not None:
        code = int(status_code)
        if 300 <= code < 400:
            resp.status_code = code
    # Set the Location header to the exact string supplied (no normalization).
    # Emit the raw UTF-8 bytes (decoded as latin-1) so non-ASCII URLs don't
    # crash Starlette's latin-1 header encoder.
    resp.headers["Location"] = args["url"].encode("utf-8").decode("latin-1")


@route("/relative-redirect/{n:int}", methods=["GET"])
def relative_redirect_n_times(req, resp, *, n):
    """Relatively 302 Redirects n times.
    ---
    get:
        tags: [Redirects]
        summary: Relative 302 redirects n times.
    """
    assert n > 0
    resp.status_code = 302
    if n == 1:
        resp.headers["Location"] = "/get"
        return
    resp.headers["Location"] = url_for("relative_redirect_n_times", n=n - 1)


@route("/absolute-redirect/{n:int}", methods=["GET"])
def absolute_redirect_n_times(req, resp, *, n):
    """Absolutely 302 Redirects n times.
    ---
    get:
        tags: [Redirects]
        summary: Absolute 302 redirects n times.
    """
    assert n > 0
    resp.status_code = 302
    if n == 1:
        resp.headers["Location"] = host_url(req) + "/get"
        return
    resp.headers["Location"] = host_url(req) + url_for(
        "absolute_redirect_n_times", n=n - 1
    )


@route("/stream/{n:int}", methods=["GET"], response_model=models.StreamResponse)
async def stream_n_messages(req, resp, *, n):
    """Stream n JSON responses.
    ---
    get:
        tags: [Dynamic data]
        summary: Streams n JSON responses (newline-delimited).
    """
    data = await get_dict(req, "url", "args", "headers", "origin")
    n = min(n, 100)
    resp.mimetype = "application/json"

    @resp.stream
    async def body():
        for i in range(n):
            data["id"] = i
            # Compact, insertion-order JSON lines (matches the original /stream).
            yield (json.dumps(data) + "\n").encode("utf-8")


@route("/status/{codes}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "TRACE"])
def view_status_code(req, resp, *, codes):
    """Return status code or random status code if more than one are given.
    ---
    get: {tags: [Status codes], summary: Returns the given (or weighted-random) status code.}
    post: {tags: [Status codes]}
    put: {tags: [Status codes]}
    delete: {tags: [Status codes]}
    patch: {tags: [Status codes]}
    trace: {tags: [Status codes]}
    """
    if "," not in codes:
        try:
            code = int(codes)
        except ValueError:
            resp.status_code = 400
            resp.content = b"Invalid status code"
            resp.mimetype = "text/html; charset=utf-8"
            return
        set_status(resp, code)
        return

    choices = []
    for choice in codes.split(","):
        if ":" not in choice:
            code = choice
            weight = 1
        else:
            code, weight = choice.split(":")
        try:
            choices.append((int(code), float(weight)))
        except ValueError:
            resp.status_code = 400
            resp.content = b"Invalid status code"
            resp.mimetype = "text/html; charset=utf-8"
            return

    set_status(resp, weighted_choice(choices))


@route("/response-headers", methods=["GET", "POST"])
def response_headers(req, resp):
    """Returns a set of response headers from the query string.
    ---
    get: {tags: [Response inspection], summary: Returns response headers from the query string.}
    post: {tags: [Response inspection]}
    """
    multi = query_multi(req)

    # responder's response headers are a plain dict (no repeated keys), so we
    # collapse repeated query values into an RFC 7230 comma-joined list.
    for key, values in multi.items():
        resp.headers[key] = ",".join(values)

    def body_dict(content_length=None):
        d = {}
        for key, values in multi.items():
            d[key] = values[0] if len(values) == 1 else values
        d["Content-Type"] = "application/json"
        if content_length is not None:
            d["Content-Length"] = str(content_length)
        return d

    body = dumps(body_dict())
    for _ in range(10):  # fixed-point on the self-referential Content-Length
        candidate = dumps(body_dict(len(body.encode("utf-8"))))
        if candidate == body:
            break
        body = candidate

    encoded = body.encode("utf-8")
    resp.content = encoded
    resp.mimetype = "application/json"
    resp.headers["Content-Length"] = str(len(encoded))


def _set_cookie(resp, key, value="", **extra):
    """set_cookie with Flask's old defaults (plain, JS-readable cookies)."""
    resp.set_cookie(key, value=value, httponly=False, samesite=None, **extra)


@route("/cookies", methods=["GET"], response_model=models.CookiesResponse)
def view_cookies(req, resp, hide_env=True):
    """Returns cookie data.
    ---
    get:
        tags: [Cookies]
        summary: Returns the cookies sent in the request.
    """
    cookies = dict(req.cookies.items())
    if hide_env and not query_has(req, "show_env"):
        for key in ENV_COOKIES:
            cookies.pop(key, None)
    jsonify(resp, cookies=cookies)


@route("/forms/post", methods=["GET"], include_in_schema=False)
def view_forms_post(req, resp):
    """Simple HTML form."""
    resp.html = text_resource("forms-post.html")


@route("/cookies/set/{name}/{value}", methods=["GET"])
def set_cookie(req, resp, *, name, value):
    """Sets a cookie and redirects to the cookie list.
    ---
    get:
        tags: [Cookies]
        summary: Sets a cookie and redirects to the cookie list.
    """
    resp.status_code = 302
    resp.headers["Location"] = url_for("view_cookies")
    _set_cookie(resp, name, value=value, secure=secure_cookie(req))


@route("/cookies/set", methods=["GET"])
def set_cookies(req, resp):
    """Sets cookie(s) as provided by the query string and redirects to cookie list.
    ---
    get:
        tags: [Cookies]
        summary: Sets cookies from the query string and redirects to the cookie list.
    """
    resp.status_code = 302
    resp.headers["Location"] = url_for("view_cookies")
    for key, value in query_pairs(req):
        _set_cookie(resp, key, value=value, secure=secure_cookie(req))


@route("/cookies/delete", methods=["GET"])
def delete_cookies(req, resp):
    """Deletes cookie(s) as provided by the query string and redirects to cookie list.
    ---
    get:
        tags: [Cookies]
        summary: Deletes cookies named in the query string and redirects to the cookie list.
    """
    resp.status_code = 302
    resp.headers["Location"] = url_for("view_cookies")
    for key, _value in query_pairs(req):
        _set_cookie(
            resp, key, value="", max_age=0, expires="Thu, 01 Jan 1970 00:00:00 GMT"
        )


@route("/basic-auth/{user}/{passwd}", methods=["GET"], response_model=models.AuthResponse)
def basic_auth(req, resp, *, user, passwd):
    """Prompts the user for authorization using HTTP Basic Auth.
    ---
    get:
        tags: [Auth]
        summary: Challenges HTTP Basic Auth.
    """
    if not check_basic_auth(req, user, passwd):
        set_status(resp, 401)
        return
    jsonify(resp, authenticated=True, user=user)


@route("/hidden-basic-auth/{user}/{passwd}", methods=["GET"], response_model=models.AuthResponse)
def hidden_basic_auth(req, resp, *, user, passwd):
    """Prompts the user for authorization using HTTP Basic Auth, 404 on failure.
    ---
    get:
        tags: [Auth]
        summary: 404'd HTTP Basic Auth.
    """
    if not check_basic_auth(req, user, passwd):
        set_status(resp, 404)
        return
    jsonify(resp, authenticated=True, user=user)


@route("/bearer", methods=["GET"], response_model=models.BearerResponse)
def bearer_auth(req, resp):
    """Prompts the user for authorization using bearer authentication.
    ---
    get:
        tags: [Auth]
        summary: Challenges Bearer Auth.
    """
    authorization = req.headers.get("Authorization")
    if not (authorization and authorization.startswith("Bearer ")):
        resp.status_code = 401
        resp.headers["WWW-Authenticate"] = "Bearer"
        resp.content = b""
        return
    token = authorization[len("Bearer ") :]
    jsonify(resp, authenticated=True, token=token)


@route("/digest-auth/{qop}/{user}/{passwd}", methods=["GET"], response_model=models.AuthResponse)
async def digest_auth_md5(req, resp, *, qop, user, passwd):
    """Prompts the user for authorization using Digest Auth.
    ---
    get:
        tags: [Auth]
        summary: Challenges HTTP Digest Auth.
    """
    await _digest_auth(req, resp, qop, user, passwd, "MD5", "never")


@route("/digest-auth/{qop}/{user}/{passwd}/{algorithm}", methods=["GET"], response_model=models.AuthResponse)
async def digest_auth_nostale(req, resp, *, qop, user, passwd, algorithm):
    """Prompts the user for authorization using Digest Auth + Algorithm.
    ---
    get:
        tags: [Auth]
        summary: Challenges HTTP Digest Auth with a chosen algorithm.
    """
    await _digest_auth(req, resp, qop, user, passwd, algorithm, "never")


@route("/digest-auth/{qop}/{user}/{passwd}/{algorithm}/{stale_after}", methods=["GET"], response_model=models.AuthResponse)
async def digest_auth(req, resp, *, qop, user, passwd, algorithm, stale_after):
    """Prompts the user for authorization using Digest Auth + Algorithm, with stale_after.
    ---
    get:
        tags: [Auth]
        summary: Challenges HTTP Digest Auth, with a stale_after window.
    """
    await _digest_auth(req, resp, qop, user, passwd, algorithm, stale_after)


async def _digest_auth(req, resp, qop, user, passwd, algorithm, stale_after):
    require_cookie_handling = req.params.get("require-cookie", "").lower() in (
        "1",
        "t",
        "true",
    )
    if algorithm not in ("MD5", "SHA-256", "SHA-512"):
        algorithm = "MD5"

    if qop not in ("auth", "auth-int"):
        qop = None

    authorization = req.headers.get("Authorization")
    credentials = None
    if authorization:
        credentials = parse_authorization_header(authorization)

    if (
        not authorization
        or not credentials
        or credentials.type.lower() != "digest"
        or (require_cookie_handling and "Cookie" not in req.headers)
    ):
        _digest_challenge(req, resp, qop, algorithm)
        _set_cookie(resp, "stale_after", value=stale_after)
        _set_cookie(resp, "fake", value="fake_value")
        return

    if require_cookie_handling and req.cookies.get("fake") != "fake_value":
        jsonify(resp, {"errors": ["missing cookie set on challenge"]})
        _set_cookie(resp, "fake", value="fake_value")
        resp.status_code = 403
        return

    current_nonce = credentials.get("nonce")

    stale_after_value = None
    if "stale_after" in req.cookies:
        stale_after_value = req.cookies.get("stale_after")

    if (
        "last_nonce" in req.cookies
        and current_nonce == req.cookies.get("last_nonce")
        or stale_after_value == "0"
    ):
        _digest_challenge(req, resp, qop, algorithm, True)
        _set_cookie(resp, "stale_after", value=stale_after)
        _set_cookie(resp, "last_nonce", value=current_nonce)
        _set_cookie(resp, "fake", value="fake_value")
        return

    body = await req.content
    if not check_digest_auth(req, user, passwd, body):
        _digest_challenge(req, resp, qop, algorithm, False)
        _set_cookie(resp, "stale_after", value=stale_after)
        _set_cookie(resp, "last_nonce", value=current_nonce)
        _set_cookie(resp, "fake", value="fake_value")
        return

    jsonify(resp, authenticated=True, user=user)
    _set_cookie(resp, "fake", value="fake_value")
    if stale_after_value:
        _set_cookie(resp, "stale_after", value=next_stale_after_value(stale_after_value))


def _digest_challenge(req, resp, qop, algorithm, stale=False):
    resp.status_code = 401
    resp.content = b""
    resp.headers["WWW-Authenticate"] = digest_challenge_header(
        req, qop, algorithm, stale
    )


@route(
    "/delay/{delay}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "TRACE"],
    response_model=models.MethodResponse,
)
async def delay_response(req, resp, *, delay):
    """Returns a delayed response (max of 10 seconds).
    ---
    get: {tags: [Dynamic data], summary: Returns a delayed response (max 10s).}
    post: {tags: [Dynamic data]}
    put: {tags: [Dynamic data]}
    delete: {tags: [Dynamic data]}
    patch: {tags: [Dynamic data]}
    trace: {tags: [Dynamic data]}
    """
    delay = min(float(delay), 10)
    await asyncio.sleep(delay)
    jsonify(
        resp,
        await get_dict(req, "url", "args", "form", "data", "origin", "headers", "files"),
    )


@route("/drip", methods=["GET"])
async def drip(
    req,
    resp,
    *,
    numbytes: int = Query(10, description="Number of bytes to stream."),
    duration: float = Query(2, description="Seconds over which to drip the bytes."),
    delay: float = Query(0, description="Initial delay in seconds before streaming."),
    code: int = Query(200, description="HTTP status code to return."),
):
    """Drips data over a duration after an optional initial delay.
    ---
    get:
        tags: [Dynamic data]
        summary: Drips data over a duration after an optional initial delay.
    """
    numbytes = min(numbytes, 10 * 1024 * 1024)

    if numbytes <= 0:
        resp.status_code = 400
        resp.content = b"number of bytes must be positive"
        resp.mimetype = "text/html; charset=utf-8"
        return

    if delay > 0:
        await asyncio.sleep(delay)

    pause = duration / numbytes

    resp.status_code = code
    resp.mimetype = "application/octet-stream"
    resp.headers["Content-Length"] = str(numbytes)

    @resp.stream
    async def body():
        for _ in range(numbytes):
            yield b"*"
            await asyncio.sleep(pause)


@route("/base64/{value}", methods=["GET"])
def decode_base64(req, resp, *, value):
    """Decodes base64url-encoded string.
    ---
    get:
        tags: [Dynamic data]
        summary: Decodes a base64url-encoded string.
    """
    encoded = value.encode("utf-8")
    try:
        decoded = base64.urlsafe_b64decode(encoded).decode("utf-8")
    except Exception:
        decoded = "Incorrect Base64 data try: SFRUUEJJTiBpcyBhd2Vzb21l"
    # Flask returned a bare str -> text/html; charset=utf-8.
    resp.content = decoded.encode("utf-8")
    resp.headers["Content-Type"] = "text/html; charset=utf-8"


@route("/cache", methods=["GET"], response_model=models.GetResponse)
async def cache(req, resp):
    """Returns a 304 if If-Modified-Since or If-None-Match is present; otherwise a normal GET.
    ---
    get:
        tags: [Response inspection]
        summary: Returns 200 (with caching headers) unless a conditional header yields 304.
    """
    is_conditional = req.headers.get("If-Modified-Since") or req.headers.get(
        "If-None-Match"
    )
    if is_conditional is None:
        jsonify(resp, await get_dict(req, "url", "args", "headers", "origin"))
        resp.headers["Last-Modified"] = http_date()
        resp.headers["ETag"] = uuid.uuid4().hex
    else:
        set_status(resp, 304)


@route("/etag/{etag}", methods=["GET"], response_model=models.GetResponse)
async def etag(req, resp, *, etag):
    """Responds to If-None-Match / If-Match conditional headers for the given etag.
    ---
    get:
        tags: [Response inspection]
        summary: Handles If-None-Match / If-Match for the given etag.
    """
    if_none_match = parse_multi_value_header(req.headers.get("If-None-Match"))
    if_match = parse_multi_value_header(req.headers.get("If-Match"))

    if if_none_match:
        if etag in if_none_match or "*" in if_none_match:
            set_status(resp, 304)
            resp.headers["ETag"] = etag
            return
    elif if_match:
        if etag not in if_match and "*" not in if_match:
            set_status(resp, 412)
            return

    jsonify(resp, await get_dict(req, "url", "args", "headers", "origin"))
    resp.headers["ETag"] = etag


@route("/cache/{value:int}", methods=["GET"], response_model=models.GetResponse)
async def cache_control(req, resp, *, value):
    """Sets a Cache-Control header for n seconds.
    ---
    get:
        tags: [Response inspection]
        summary: Sets a Cache-Control header for n seconds.
    """
    jsonify(resp, await get_dict(req, "url", "args", "headers", "origin"))
    resp.headers["Cache-Control"] = "public, max-age={0}".format(value)


@route("/encoding/utf8", methods=["GET"])
def encoding(req, resp):
    """Returns a UTF-8 encoded body.
    ---
    get:
        tags: [Response formats]
        summary: Returns a UTF-8 encoded body.
    """
    resp.content = resource("UTF-8-demo.txt")
    resp.mimetype = "text/html; charset=utf-8"


@route("/bytes/{n:int}", methods=["GET"])
def random_bytes(req, resp, *, n, seed: int = Query(None, description="RNG seed.")):
    """Returns n random bytes generated with given seed.
    ---
    get:
        tags: [Dynamic data]
        summary: Returns n random bytes (optionally seeded).
    """
    n = min(n, 100 * 1024)  # 100KB limit

    if seed is not None:
        random.seed(seed)

    resp.content = bytes(bytearray(random.randint(0, 255) for _ in range(n)))
    resp.mimetype = "application/octet-stream"


@route("/stream-bytes/{n:int}", methods=["GET"])
async def stream_random_bytes(
    req,
    resp,
    *,
    n,
    seed: int = Query(None, description="RNG seed."),
    chunk_size: int = Query(None, description="Bytes per streamed chunk."),
):
    """Streams n random bytes generated with given seed, at given chunk size per packet.
    ---
    get:
        tags: [Dynamic data]
        summary: Streams n random bytes (optionally seeded) in chunks.
    """
    n = min(n, 100 * 1024)  # 100KB limit

    if seed is not None:
        random.seed(seed)

    chunk_size = max(1, chunk_size) if chunk_size is not None else 10 * 1024

    resp.mimetype = "application/octet-stream"

    @resp.stream
    async def body():
        chunks = bytearray()
        for _ in range(n):
            chunks.append(random.randint(0, 255))
            if len(chunks) == chunk_size:
                yield bytes(chunks)
                chunks = bytearray()
        if chunks:
            yield bytes(chunks)


@route("/range/{numbytes:int}", methods=["GET"])
async def range_request(
    req,
    resp,
    *,
    numbytes,
    duration: float = Query(0, description="Seconds over which to drip the range."),
    chunk_size: int = Query(None, description="Bytes per streamed chunk."),
):
    """Streams numbytes bytes, honoring a Range header to select a subset.
    ---
    get:
        tags: [Dynamic data]
        summary: Streams numbytes bytes, honoring a Range header.
    """
    if numbytes <= 0 or numbytes > (100 * 1024):
        resp.status_code = 404
        resp.content = b"number of bytes must be in the range (0, 102400]"
        resp.headers["ETag"] = "range%d" % numbytes
        resp.headers["Accept-Ranges"] = "bytes"
        return

    chunk_size = max(1, chunk_size) if chunk_size is not None else 10 * 1024
    pause_per_byte = duration / numbytes

    first_byte_pos, last_byte_pos = get_request_range(req.headers, numbytes)
    range_length = (last_byte_pos + 1) - first_byte_pos

    if (
        first_byte_pos > last_byte_pos
        or first_byte_pos not in range(0, numbytes)
        or last_byte_pos not in range(0, numbytes)
    ):
        resp.status_code = 416
        resp.headers["ETag"] = "range%d" % numbytes
        resp.headers["Accept-Ranges"] = "bytes"
        resp.headers["Content-Range"] = "bytes */%d" % numbytes
        resp.headers["Content-Length"] = "0"
        resp.content = b""
        return

    resp.mimetype = "application/octet-stream"
    resp.headers["ETag"] = "range%d" % numbytes
    resp.headers["Accept-Ranges"] = "bytes"
    resp.headers["Content-Length"] = str(range_length)
    resp.headers["Content-Range"] = "bytes %d-%d/%d" % (
        first_byte_pos,
        last_byte_pos,
        numbytes,
    )
    resp.status_code = 200 if (
        first_byte_pos == 0 and last_byte_pos == (numbytes - 1)
    ) else 206

    @resp.stream
    async def body():
        chunks = bytearray()
        for i in range(first_byte_pos, last_byte_pos + 1):
            # Predictable, request-stable data generation.
            chunks.append(ord("a") + (i % 26))
            if len(chunks) == chunk_size:
                yield bytes(chunks)
                if pause_per_byte:
                    await asyncio.sleep(pause_per_byte * chunk_size)
                chunks = bytearray()
        if chunks:
            if pause_per_byte:
                await asyncio.sleep(pause_per_byte * len(chunks))
            yield bytes(chunks)


@route("/links/{n:int}/{offset:int}", methods=["GET"])
def link_page(req, resp, *, n, offset):
    """Generate a page containing n links to other pages which do the same.
    ---
    get:
        tags: [Dynamic data]
        summary: Returns a page of n HTML links.
    """
    n = min(max(1, n), 200)  # 1..200 links

    link = "<a href='{0}'>{1}</a> "
    html = ["<html><head><title>Links</title></head><body>"]
    for i in range(n):
        if i == offset:
            html.append("{0} ".format(i))
        else:
            html.append(link.format(url_for("link_page", n=n, offset=i), i))
    html.append("</body></html>")
    resp.html = "".join(html)


@route("/links/{n:int}", methods=["GET"], include_in_schema=False)
def links(req, resp, *, n):
    """Redirect to first links page."""
    resp.status_code = 302
    resp.headers["Location"] = url_for("link_page", n=n, offset=0)


@route("/image", methods=["GET"])
def image(req, resp):
    """Returns a simple image of the type suggested by the Accept header.
    ---
    get:
        tags: [Images]
        summary: Returns an image matching the Accept header.
    """
    headers = get_headers(req)
    if "accept" not in headers:
        _serve_image(resp, "images/pig_icon.png", "image/png")
        return

    accept = headers["accept"].lower()
    if "image/webp" in accept:
        _serve_image(resp, "images/wolf_1.webp", "image/webp")
    elif "image/svg+xml" in accept:
        _serve_image(resp, "images/svg_logo.svg", "image/svg+xml")
    elif "image/jpeg" in accept:
        _serve_image(resp, "images/jackal.jpg", "image/jpeg")
    elif "image/png" in accept or "image/*" in accept:
        _serve_image(resp, "images/pig_icon.png", "image/png")
    else:
        set_status(resp, 406)


def _serve_image(resp, filename, content_type):
    resp.content = resource(filename)
    resp.mimetype = content_type


@route("/image/png", methods=["GET"])
def image_png(req, resp):
    """Returns a simple PNG image.
    ---
    get:
        tags: [Images]
        summary: Returns a simple PNG image.
    """
    _serve_image(resp, "images/pig_icon.png", "image/png")


@route("/image/jpeg", methods=["GET"])
def image_jpeg(req, resp):
    """Returns a simple JPEG image.
    ---
    get:
        tags: [Images]
        summary: Returns a simple JPEG image.
    """
    _serve_image(resp, "images/jackal.jpg", "image/jpeg")


@route("/image/webp", methods=["GET"])
def image_webp(req, resp):
    """Returns a simple WEBP image.
    ---
    get:
        tags: [Images]
        summary: Returns a simple WebP image.
    """
    _serve_image(resp, "images/wolf_1.webp", "image/webp")


@route("/image/svg", methods=["GET"])
def image_svg(req, resp):
    """Returns a simple SVG image.
    ---
    get:
        tags: [Images]
        summary: Returns a simple SVG image.
    """
    _serve_image(resp, "images/svg_logo.svg", "image/svg+xml")


@route("/xml", methods=["GET"])
def xml(req, resp):
    """Returns a simple XML document.
    ---
    get:
        tags: [Response formats]
        summary: Returns a simple XML document.
    """
    resp.content = resource("sample.xml")
    resp.mimetype = "application/xml"


@route("/json", methods=["GET"], response_model=models.JsonResponse)
def a_json_endpoint(req, resp):
    """Returns a simple JSON document.
    ---
    get:
        tags: [Response formats]
        summary: Returns a simple JSON document.
    """
    jsonify(
        resp,
        slideshow={
            "title": "Sample Slide Show",
            "date": "date of publication",
            "author": "Yours Truly",
            "slides": [
                {"type": "all", "title": "Wake up to WonderWidgets!"},
                {
                    "type": "all",
                    "title": "Overview",
                    "items": [
                        "Why <em>WonderWidgets</em> are great",
                        "Who <em>buys</em> WonderWidgets",
                    ],
                },
            ],
        },
    )


# Backwards-compatible alias for the ASGI app object.
app = api


if __name__ == "__main__":
    # Dev server (responder's built-in, uvicorn-based). Production uses granian
    # via the Dockerfile / Procfile. Honors the PORT env var if set.
    api.run(port=5000)

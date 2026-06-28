# -*- coding: utf-8 -*-

"""
httpbin.helpers
~~~~~~~~~~~~~~~

Helper functions for responder-httpbin.

These were originally written against Flask's global ``request`` object. For the
responder port they take an explicit ``req`` (a ``responder.Request``) so they
stay framework-light and easy to test.
"""

import base64
import json
import os
import re
import time
from email.utils import formatdate
from hashlib import md5, sha256, sha512
from urllib.parse import urlparse, urlunparse, parse_qsl

from .structures import CaseInsensitiveDict


ASCII_ART = """
    -=[ teapot ]=-

       _...._
     .'  _ _ `.
    | ."` ^ `". _,
    \\_;`"---"`|//
      |       ;/
      \\_     _/
        `\"\"\"`
"""

REDIRECT_LOCATION = "/redirect/1"

ENV_HEADERS = (
    "X-Varnish",
    "X-Request-Start",
    "X-Heroku-Queue-Depth",
    "X-Real-Ip",
    "X-Forwarded-Proto",
    "X-Forwarded-Protocol",
    "X-Forwarded-Ssl",
    "X-Heroku-Queue-Wait-Time",
    "X-Forwarded-For",
    "X-Heroku-Dynos-In-Use",
    "X-Forwarded-Protocol",
    "X-Forwarded-Port",
    "X-Request-Id",
    "Via",
    "Total-Route-Time",
    "Connect-Time",
)

ROBOT_TXT = """User-agent: *
Disallow: /deny
"""

ACCEPTED_MEDIA_TYPES = [
    "image/webp",
    "image/svg+xml",
    "image/jpeg",
    "image/png",
    "image/*",
]

ANGRY_ASCII = """
          .-''''''-.
        .' _      _ '.
       /   O      O   \\
      :                :
      |                |
      :       __       :
       \\  .-"`  `"-.  /
        '.          .'
          '-......-'
     YOU SHOULDN'T BE HERE
"""


# ----------------------
# Generic request access
# ----------------------


def http_date():
    """RFC 1123 date string for the current time (replaces werkzeug.http.http_date)."""
    return formatdate(timeval=None, localtime=False, usegmt=True)


def _canonical_header_name(name):
    """Title-case an HTTP header name segment-by-segment.

    ASGI lowercases header names, but httpbin echoes them in canonical form
    (``Content-Type``, ``User-Agent``...), so we rebuild that casing.
    """
    return "-".join(part.capitalize() for part in name.split("-"))


def json_safe(string, content_type="application/octet-stream"):
    """Returns JSON-safe version of `string`.

    If `string` is a Unicode string or a valid UTF-8, it is returned unmodified,
    as it can safely be encoded to JSON string.

    If `string` contains raw/binary data, it is Base64-encoded, formatted and
    returned according to "data" URL scheme (RFC2397). Since JSON is not
    suitable for binary data, some additional encoding was necessary; "data"
    URL scheme was chosen for its simplicity.
    """
    if isinstance(string, str):
        string = string.encode("utf-8")
    try:
        string = string.decode("utf-8")
        json.dumps(string)
        return string
    except (ValueError, TypeError):
        return b"".join(
            [
                b"data:",
                content_type.encode("utf-8"),
                b";base64,",
                base64.b64encode(string),
            ]
        ).decode("utf-8")


def semiflatten(multi):
    """Convert a mapping of key -> list-of-values into a regular dict.

    If there is more than one value for a key the result keeps the list,
    otherwise it has the plain scalar value.
    """
    if not multi:
        return {}
    result = {}
    for key, values in multi.items():
        result[key] = values[0] if len(values) == 1 else list(values)
    return result


def query_pairs(req):
    """Return the request's query string as ``[(key, value), ...]``.

    Uses ``keep_blank_values=True`` to match werkzeug; responder's ``req.params``
    drops blank-valued keys (``?show_env``, ``?foo=``), which httpbin keeps.
    """
    return parse_qsl(req.url.query, keep_blank_values=True)


def query_multi(req):
    """Return ``{key: [values...]}`` for the request's query string."""
    out = {}
    for key, value in query_pairs(req):
        out.setdefault(key, []).append(value)
    return out


def query_flat(req):
    """Return ``{key: last_value}`` for the request's query string."""
    out = {}
    for key, value in query_pairs(req):
        out[key] = value
    return out


def query_has(req, key):
    """True if ``key`` appears in the query string (even blank-valued)."""
    return any(k == key for k, _ in query_pairs(req))


def get_headers(req, hide_env=True):
    """Returns a CaseInsensitiveDict of the request's headers (canonical-cased).

    Duplicate headers are comma-combined to match WSGI/werkzeug (responder's
    ``req.headers`` keeps only the last value).
    """
    show_env = query_has(req, "show_env")
    env_lower = {h.lower() for h in ENV_HEADERS}

    headers = CaseInsensitiveDict()
    for raw_key, raw_value in req._starlette.headers.raw:  # preserves duplicates
        key = raw_key.decode("latin-1")
        value = raw_value.decode("latin-1")
        if hide_env and not show_env and key.lower() in env_lower:
            continue
        canon = _canonical_header_name(key)
        if canon in headers:
            headers[canon] = headers[canon] + ", " + value
        else:
            headers[canon] = value
    return headers


def get_url(req):
    """Absolute URL of the request, honoring proxy ``X-Forwarded-*`` headers."""
    protocol = req.headers.get("X-Forwarded-Proto") or req.headers.get(
        "X-Forwarded-Protocol"
    )
    if protocol is None and req.headers.get("X-Forwarded-Ssl") == "on":
        protocol = "https"
    if protocol is None:
        return req.full_url
    url = list(urlparse(req.full_url))
    url[0] = protocol
    return urlunparse(url)


def get_origin(req):
    """Best-effort client IP address."""
    forwarded = req.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded
    return req.client.host if req.client else None


async def _parse_body(req):
    """Parse the request body the way werkzeug used to: returns
    ``(raw_data_bytes, form_dict, files_dict)``.

    For form / multipart requests ``raw_data_bytes`` is empty (the stream was
    consumed for form parsing), mirroring Flask's ``request.data`` behavior.
    """
    content_type = (req.headers.get("content-type") or "").lower()

    if "multipart/form-data" in content_type:
        form, files = {}, {}
        # Use Starlette's multi-aware FormData directly; responder's
        # req.media(format="files") returns a plain dict that drops repeated
        # field/file names (keeping only the last value).
        form_obj = await req._starlette.form()
        try:
            for key, value in form_obj.multi_items():
                if hasattr(value, "read"):  # an UploadFile
                    content = await value.read()
                    ct = value.content_type or "application/octet-stream"
                    _append_multi(files, key, json_safe(content, ct))
                else:
                    _append_multi(form, key, value)
        finally:
            await form_obj.close()
        return b"", _flatten_appended(form), _flatten_appended(files)

    if "application/x-www-form-urlencoded" in content_type:
        raw = await req.content
        pairs = parse_qsl(raw.decode("utf-8", "replace"), keep_blank_values=True)
        form = {}
        for key, value in pairs:
            form.setdefault(key, []).append(value)
        return b"", semiflatten(form), {}

    raw = await req.content
    return raw, {}, {}


def _append_multi(store, key, value):
    store.setdefault(key, []).append(value)


def _flatten_appended(store):
    return {k: (v[0] if len(v) == 1 else v) for k, v in store.items()}


async def get_dict(req, *keys, **extras):
    """Returns a dict of the requested request attributes.

    Mirrors the original httpbin ``get_dict`` but is async (responder reads the
    body asynchronously) and only touches the body when a body-derived key is
    requested.
    """
    _keys = ("url", "args", "form", "data", "origin", "headers", "files", "json", "method")
    assert all(k in _keys for k in keys)

    need_body = any(k in keys for k in ("form", "data", "files", "json"))
    raw, form, files = (b"", {}, {})
    if need_body:
        raw, form, files = await _parse_body(req)

    try:
        _json = json.loads(raw.decode("utf-8")) if raw else None
    except (ValueError, TypeError):
        _json = None

    d = {
        "url": get_url(req),
        "args": semiflatten(query_multi(req)),
        "form": form,
        "data": json_safe(raw),
        "origin": get_origin(req),
        "headers": get_headers(req),
        "files": files,
        "json": _json,
        "method": str(req.method),
    }

    out = {key: d.get(key) for key in keys}
    out.update(extras)
    return out


# -----------
# Status codes
# -----------


def set_status(resp, code):
    """Set ``resp`` to a canned response for ``code`` (mirrors httpbin's map)."""
    redirect = dict(headers=dict(location=REDIRECT_LOCATION))

    code_map = {
        301: redirect,
        302: redirect,
        303: redirect,
        304: dict(data=""),
        305: redirect,
        307: redirect,
        401: dict(headers={"WWW-Authenticate": 'Basic realm="Fake Realm"'}),
        402: dict(
            data="Fuck you, pay me!",
            headers={"x-more-info": "http://vimeo.com/22053820"},
        ),
        406: dict(
            data=json.dumps(
                {
                    "message": "Client did not request a supported media type.",
                    "accept": ACCEPTED_MEDIA_TYPES,
                }
            ),
            headers={"Content-Type": "application/json"},
        ),
        407: dict(headers={"Proxy-Authenticate": 'Basic realm="Fake Realm"'}),
        418: dict(  # I'm a teapot!
            data=ASCII_ART,
            headers={"x-more-info": "http://tools.ietf.org/html/rfc2324"},
        ),
    }

    resp.status_code = code
    resp.content = b""

    if code in code_map:
        m = code_map[code]
        if "data" in m:
            data = m["data"]
            resp.content = data.encode("utf-8") if isinstance(data, str) else data
        if "headers" in m:
            for key, value in m["headers"].items():
                resp.headers[key] = value
    elif code != 304:
        # Flask's make_response() defaults to text/html; werkzeug strips entity
        # headers on 304, so only set it for other non-mapped codes.
        resp.mimetype = "text/html; charset=utf-8"
    return resp


# ----------
# Basic auth
# ----------


class Authorization(dict):
    """Tiny stand-in for werkzeug's Authorization object."""

    def __init__(self, auth_type, data):
        super().__init__(data)
        self.type = auth_type


def parse_dict_header(value):
    """Parse a ``key=value, key2="value2"`` header into a dict."""
    result = {}
    for item in _split_header_words(value):
        if "=" not in item:
            result[item] = None
            continue
        name, val = item.split("=", 1)
        name = name.strip()
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] == '"':
            val = val[1:-1]
        result[name] = val
    return result


def _split_header_words(value):
    """Split a comma-separated header, respecting double-quoted sections."""
    parts = []
    current = []
    in_quotes = False
    for char in value:
        if char == '"':
            in_quotes = not in_quotes
            current.append(char)
        elif char == "," and not in_quotes:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    if current:
        parts.append("".join(current).strip())
    return [p for p in parts if p]


def parse_authorization_header(value):
    """Parse an ``Authorization`` header (Basic or Digest)."""
    if not value:
        return None
    try:
        auth_type, auth_info = value.split(None, 1)
    except ValueError:
        return None
    auth_type = auth_type.lower()

    if auth_type == "basic":
        try:
            # latin-1 (like werkzeug) maps every byte and never raises, so
            # non-UTF-8 credentials authenticate the same way they did on Flask.
            decoded = base64.b64decode(auth_info).decode("latin-1")
            username, password = decoded.split(":", 1)
        except Exception:
            return None
        return Authorization("basic", {"username": username, "password": password})

    if auth_type == "digest":
        params = parse_dict_header(auth_info)
        required = ("username", "realm", "nonce", "uri", "response")
        if any(params.get(k) is None for k in required):
            return None
        if params.get("qop") and (not params.get("nc") or not params.get("cnonce")):
            return None
        return Authorization("digest", params)

    return None


def check_basic_auth(req, user, passwd):
    """Checks user authentication using HTTP Basic Auth."""
    auth = parse_authorization_header(req.headers.get("Authorization"))
    return bool(
        auth
        and auth.type == "basic"
        and auth.get("username") == user
        and auth.get("password") == passwd
    )


# -----------
# Digest auth
# -----------
# qop is a quality of protection


def H(data, algorithm):
    if algorithm == "SHA-256":
        return sha256(data).hexdigest()
    elif algorithm == "SHA-512":
        return sha512(data).hexdigest()
    else:
        return md5(data).hexdigest()


def HA1(realm, username, password, algorithm):
    """Create HA1 hash by realm, username, password.

    HA1 = md5(A1) = MD5(username:realm:password)
    """
    if not realm:
        realm = ""
    return H(
        b":".join(
            [username.encode("utf-8"), realm.encode("utf-8"), password.encode("utf-8")]
        ),
        algorithm,
    )


def HA2(credentials, request, algorithm):
    """Create HA2 md5 hash.

    If the qop directive's value is "auth" or is unspecified, then HA2:
        HA2 = md5(A2) = MD5(method:digestURI)
    If the qop directive's value is "auth-int" , then HA2 is
        HA2 = md5(A2) = MD5(method:digestURI:MD5(entityBody))
    """
    if credentials.get("qop") == "auth" or credentials.get("qop") is None:
        return H(
            b":".join(
                [request["method"].encode("utf-8"), request["uri"].encode("utf-8")]
            ),
            algorithm,
        )
    elif credentials.get("qop") == "auth-int":
        for k in "method", "uri", "body":
            if k not in request:
                raise ValueError("%s required" % k)
        A2 = b":".join(
            [
                request["method"].encode("utf-8"),
                request["uri"].encode("utf-8"),
                H(request["body"], algorithm).encode("utf-8"),
            ]
        )
        return H(A2, algorithm)
    raise ValueError


def response(credentials, password, request):
    """Compile digest auth response.

    If the qop directive's value is "auth" or "auth-int" , then compute the response as follows:
       RESPONSE = MD5(HA1:nonce:nonceCount:clienNonce:qop:HA2)
    Else if the qop directive is unspecified, then compute the response as follows:
       RESPONSE = MD5(HA1:nonce:HA2)
    """
    response = None
    algorithm = credentials.get("algorithm")
    HA1_value = HA1(
        credentials.get("realm"), credentials.get("username"), password, algorithm
    )
    HA2_value = HA2(credentials, request, algorithm)
    if credentials.get("qop") is None:
        response = H(
            b":".join(
                [
                    HA1_value.encode("utf-8"),
                    credentials.get("nonce", "").encode("utf-8"),
                    HA2_value.encode("utf-8"),
                ]
            ),
            algorithm,
        )
    elif credentials.get("qop") == "auth" or credentials.get("qop") == "auth-int":
        for k in "nonce", "nc", "cnonce", "qop":
            if k not in credentials:
                raise ValueError("%s required for response H" % k)
        response = H(
            b":".join(
                [
                    HA1_value.encode("utf-8"),
                    credentials.get("nonce").encode("utf-8"),
                    credentials.get("nc").encode("utf-8"),
                    credentials.get("cnonce").encode("utf-8"),
                    credentials.get("qop").encode("utf-8"),
                    HA2_value.encode("utf-8"),
                ]
            ),
            algorithm,
        )
    else:
        raise ValueError("qop value are wrong")

    return response


def check_digest_auth(req, user, passwd, body=b""):
    """Check user authentication using HTTP Digest auth."""
    authorization = req.headers.get("Authorization")
    if authorization:
        credentials = parse_authorization_header(authorization)
        if not credentials:
            return False
        request_uri = req.url.path
        if req.url.query:
            request_uri += "?" + req.url.query
        try:
            response_hash = response(
                credentials,
                passwd,
                dict(uri=request_uri, body=body, method=str(req.method)),
            )
        except (ValueError, KeyError):
            return False
        if credentials.get("response") == response_hash:
            return True
    return False


def secure_cookie(req):
    """Return true if cookie should have secure attribute."""
    return req.is_secure


def __parse_request_range(range_header_text):
    """Return a tuple describing the byte range requested in a GET request.

    If the range is open ended on the left or right side, then a value of None
    will be set.
    RFC7233: http://svn.tools.ietf.org/svn/wg/httpbis/specs/rfc7233.html#header.range
    Examples:
      Range : bytes=1024-
      Range : bytes=10-20
      Range : bytes=-999
    """
    left = None
    right = None

    if not range_header_text:
        return left, right

    range_header_text = range_header_text.strip()
    if not range_header_text.startswith("bytes"):
        return left, right

    components = range_header_text.split("=")
    if len(components) != 2:
        return left, right

    components = components[1].split("-")

    try:
        right = int(components[1])
    except Exception:
        pass

    try:
        left = int(components[0])
    except Exception:
        pass

    return left, right


def get_request_range(request_headers, upper_bound):
    first_byte_pos, last_byte_pos = __parse_request_range(request_headers.get("range"))

    if first_byte_pos is None and last_byte_pos is None:
        # Request full range
        first_byte_pos = 0
        last_byte_pos = upper_bound - 1
    elif first_byte_pos is None:
        # Request the last X bytes
        first_byte_pos = max(0, upper_bound - last_byte_pos)
        last_byte_pos = upper_bound - 1
    elif last_byte_pos is None:
        # Request the last X bytes
        last_byte_pos = upper_bound - 1

    return first_byte_pos, last_byte_pos


def parse_multi_value_header(header_str):
    """Break apart an HTTP header string that is potentially a quoted, comma separated list as used in entity headers in RFC2616."""
    parsed_parts = []
    if header_str:
        parts = header_str.split(",")
        for part in parts:
            match = re.search('\\s*(W/)?\\"?([^"]*)\\"?\\s*', part)
            if match is not None:
                parsed_parts.append(match.group(2))
    return parsed_parts


def next_stale_after_value(stale_after):
    try:
        stal_after_count = int(stale_after) - 1
        return str(stal_after_count)
    except ValueError:
        return "never"


def digest_challenge_header(req, qop, algorithm, stale=False):
    """Build the ``WWW-Authenticate: Digest ...`` challenge header string."""
    remote_addr = (req.client.host if req.client else "") or ""
    nonce = H(
        b"".join(
            [
                remote_addr.encode("ascii", "ignore"),
                b":",
                str(time.time()).encode("ascii"),
                b":",
                os.urandom(10),
            ]
        ),
        algorithm,
    )
    opaque = H(os.urandom(10), algorithm)

    if qop is None:
        qop_value = "auth, auth-int"
    else:
        qop_value = qop

    parts = [
        'Digest realm="me@kennethreitz.com"',
        'nonce="%s"' % nonce,
        'qop="%s"' % qop_value,
        'opaque="%s"' % opaque,
        "algorithm=%s" % algorithm,
        "stale=%s" % ("TRUE" if stale else "FALSE"),
    ]
    return ", ".join(parts)

# -*- coding: utf-8 -*-

"""
httpbin.filters
~~~~~~~~~~~~~~~

Content-encoding helpers for the ``/gzip``, ``/deflate`` and ``/brotli``
endpoints. In the original Flask app these were response decorators; under
responder we disable the framework's automatic gzip middleware and encode the
body explicitly, so they are now simple byte-in / byte-out functions.
"""

import gzip as _gzip
import zlib

try:  # brotli is optional; /brotli 501s without it
    import brotli as _brotli
except ImportError:  # pragma: no cover
    try:
        import brotlicffi as _brotli
    except ImportError:
        _brotli = None


def gzip_compress(data):
    """Return GZip-encoded ``data`` (bytes)."""
    return _gzip.compress(data, compresslevel=4)


def deflate_compress(data):
    """Return Deflate-encoded ``data`` (bytes)."""
    deflater = zlib.compressobj()
    return deflater.compress(data) + deflater.flush()


def brotli_compress(data):
    """Return Brotli-encoded ``data`` (bytes), or ``None`` if brotli is missing."""
    if _brotli is None:
        return None
    return _brotli.compress(data)


brotli_available = _brotli is not None

import base64
import random
import string
from datetime import datetime
from time import timezone
import falcon
import pytest
from oauthlib.common import to_unicode, bytes_type


def to_bytes(text, encoding='utf-8'):
    """Make sure text is bytes type."""
    if not text:
        return text
    if not isinstance(text, bytes_type):
        text = text.encode(encoding)
    return text


def decode_base64(text, encoding='utf-8'):
    """Decode base64 string."""
    text = to_bytes(text, encoding)
    return to_unicode(base64.b64decode(text), encoding)


def extract_params(req):
    body = req.stream.read()
    if not body:
        body = req.params
    return req.uri, req.method, body, req.headers


def patch_response(resp, headers, body, status):
    if body:
        resp.body = body
    resp.set_headers(headers)
    if isinstance(status, int):
        status = getattr(falcon, 'HTTP_{}'.format(status))
    resp.status = status
    return resp


def utcnow():
    return datetime.now(timezone.utc)
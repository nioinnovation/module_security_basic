"""

   Base 64 utils

"""
from base64 import b64decode, b64encode


def base64_decode(s, encoding='ISO-8859-1'):
    """Return the native string base64-decoded (as a native string)."""
    if isinstance(s, str):
        b = s.encode(encoding)
    else:
        b = s
    b = b64decode(b)
    return b.decode(encoding)


def base64_encode(s, encoding='ISO-8859-1'):
    """Return the native string base64-encoded (as a native string)."""
    if isinstance(s, str):
        b = s.encode(encoding)
    else:
        b = s
    b = b64encode(b)
    return b.decode(encoding)

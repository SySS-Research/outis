import math
import hashlib
import base64

def xor_encode(text,key):
    """
    XOR the given text input with the specified key.
    text must be bytes, key must be string, result is bytes, sorry...
    """

    return b"".join(bytes([ord(x)^y]) for x,y in zip(key*len(text),text))

def lenofb64coding(initlen):
    """
    Calculates the length of a Base64 encoded string of data of the initial length initlen
    """

    x = math.ceil(initlen * 4 / 3)
    while x % 3 > 0: x += 1
    return x

def lenofb64decoded(initlen):
    """
    Calculates the length of a Base64 decoded form of the initial length of Base64 encoded data
    :param initlen: length of a Base64 encoded string
    :return: length of maximal decoded content for that lenght
    """

    while initlen % 3 > 0: initlen -= 1
    x = math.ceil(initlen * 3 // 4)
    return x


def sha512(data):
    if not data:
        return None
    h = hashlib.new('sha512')
    h.update(data)
    return h.digest()

def dnsdecode(data):
    """
    decodes DNS transmittable hostname data, 0-9A-Z, ignoring casing
    :param data: DNS transmittable hostname data
    :return: decoded form
    """

    return base64.b16decode(data, casefold=True)

def dnsencode(data):
    """
    encodes data in a DNS transmittable TXT form, so we use base64 for now
    :param data: data to encode
    :return: encoded form
    """

    return base64.b64encode(data)



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

def sha512(data):
    if not data:
        return None
    h = hashlib.new('sha512')
    h.update(data)
    return h.digest()

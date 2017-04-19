import math
import hashlib
import base64

from syhelpers.log import print_error


def xor_encode(text, key):
    """
    XOR the given text input with the specified key.
    text must be bytes, key must be string, result is bytes, sorry...
    """

    # noinspection PyTypeChecker
    return b"".join(bytes([ord(x) ^ y]) for x, y in zip(key*len(text), text))


def lenofb64coding(initlen):
    """
    Calculates the length of a Base64 encoded string of data of the initial length initlen
    """

    x = math.ceil(initlen * 4 / 3)
    while x % 3 > 0:
        x += 1
    return x


def lenofb64decoded(initlen):
    """
    Calculates the length of a Base64 decoded form of the initial length of Base64 encoded data
    :param initlen: length of a Base64 encoded string
    :return: length of maximal decoded content for that lenght
    """

    while initlen % 3 > 0:
        initlen -= 1
    x = math.ceil(initlen * 3 // 4)
    return x


def sha512(data):
    if not data:
        return None
    h = hashlib.new('sha512')
    h.update(data)
    return h.digest()


def dnshostdecode(data):
    """
    decodes DNS transmittable hostname data, 0-9A-F, ignoring casing
    :param data: DNS transmittable hostname data
    :return: decoded form
    """

    # TODO: receiving 0-9A-Z would be better
    return base64.b16decode(data, casefold=True)


def dnshostencode(data, zone):
    """
    encodes the data in a DNS transmittable hostname, 0-9A-F
    :param data: DNS transmittable hostname data
    :param zone: DNS zone to add at the end
    :return: encoded form
    """

    # TODO: sending 0-9A-Z would be better

    res = b""
    sdata = base64.b16encode(data)

    # every 60 characters, we will add a dot
    for i in range(len(sdata)):
        res += sdata[i:i+1]
        if (i+1) % 60 == 0 and (i+1) < len(sdata):
            res += b'.'

    return res + b'.' + zone.encode('utf-8') + b'.'


def dnstxtencode(data):
    """
    encodes data in a DNS transmittable TXT form, so we use base64 for now
    :param data: data to encode
    :return: encoded form
    """

    return base64.b64encode(data)


def dnsip4encode(data):
    """
    encodes the data as a single IPv4 address
    :param data: data to encode
    :return: encoded form
    """

    if len(data) > 4 or len(data) < 4:
        print_error("dnsip4encode: data ({}) is more or less than 4 bytes, cannot encode".format(data))
        return None

    return '{}.{}.{}.{}'.format(*data).encode("utf-8")


def dnsip6encode(data):
    """
    encodes the data as a single IPv6 address
    :param data: data to encode
    :return: encoded form
    """

    if len(data) != 16:
        print_error("dnsip6encode: data is more or less than 16 bytes, cannot encode")
        return None

    res = b''
    reslen = 0
    for i in range(len(data)):
        res += base64.b16encode(data[i:i+1])
        reslen += 1
        if reslen % 2 == 0:
            res += b':'

    return res[:-1]

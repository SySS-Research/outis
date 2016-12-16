
import OpenSSL
import hashlib

from helpers.log import print_error

def load_certificate(filename):
    cert = None
    try:
        f = open(filename)
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, f.read())
    except Exception as e:
        print_error("Loading certificate file failed: {}".format(e))
    finally:
        f.close()
    return cert

def load_privatekey(filename):
    pkey = None
    try:
        f = open(filename)
        pkey = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, f.read())
    except Exception as e:
        print_error("Loading certificate file failed: {}".format(e))
    finally:
        f.close()
    return pkey

def verify_signature(cert, signature, data, digest='sha512'):
    try:
        OpenSSL.crypto.verify(cert, signature, data, digest)
        return True
    except Exception as e:
        print_error("Signature verification failed: {}".format(e))
        return False

def create_signature(pkey, data, digest='sha512'):
    try:
        sig = OpenSSL.crypto.sign(pkey, data, digest)
        return sig
    except Exception as e:
        print_error("Signature creation failed: {}".format(e))
        return None

def sha512(data):
    if not data:
        return None
    h = hashlib.new('sha512')
    h.update(data)
    return h.hexdigest()

def int2bytes(i, byteorder='big'):
    return i.to_bytes((i.bit_length() + 7) // 8, byteorder=byteorder)


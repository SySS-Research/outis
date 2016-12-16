
def xor_encode(text,key):
    """
    XOR the given text input with the specified key.
    text must be bytes, key must be string, result is bytes, sorry...
    """

    return b"".join(bytes([ord(x)^y]) for x,y in zip(key*len(text),text))


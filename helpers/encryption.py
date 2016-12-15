
def xor_encode(text,key):
    """
    XOR the given text input with the specified key.
    """

    return "".join(chr(ord(x)^ord(y))for x,y in zip(key*len(text),text))



import re
import base64
import string
from Crypto.Random import random


def random_string(length=-1, charset=string.ascii_letters):
    """
    Returns a random string of "length" characters.
    If no length is specified, resulting string is in between 6 and 15 characters.
    A character set can be specified, defaulting to just alpha letters.
    """

    if length == -1:
        length = random.randrange(6, 16)
    rand_string = ''.join(random.choice(charset) for _ in range(length))
    return rand_string


def randomize_capitalization(data):
    """
    Randomize the capitalization of a string.
    """

    return "".join(random.choice([k.upper(), k]) for k in data)


def enc_powershell(raw):
    """
    Encode a PowerShell command into a form usable by powershell.exe -enc ...
    """

    return base64.b64encode(b"".join([bytes([char]) + b"\x00" for char in bytes(raw, 'utf-8')])).decode("utf-8")


def powershell_launcher(raw, baseCmd="powershell.exe -NoP -sta -NonI -W Hidden -Enc "):
    """
    Build a one line PowerShell launcher with an -enc command.
    """

    # encode the data into a form usable by -enc
    encCMD = enc_powershell(raw)

    return baseCmd + encCMD


# noinspection PyTypeChecker
def strip_powershell_comments(data):
    """
    Strip block comments, line comments and empty lines from a PowerShell source file.
    """
    
    # strip block comments
    strippedCode = re.sub(re.compile('<#.*?#>', re.DOTALL), '', data)

    # strip blank lines and lines starting with #
    # noinspection PyPep8
    strippedCode = "\n".join([line for line in strippedCode.split('\n') if ((line.strip() != '') and
        (not line.strip().startswith("#")))])

    # TODO: strip comments at the end of lines

    return strippedCode


def strip_debug_commands(data):
    """
    Strip debug statements from a PowerShell source file.
    """

    # strip block comments
    strippedCode = re.sub(re.compile('<#.*?#>', re.DOTALL), '', data)

    # strip debug statements
    # noinspection PyPep8,PyTypeChecker
    strippedCode = "\n".join([line for line in strippedCode.split('\n')
                              if not line.strip().lower().startswith("print-debug ")])

    return strippedCode

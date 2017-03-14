
import re, base64, string
from Crypto.Random import random

def random_string(length=-1, charset=string.ascii_letters):
    """
    Returns a random string of "length" characters.
    If no length is specified, resulting string is in between 6 and 15 characters.
    A character set can be specified, defaulting to just alpha letters.
    """

    if length == -1: length = random.randrange(6,16)
    random_string = ''.join(random.choice(charset) for _ in range(length))
    return random_string

def randomize_capitalization(data):
    """
    Randomize the capitalization of a string.
    """

    return "".join( random.choice([k.upper(), k ]) for k in data )

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

def strip_powershell_comments(data):
    """
    Strip block comments, line comments, empty lines, verbose statements,
    and debug statements from a PowerShell source file.
    """
    
    # strip block comments
    strippedCode = re.sub(re.compile('<#.*?#>', re.DOTALL), '', data)

    # strip blank lines, lines starting with #, and verbose/debug statements
    strippedCode = "\n".join([line for line in strippedCode.split('\n') if ((line.strip() != '') and (not line.strip().startswith("#")) and (not line.strip().lower().startswith("write-verbose ")) and (not line.strip().lower().startswith("write-debug ")) )])
    
    return strippedCode

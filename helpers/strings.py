
import re, base64
from Crypto.Random import random

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

def powershell_launcher(raw):
    """
    Build a one line PowerShell launcher with an -enc command.
    """

    # encode the data into a form usable by -enc
    encCMD = enc_powershell(raw)

    return "powershell.exe -NoP -sta -NonI -W Hidden -Enc " + encCMD

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

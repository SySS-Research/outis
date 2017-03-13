
DEBUG_MODULES = [
    "Message Parse", "Message Create",
    "PlatformPowershell",
    "Main",
    "TransportDns"
]

def print_error(text):
    """ for error messages """
    print("[-] ERROR: "+str(text))

def print_message(text):
    """ for status messages """
    print("[+] "+str(text))

def print_text(text):
    """ for raw output of text messages """
    print(str(text))

def print_debug(module, text):
    """ for debug messages, use the list DEBUG_MODULES to select if it should be printed """
    if module in DEBUG_MODULES:
        print("[D] ["+str(module)+"] "+str(text))


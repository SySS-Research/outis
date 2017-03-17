
AVAILABLE_DEBUG_MODULES = [
    "Message Parse", "Message Create",
    "PlatformPowershell",
    "Main", "Handler",
    "TransportReverseTcp", "TransportDns"
]

ACTIVATED_DEBUG_MODULES = []


def activate_debug(module):
    """
    activates the given module for debugging
    :param module: the module name to activate
    :return: None
    """

    module = str(module)
    if module not in AVAILABLE_DEBUG_MODULES:
        print_error("debug module '{}' is unknown, cannot activate it".format(module))
        return
    if module in ACTIVATED_DEBUG_MODULES:
        print_error("debug module '{}' is already active".format(module))
        return
    ACTIVATED_DEBUG_MODULES.append(module)


def isactivated(module):
    """
    checks whether the given module is active for debugging
    :param module: the module name to check
    :return: True iff the given module is active for debugging
    """

    module = str(module)
    if module not in AVAILABLE_DEBUG_MODULES:
        print_error("debug module '{}' is unknown, cannot check it".format(module))
        return False
    if module in ACTIVATED_DEBUG_MODULES:
        return True
    return False


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
    """ for debug messages, use the list ACTIVATED_DEBUG_MODULES to select if it should be printed """
    if module in ACTIVATED_DEBUG_MODULES:
        print("[D] ["+str(module)+"] "+str(text))


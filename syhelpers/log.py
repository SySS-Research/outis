import tempfile
import datetime

AVAILABLE_DEBUG_MODULES = [
    "Message Parse", "Message Create",
    "PlatformPowershell",
    "Main", "Handler", "Channel", "Log",
    "TransportReverseTcp", "TransportDns",
    "CmdHandler", "CmdSession"
]

ACTIVATED_DEBUG_MODULES = []

LOGFILE = None


# noinspection PyShadowingBuiltins
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

    # if this is the first activation set LOGFILE and print it
    if not ACTIVATED_DEBUG_MODULES:
        import os
        global LOGFILE
        LOGFILE = str(os.path.join(tempfile.gettempdir(), "outis.log"))
        print_message("DEBUGGING is active, writing to debug file " + str(LOGFILE))

    # add module to ACTIVATED_DEBUG_MODULES
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

    if LOGFILE:
        # noinspection PyTypeChecker
        with open(LOGFILE, "a") as logfile:
            logfile.write("[-] ["+str(datetime.datetime.now())+"] ERROR: "+str(text) + "\n")
    print("[-] ERROR: "+str(text))


def print_message(text):
    """ for status messages """

    if LOGFILE:
        # noinspection PyTypeChecker
        with open(LOGFILE, "a") as logfile:
            logfile.write("[+] ["+str(datetime.datetime.now())+"] "+str(text) + "\n")
    print("[+] "+str(text))


def print_text(text):
    """ for raw output of text messages """

    if LOGFILE:
        # noinspection PyTypeChecker
        with open(LOGFILE, "a") as logfile:
            logfile.write("[T] ["+str(datetime.datetime.now())+"] "+str(text) + "\n")
    print(str(text))


def print_debug(module, text):
    """ for debug messages, use the list ACTIVATED_DEBUG_MODULES to select if it should be printed """

    if module in ACTIVATED_DEBUG_MODULES:
        if LOGFILE:
            # noinspection PyTypeChecker
            with open(LOGFILE, "a") as logfile:
                logfile.write("[D] [" + str(datetime.datetime.now()) + "] ["+str(module)+"] " + str(text) + "\n")
        #print("[D] ["+str(module)+"] "+str(text))


def getTerminalSize():
    """
    returns the terminal width and height
    :return: the terminal width and height
    """

    import os
    env = os.environ

    def ioctl_GWINSZ(fdi):
        # noinspection PyBroadException
        try:
            import fcntl
            import termios
            import struct
            cri = struct.unpack('hh', fcntl.ioctl(fdi, termios.TIOCGWINSZ, '1234'))
        except:
            return
        return cri

    cr = ioctl_GWINSZ(0) or ioctl_GWINSZ(1) or ioctl_GWINSZ(2)

    if not cr:
        # noinspection PyBroadException
        try:
            fd = os.open(os.ctermid(), os.O_RDONLY)
            cr = ioctl_GWINSZ(fd)
            os.close(fd)
        except:
            pass

    if not cr:
        cr = (env.get('LINES', 25), env.get('COLUMNS', 80))

    return int(cr[1]), int(cr[0])


def print_table(table, headers, maxwidth=None, columsep="  "):
    """
    print a pretty formated ascii table
    :param table: list of lists for the content
    :param headers: list of headers
    :param maxwidth: maximal width of the table, will attempt to break last column lines if longer (default: infty)
    :param columsep: column seperator (default: two spaces)
    :return: None
    """

    col_width = [max(len(x) for x in col) for col in zip(headers, *table)]
    print_debug("Log", "current width = "+str(sum(col_width)))
    print_debug("Log", "current width without last line = " + str(sum(col_width[:-1])))
    if maxwidth is not None and sum(col_width) > maxwidth:
        print_debug("Log", "Need to break last column for terminal width {}".format(maxwidth))
        lastcolumnwidth = maxwidth - sum(col_width[:-1]) - len(columsep) * (len(col_width) - 1)
        print_debug("Log", "last column will have a width of " + str(lastcolumnwidth))
        if lastcolumnwidth < 10:
            print_error("Cannot plot table for terminal width {}, last column has less than 10 chars".format(maxwidth))
            return
        if len(headers[-1]) > lastcolumnwidth:
            print_error("Cannot plot table for terminal width {}, header of last column too long".format(maxwidth))
            return
        col_width[-1] = lastcolumnwidth
        # TODO: ...

    print(columsep.join("{:{}}".format(x, col_width[i]) for i, x in enumerate(headers)))
    print(columsep.join(("-" * col_width[i]) for i, x in enumerate(headers)))
    for line in table:
        lastcolumn = []
        lastcolumntmp = line[-1]
        while len(lastcolumntmp) > col_width[-1]:
            a = lastcolumntmp.rfind(" ", col_width[-1] - 10, col_width[-1]) + 1
            if a < col_width[-1] - 10:
                a = col_width[-1]
            lastcolumn.append(lastcolumntmp[:a])
            lastcolumntmp = lastcolumntmp[a:]
        if len(lastcolumntmp) > 0:
            lastcolumn.append(lastcolumntmp)

        print(columsep.join("{:{}}".format(x, col_width[i]) for i, x in enumerate(line[:-1]))
              + columsep + lastcolumn[0])
        for l in lastcolumn[1:]:
            print(columsep.join((" " * col_width[i]) for i, x in enumerate(headers[:-1])) + columsep + l)


def print_table_terminal(table, headers, columsep="  "):
    """
    prints a pretty formated table for the terminal width
    :param table: list of lists for the content
    :param headers: list of headers
    :param columsep: column seperator (default: two spaces)
    :return: None
    """

    width, _ = getTerminalSize()
    print_table(table, headers, maxwidth=width, columsep=columsep)


import cmd

from syhelpers.log import print_error, print_debug, activate_debug, AVAILABLE_DEBUG_MODULES

DEBUGMODULE = "CmdHandler"


class HandlerCmdProcessor(cmd.Cmd):
    """
    Command line processor for the handler part.
    """

    # prompt to show in front of each input line
    prompt = "outis> "

    def __init__(self, handler):
        """
        constructor for command line processor for handler part
        :param handler: outis handler to work with
        """

        super().__init__()
        self.handler = handler

    def emptyline(self):
        """
        will be executed when an emtpy line is entered, default would be to repeat the last command, we pass instead
        :return: None
        """

        pass

    def do_EOF(self, line):
        """exit :: Exit outis and end all running tasks."""

        return self.do_exit(line)

    # noinspection PyUnusedLocal
    def do_exit(self, line):
        """exit :: Exit outis and end all running tasks."""

        self.handler.stop()
        return True

    def do_set(self, line):
        """set <KEY> <VALUE> :: Set an option for handle, platform or transport module"""

        v = line.split(" ")
        if len(v) != 2:
            print_error("set: expected KEY and VALUE, e.g. set PLATFORM POWERSHELL")
            return

        key, value = v
        self.handler.setoption(key, value)

    # noinspection PyUnusedLocal
    def complete_set(self, text, line, bigidx, endidx):
        """autocompletion for set command"""

        v = line.split(" ")
        if len(v) > 1:
            if text == v[1]:
                #print_debug(DEBUGMODULE, "Trying to complete option name "+str(v[1]))
                return self.handler.completeoption(v[1])
            if len(v) > 2 and text == v[2]:
                return self.handler.completeoptionvalue(v[1], v[2])
            else:
                print_debug(DEBUGMODULE, "Trying to complete invalid part")
                return []
        else:
            print_debug(DEBUGMODULE, "Cannot autocomplete invalid line")
            return []

    # noinspection PyUnusedLocal
    def do_generatestager(self, line):
        """generatestager :: Generate and print a stager for the current platform and transport."""

        self.handler.generatestager()

    def do_generateagent(self, line):
        """generateagent <FILENAME> :: Generate the agent code and writes it to the file"""

        self.handler.generateagent(filename=line)

    # noinspection PyUnusedLocal
    def do_run(self, line):
        """run :: Run the listener and handle any communication with agents. If staged, the initial connection will """\
            """be upgraded to a full agent using plattform / transport modules."""

        self.handler.run()

    # noinspection PyUnusedLocal
    def do_info(self, line):
        """info :: print information of options for the handler and the selected transport and platform modules"""

        self.handler.show_options()

    # noinspection PyMethodMayBeStatic
    def do_activate_debug(self, line):
        """activate_debug <MODULE> :: enables debug output to logfile for this module"""

        activate_debug(line)

    # noinspection PyUnusedLocal,PyMethodMayBeStatic
    def complete_activate_debug(self, text, line, bigidx, endidx):
        """autocompletion for activate_debug modules"""

        return [v for v in AVAILABLE_DEBUG_MODULES if v.startswith(str(text))]

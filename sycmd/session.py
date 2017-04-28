import cmd

from syhelpers.log import print_error

DEBUGMODULE = "CmdSession"


class SessionCmdProcessor(cmd.Cmd):
    """
    Command line processor for a runnning session
    """

    # prompt to show in front of each input line
    prompt = "outis session> "

    def __init__(self, messagequeue):
        """
        constructor for command line processor for session part
        :param messagequeue:
        """

        super().__init__()
        self.msgqueue = messagequeue

    def emptyline(self):
        """
        will be executed when an emtpy line is entered, default would be to repeat the last command, we pass instead
        :return: None
        """

        pass

    def do_EOF(self, line):
        """exit :: Exit session and close the connection to the agent"""

        return self.do_exit(line)

    # noinspection PyUnusedLocal
    def do_exit(self, line):
        """exit :: Exit session and close the connection to the agent"""

        r = input("Do you really want to exit the session and close the connection [y/N]? ")
        if r == "y" or r == "Y":
            self.msgqueue.put(["exit"])
            self.msgqueue.join()
            return True

    def do_download(self, line):
        """download REMOTEFILE LOCALTARGETFILE :: download the REMOTEFILE in the agents file system to """\
                """LOCALTARGETFILE here"""

        v = line.split(" ")
        if len(v) != 2:
            print_error("download: expected REMOTEFILE and LOCALTARGETFILE, e.g. download "
                        "C:\\input.txt /tmp/output.txt")
            return

        self.msgqueue.put(["download", v[0], v[1]])
        self.msgqueue.join()

    def do_upload(self, line):
        """upload LOCALFILE REMOTETARGETFILE :: upload the LOCALFILE from here to the agent file system as """\
            """REMOTETARGETFILE"""

        v = line.split(" ")
        if len(v) != 2:
            print_error("upload: expected LOCALFILE and REMOTETARGETFILE, e.g. upload "
                        "/tmp/input.txt C:\\output.txt")
            return

        self.msgqueue.put(["upload", v[0], v[1]])
        self.msgqueue.join()

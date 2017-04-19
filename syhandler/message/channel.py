from syhelpers.dataqueue import DataQueue
from syhelpers.log import print_error, print_debug

DEBUG_MODULE = "Channel"


class Channel:
    """
    channel object for the handler. Different data streams can be wrapped into our connection using this.
    """

    def __init__(self):
        """
        initiate a new channel object
        """

        self.state = "RESERVED"
        self.receivequeue = DataQueue()
        self.sendqueue = DataQueue()
        self.size = None

    def isReserved(self):
        """
        :returns wether the channel is marked as reserved
        :return: True if reserved
        """

        return self.state == "RESERVED"

    def setOpen(self):
        """
        marks the channel as open, will be called once messages refer to the channel
        :return: None
        """

        self.state = "OPEN"

    def isOpen(self):
        """
        returns wether the channel is open
        :return: True if open
        """

        return self.state == "OPEN"

    def setClose(self):
        """
        marks the channel as closed
        :return: None
        """

        self.state = "CLOSED"

    def isClosed(self):
        """
        returns wether the channel is marked closed
        :return: True iff closed
        """

        return self.state == "CLOSED"

    def write(self, data):
        """
        writes data to this channel
        :param data: data to write to the channel
        :return: None
        """

        if not self.isOpen():
            print_error("cannot write to non-open channel")
            return

        return self.sendqueue.write(data)

    def writeFromSend(self, data):
        """
        writes data to the receivequeue of this channel, to be used from connection only
        :param data: data to write to the channel
        :return: None
        """

        if not self.isOpen():
            print_error("cannot write to non-open channel")
            return

        # TODO: remove the message here
        print_debug(DEBUG_MODULE, "received data in channel: {}".format(data))

        self.receivequeue.write(data)

    def read(self, leng=-1):
        """
        reads data from the channel
        :param leng: length of bytes to read. If not specified or negative, all bytes are returned.
        :return: data bytes
        """

        return self.receivequeue.read(leng)

    def readToSend(self, leng=-1):
        """
        reads data from the channels sendqueue, to be used for connection only
        :param leng: length of bytes to read. If not specified or negative, all bytes are returned.
        :return: data bytes from the sendqueue
        """

        return self.sendqueue.read(leng)

    def has_data(self):
        """
        returns True iff the channel has data to read
        :return: True iff the channel has data to read
        """

        return self.receivequeue.has_data()

    def has_data_to_send(self):
        """
        returns True iff the channels sendqueue has data to send
        :return: True iff the channels sendqueue has data to send
        """

        return self.sendqueue.has_data()

    def setSize(self, size):
        """
        sets the size value for the expected data of this channel
        :param size: size in bytes
        :return: None
        """

        self.size = size

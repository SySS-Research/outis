
class DataQueue:
    """
    storage queue for sending / receiving data
    """

    def __init__(self):
        """
        initialize a new storage queue
        """

        self.queue = b""

    def add(self, data):
        """
        add the data to the send queue
        :param data: data to send
        :return: None
        """

        self.queue += data

    def get(self, len):
        """
        get and remove next len bytes from the send queue
        :param len: byte len to get and remove
        :return: data
        """

        if len > len(self.queue):
            len = len(self.queue)

        data = self.queue[:len]
        self.queue = self.queue[len:]
        return data


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

    def get(self, leng):
        """
        get and remove next len bytes from the send queue
        :param leng: byte len to get and remove
        :return: data
        """

        if leng > len(self.queue):
            leng = len(self.queue)

        data = self.queue[:leng]
        self.queue = self.queue[leng:]
        return data

    def has_data(self):
        """
        returns True iff the queue has data
        :return: True iff the queue has data
        """

        return len(self.queue) > 0

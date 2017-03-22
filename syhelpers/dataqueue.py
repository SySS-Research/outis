import ssl


class DataQueue:
    """
    storage queue for sending / receiving data
    """

    def __init__(self):
        """
        initialize a new storage queue
        """

        self.memorybio = ssl.MemoryBIO()

    def has_data(self):
        """
        returns True iff the queue has data
        :return: True iff the queue has data
        """

        return self.memorybio.pending > 0

    def length(self):
        """
        returns the length of the data in the queue
        :return: length of the data in the queue
        """

        return self.memorybio.pending

    def read(self, leng=-1):
        """
        reads up to leng bytes from the buffer. If leng is not specified or negative, all bytes are returned.
        :param leng: length of bytes to read
        :return: bytes
        """

        return self.memorybio.read(leng)

    def write(self, buf):
        """
        Write the bytes from buf to the buffer. The buf argument must be an object supporting the buffer protocol.
        The return value is the number of bytes written, which is always equal to the length of buf.
        :param buf: bytes to write to the buffer
        :return: number of bytes written
        """

        return self.memorybio.write(buf)


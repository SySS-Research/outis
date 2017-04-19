import threading


class SyThread(threading.Thread):

    def __init__(self, target, args=()):
        """
        constructor of our thread
        :param target method to call in the tread
        :param args: arguments to present to target function
        """

        self.stopevent = threading.Event()
        threading.Thread.__init__(self, target=target, args=args)
        self.result = None
        self.daemon = True

    def terminate(self, timeout):
        """
        Stop the thread and wait for it to end.
        :param timeout: timeout for the join operation
        :return:
        """

        self.stopevent.set()
        threading.Thread.join(self, timeout)

    def getResult(self):
        """
        Returns the result of the thread if implemented in the run function or None
        :return: result or None
        """

        return self.result

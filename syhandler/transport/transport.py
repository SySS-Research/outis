
class Transport:
    """ Transport: abstract way for communication between agent and handler """

    # noinspection PyUnusedLocal
    def __init__(self, handler):
        raise NotImplementedError("Transport.init should have been implemented by transport module")
    
    def open(self, staged=False):
        raise NotImplementedError("Transport.open should have been implemented by transport module")

    def send(self, data):
        raise NotImplementedError("Transport.send should have been implemented by transport module")

    def receive(self):
        raise NotImplementedError("Transport.receive should have been implemented by transport module")

    def upgradefromstager(self):
        raise NotImplementedError("Transport.upgradefromstager should have been implemented by transport module")

    def upgradetotls(self):
        raise NotImplementedError("Transport.upgradetotls should have been implemented by transport module")
    
    def close(self):
        raise NotImplementedError("Transport.close should have been implemented by transport module")

    def receivemessage(self, headers=None):
        """
        receives a message format message from the agent
        wrapper for Message.parseFromTransport
        :param headers: if set use these headers first
        :return: message
        """

        from ..message.message import Message
        message = Message.parseFromTransport(self, headers=headers)
        return message

    def sendmessage(self, message):
        """
        sends the given message format message to the agent
        wrapper for Message.sendToTransport
        """

        message.sendToTransport(self)


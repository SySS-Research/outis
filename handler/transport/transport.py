

class Transport:
    """ Transport: abstract way for communication between agent and handler """

    def __init__(self):
        raise NotImplementedError("Transport.init should have been implemented by transport module")

    def setoption(self, name, value):
        raise NotImplementedError("Transport.setoption should have been implemented by transport module")
    
    def open(self):
        raise NotImplementedError("Transport.open should have been implemented by transport module")

    def send(self, data):
        raise NotImplementedError("Transport.send should have been implemented by transport module")

    def receive(self):
        raise NotImplementedError("Transport.receive should have been implemented by transport module")
    
    def close(self):
        raise NotImplementedError("Transport.close should have been implemented by transport module")


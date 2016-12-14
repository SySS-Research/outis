
class Platform:
    """ Platform: abstract platform of the agent """

    def __init__(self):
        raise NotImplementedError("Platform.init should have been implemented by platform module")
    
    def getstager(self, handler):
        raise NotImplementedError("Platform.getstager should have been implemented by platform module")

    def getagent(self, handler):
        raise NotImplementedError("Platform.getagent should have been implemented by platform module")


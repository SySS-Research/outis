
class Platform:
    """ Platform: abstract platform of the agent """

    def __init__(self):
        raise NotImplementedError("Platform.init should have been implemented by platform module")

    def isstaged(self):
        """
        is the current platform set staged or not? overwrite to handle stages
        """

        return False
    
    def getstager(self, handler):
        raise NotImplementedError("Platform.getstager should have been implemented by platform module")

    def getagent(self, handler):
        raise NotImplementedError("Platform.getagent should have been implemented by platform module")


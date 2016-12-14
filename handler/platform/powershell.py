
from helpers.log import *
from .platform import Platform
from helpers.modulebase import ModuleBase

class PlatformPowershell(Platform, ModuleBase):

    def __init__(self):
        self.options = {
            'STAGED' : {
                'Description'   :   'Is the communication setup staged or not?',
                'Required'      :   True,
                'Value'         :   "TRUE",
                'Options'       :   ("TRUE", "FALSE")
            }
        }
    
    def getstager(self, handler):
        raise NotImplementedError("Platform.getstager should have been implemented by platform module")

    def getagent(self, handler):
        raise NotImplementedError("Platform.getagent should have been implemented by platform module")




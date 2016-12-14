#!/usr/bin/python3

from .transport.reversetcp import TransportReverseTcp
from .message.message import Message
from .platform.powershell import PlatformPowershell
from helpers.log import print_message, print_error
from helpers.modulebase import ModuleBase

class Handler(ModuleBase):
    """ Base handler for all interactions with agents """
    
    def __init__(self):
        self.options = {
            'TRANSPORT' : {
                'Description'   :   'Communication way between agent and handler',
                'Required'      :   True,
                'Value'         :   "REVERSETCP",
                'Options'       :   ("REVERSETCP","TODO")
            },
            'PLATFORM' : {
                'Description'   :   'Platform of agent code',
                'Required'      :   False,
                'Value'         :   "POWERSHELL",
                'Options'       :   ("POWERSHELL",)
            }
        }
        self.transport = TransportReverseTcp()
        self.platform = PlatformPowershell()
    
    def setoption(self, name, value):
        if ModuleBase.setoption(self, name, value):
            return True
        elif self.transport and self.transport.setoption(name, value):
            return True
        elif self.platform and self.platform.setoption(name, value):
            return True
        else:
            print_error(str(name.upper())+" not recognized as an option")
            return False

    def validate_options(self):
        return ModuleBase.validate_options(self)

    def run(self):
        if not self.validate_options():
            return

        self.transport.open()
        
        message0 = Message()
        message0.create(0x01, b'Test0')
        self.transport.sendmessage(message0)

        message1 = self.transport.receivemessage()

        message2 = Message()
        message2.create(0x01, b'TestBack')
        self.transport.sendmessage(message1)

        self.transport.close()


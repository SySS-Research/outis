
from .transport import Transport
from helpers.log import print_message, print_error
import socket
from helpers.modulebase import ModuleBase

class TransportReverseTcp (Transport,ModuleBase):
    """ opens a tcp listener and allows connections from agents """

    def __init__(self, **kwargs):
        self.options = {
            'LHOST' : {
                'Description'   :   'Interface IP to listen on',
                'Required'      :   True,
                'Value'         :   "0.0.0.0"
            },
            'LPORT' : {
                'Description'   :   'Port to listen on',
                'Required'      :   True,
                'Value'         :   "8080"
            },
            'CONNECTHOST' : {
                'Description'   :   'Interface IP to listen on (if not set, uses LHOST)',
                'Required'      :   False,
                'Value'         :   None
            },
            'CONNECTPORT' : {
                'Description'   :   'Port to connect to (if not set, uses LPORT)',
                'Required'      :   False,
                'Value'         :   None
            }
        }
        self.conn = None
        self.socket = None
        self.staged = False
    
    def setoption(self, name, value):

        # TODO: check ips

        if name.upper() == "LPORT" and not(self._validate_lport("LPORT",value)):
            return True # value found, but not set
        if name.upper() == "CONNECTPORT" and not(self._validate_lport("CONNECTPORT",value)):
            return True # value found, but not set

        return ModuleBase.setoption(self, name, value)

    def _validate_lport(self, name, port):
        if not port or not str(port).isdigit() or int(port) < 1 or int(port) > 65535:
            print_error(str(name)+" is invalid, should be 1 <= port <= 65535")
            return False
        else:
            return True

    def validate_options(self):
        """
        Validate all currently set listener options.
        """
        
        valid = ModuleBase.validate_options(self)
        
        # TODO: check ips

        # check port
        port = self.options['LPORT']['Value']
        if port and not(self._validate_lport('LPORT', port)):
            valid = False
        port = self.options['CONNECTPORT']['Value']
        if port and not(self._validate_lport('CONNECTPORT', port)):
            valid = False

        return valid
    
    def open(self, staged=False):
        if not self.validate_options():
            return

        self.staged = staged

        lparams = (self.options['LHOST']['Value'], int(self.options['LPORT']['Value']))        

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(lparams)
        self.socket.listen(1)

        print_message("TCP transport listening on {}:{}".format(*lparams))
        
        self.conn, addr = self.socket.accept()
        print_message("Connection from {}:{}".format(*addr))
   
    def send(self, data):
        if not self.conn:
            print_error("Connection not open")
            return

        self.conn.send(data)

    def receive(self, leng=1024):
        if not self.conn:
            print_error("Connection not open")
            return

        data = self.conn.recv(leng)
        if not data:
            print_error("Connection closed by peer")
            self.close()
        return data

    def upgradefromstager(self):
        # TODO stager upgraden statt verbindung zu erneuern
        self.close()
        self.open(staged=False)

    def close(self):
        if not self.conn:
            print_error("Connection not open")
            return
        self.conn.close()
        self.conn = None



from .transport import Transport
from helpers.log import print_message, print_error
import socket

class TransportReverseTcp (Transport):
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
            }
        }

    
    def validate_options(self):
        """
        Validate all currently set listener options.
        """
        
        valid = True

        # make sure all options are set
        for option,values in self.options.items():
            if values['Required'] and not(values['Value']) or (values['Value'] == ''):
                print_error(str(option)+" must be set")
                valid = False
        
        # TODO: check ip and port

        port = self.options['LPORT']['Value']
        if not port or not str(port).isdigit() or int(port) < 1 or int(port) > 65535:
            print_error("LPORT is invalid")
            valid = False

        return valid
    
    def setoption(self, name, value):
        if name and isinstance(name, str) and name.upper() in self.options:
            self.options[name.upper()]['Value'] = value
            return True
        else:
            print_error(str(name.upper())+" not recognized as an option")
            return False
    
    def open(self):
        if not self.validate_options():
            return

        lparams = (self.options['LHOST']['Value'], int(self.options['LPORT']['Value']))        

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(lparams)
        self.socket.listen(1)

        print_message("TCP Transport listening on {}:{}".format(*lparams))
        
        self.conn, addr = self.socket.accept()
        print_message("Connection from {}:{}".format(*addr))
   
    def send(self, data):
        if not self.conn:
            print_error("Connection not open")
            return

        self.conn.send(data)

    def receive(self):
        if not self.conn:
            print_error("Connection not open")
            return

        data = self.conn.recv(1024)
        if not data:
            print_error("Connection closed by peer")
            self.close()
        return data

    def close(self):
        if not self.conn:
            print_error("Connection not open")
            return
        self.conn.close()
        self.conn = None


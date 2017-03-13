from helpers.types import isportnumber
from .transport import Transport
from helpers.log import print_message, print_error
import socket, ssl
from helpers.modulebase import ModuleBase

class TransportDns (Transport,ModuleBase):
    """ allows and handles DNS query based connections """

    def __init__(self, **kwargs):
        self.options = {
            'ZONE' : {
                'Description'   :   'DNS Zone for handling requests',
                'Required'      :   True,
                'Value'         :   None
            },
            'LHOST': {
                'Description': 'Interface IP to listen on',
                'Required': True,
                'Value': "0.0.0.0"
            },
            'LPORT' : {
                'Description'   :   'UDP-Port to listen on for DNS server',
                'Required'      :   True,
                'Value'         :   "53"
            },
            'DNSTYPE': {
                'Description': 'DNS type to use for the connection',
                'Required': True,
                'Value': "TXT",
                'Options': ("TXT",) # TODO: add and prefer A type
            }
        }
        self.socket = None
        self.staged = False
    
    def setoption(self, name, value):
        """
        Sets an option
        :param name: name of the option
        :param value: new value
        :return: True iff the value was found, not necessary set!
        """

        # TODO: check interface ip LHOST

        if name.upper() == "ZONE" and not(self._validate_zone("ZONE",value)):
            return True # value found, but not set
        if name.upper() == "LPORT" and not(self._validate_port("LPORT",value)):
            return True # value found, but not set

        return ModuleBase.setoption(self, name, value)

    def _validate_zone(self, name, zone):
        """
        validates whether DNS zone is plausible
        :param name: name of the option field, used for outputs
        :param zone: string of the DNS zone to validate
        :return: True iff we could validate the zone
        """

        # TODO: check zone

        if not zone or not str(zone):
            print_error(str(name)+" is invalid")
            return False
        else:
            return True

    def _validate_port(self, name, port):
        """
        checks whether the port value is plausible
        :param name: name of the option, to use in messages
        :param port: port number to check
        :return: True iff plausible
        """

        if not isportnumber(port):
            print_error(str(name)+" is invalid, should be 1 <= port <= 65535")
            return False
        else:
            if port and int(port) != 53:
                print_error("DNS might not work if you set a non-default port. We will assume, you know what you do and continue.")
            return True

    def validate_options(self):
        """
        Validate all currently set listener options.
        """
        
        valid = ModuleBase.validate_options(self)

        # TODO: check interface ip LHOST

        port = self.options['LPORT']['Value']
        if port and not(self._validate_port('LPORT', port)):
            valid = False

        zone = self.options['ZONE']['Value']
        if zone and not(self._validate_zone('ZONE', port)):
            valid = False

        return valid
    
    def open(self, staged=False):
        """
        open the DNS server and listen for connections
        :param staged: should we stage first?
        :return: None
        """

        if not self.validate_options():
            return

        self.staged = staged

        lparams = (self.options['LHOST']['Value'], int(self.options['LPORT']['Value']))

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(lparams)
        self.socket.listen(1)

        print_message("DNS listening on {}:{}".format(*lparams))
        
        self.conn, addr = self.socket.accept()
        print_message("Connection from {}:{}".format(*addr))
   
    def send(self, data):
        """
        send data to the connected host
        :param data: data to send
        :return: None
        """

        # TODO: change to multi connection puzzeling, and to polling based

        if not self.conn:
            print_error("Connection not open")
            return

        self.conn.send(data)

    def receive(self, leng=1024):
        """
        receive data from connected host
        :param leng: length of data to collect
        :return: None
        """

        # TODO: change to multi connection puzzeling

        if not self.conn:
            print_error("Connection not open")
            return

        data = self.conn.recv(leng)
        if not data:
            print_error("Connection closed by peer")
            self.close()
        return data

    def upgradefromstager(self):
        """
        upgrade the connection from staged form to unstaged real connection
        :return: None
        """

        # TODO: upgrade stager instead of reopening connection
        self.close()
        self.open(staged=False)

    def upgradetotls(self):
        """
        upgrade to a tls wrapped connection
        :return: None
        """

        # TODO: implement
        print_error("DNS + TLS is not implemented yet")
        return

        # TODO: newer TLS version?
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        # TODO: load the certificate from the correct option path
        context.load_cert_chain(certfile="./data/syssspy.pem", keyfile="./data/syssspy.pem")
        self.conn = context.wrap_socket(self.conn, server_side=True)
        print_message("Upgrade to TLS done")

    def close(self):
        """
        Close the connection
        :return: None
        """

        # TODO: change to multi connection puzzeling
        if not self.conn:
            print_error("Connection not open")
            return
        self.conn.close()
        self.conn = None


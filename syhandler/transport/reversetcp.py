from syhelpers.files import sanatizefilename
from syhelpers.types import isportnumber
from .transport import Transport
from syhelpers.log import print_message, print_error, print_debug
from syhelpers.modulebase import ModuleBase

import socket
import ssl


DEBUG_MODULE = "TransportReverseTcp"


class TransportReverseTcp (Transport, ModuleBase):
    """ opens a tcp listener and allows connections from agents """

    # noinspection PyMissingConstructor
    def __init__(self, handler):
        """
        initializese the module
        :param handler: backreference to outis handler object
        """

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
                'Description'   :   'Interface IP to listen on (uses LHOST if not set )',
                'Required'      :   False,
                'Value'         :   None
            },
            'CONNECTPORT' : {
                'Description'   :   'Port to connect to (uses LPORT if not set)',
                'Required'      :   False,
                'Value'         :   None
            }
        }
        self.handler = handler
        self.conn = None
        self.socket = None
        self.staged = False

    def setoption(self, name, value):
        """
        Sets an option
        :param name: name of the option
        :param value: new value
        :return: True iff the value was found, not necessary set!
        """

        # TODO: check ips

        if name.upper() == "LPORT" and not(self._validate_port("LPORT", value)):
            return True  # value found, but not set
        if name.upper() == "CONNECTPORT" and not(self._validate_port("CONNECTPORT", value)):
            return True  # value found, but not set

        return ModuleBase.setoption(self, name, value)

    @staticmethod
    def _validate_port(name, port):
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
            return True

    def validate_options(self):
        """
        Validate all currently set listener options.
        """

        valid = ModuleBase.validate_options(self)

        # TODO: check ips

        # check port
        port = self.options['LPORT']['Value']
        if port and not(self._validate_port('LPORT', port)):
            valid = False
        port = self.options['CONNECTPORT']['Value']
        if port and not(self._validate_port('CONNECTPORT', port)):
            valid = False

        return valid

    def open(self, staged=False):
        """
        opens the server part and listens for connections
        :param staged: should we stage first?
        :return: True if successfull
        """

        if not self.validate_options():
            return False

        self.conn = None
        self.socket = None
        self.staged = staged

        lparams = (self.options['LHOST']['Value'], int(self.options['LPORT']['Value']))

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.socket.bind(lparams)
        except PermissionError as e:
            print_error("Could not open TCP server on {}:{}: {}".format(lparams[0], lparams[1],
                                                                        str(e)))
            return False
        self.socket.listen(1)

        print_message("TCP transport listening on {}:{}".format(lparams[0], lparams[1]))

        self.conn, addr = self.socket.accept()
        print_message("Connection from {}:{}".format(addr[0], addr[1]))
        return True

    def send(self, data):
        """
        send data to the connected host
        :param data: data to send
        :return: None
        """

        if not self.conn:
            print_error("Connection not open")
            return

        self.conn.send(data)

    def receive(self, leng=1024):
        """
        receive data from connected host
        :param leng: length of data to collect
        :return: data (or None if connection closed)
        """

        if not self.conn:
            print_error("Connection not open")
            return None

        try:
            data = self.conn.recv(leng)
        except ConnectionResetError:
            data = None

        print_debug(DEBUG_MODULE, "received data: {}".format(data))

        if not data:
            print_error("Connection closed by peer")
            self.close()
        return data

    def upgradefromstager(self):
        """
        upgrade the connection from staged form to unstaged real connection
        :return: None
        """

        # TODO upgrade stager instead of reopening connection

        print_debug(DEBUG_MODULE, "upgrading from stager")
        self.close()
        self.open(staged=False)

    def upgradetotls(self):
        """
        upgrade to a tls wrapped connection
        :return: None
        """

        print_debug(DEBUG_MODULE, "upgrading to TLS context")

        # TODO: newer TLS version?
        # noinspection PyUnresolvedReferences
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        # TODO: PLATFORM STAGECERTIFICATEFILE is not the correct name for this value, move to handler or set a different
        #   variable in TRANSPORT with the same initial value?
        certkeyfile = sanatizefilename(self.handler.platform.options['STAGECERTIFICATEFILE']['Value'])
        context.load_cert_chain(certfile=certkeyfile, keyfile=certkeyfile)
        self.conn = context.wrap_socket(self.conn, server_side=True)
        print_message("Upgrade to TLS done")

    def close(self):
        """
        Close the connection
        :return: None
        """

        if self.conn is None:
            print_debug(DEBUG_MODULE, "Connection not open")
            return

        self.conn.close()
        self.conn = None


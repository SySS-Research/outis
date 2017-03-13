import socketserver

from helpers.dataqueue import DataQueue
from helpers.encoding import dnsdecode, dnsencode
from helpers.types import isportnumber, isint
from .transport import Transport
from helpers.log import *
import socket, ssl
from helpers.modulebase import ModuleBase
import dns
import dns.message

DEBUG_MODULE = "TransportDns"

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
        self.server = None
        self.staged = False
        self.senddataqueue = DataQueue()
        self.recvdataqueue = DataQueue()
    
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
        elif isint(value) and int(value) != 53:
            print_error("DNS might not work if you set a non-default port. We will assume, you know what you do and continue.")
            # and continue setting it

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

        # mark backchannel to us from each DnsHandler instance
        DnsHandler.transport = self

        lparams = (self.options['LHOST']['Value'], int(self.options['LPORT']['Value']))

        self.server = socketserver.UDPServer(lparams, DnsHandler)
        self.server.serve_forever()

        print_message("DNS listening on {}:{}".format(*lparams))
   
    def send(self, data):
        """
        send data to the connected host
        :param data: data to send
        :return: None
        """

        # TODO: change to multi connection puzzeling, and to polling based

        if not self.server:
            print_error("Connection not open")
            return

        # TODO: self.conn.send(data)

    def receive(self, leng=1024):
        """
        receive data from connected host
        :param leng: length of data to collect
        :return: None
        """

        # TODO: change to multi connection puzzeling

        if not self.server:
            print_error("Connection not open")
            return

        # TODOdata = self.conn.recv(leng)
        # if not data:
        #    print_error("Connection closed by peer")
        #    self.close()
        # return data
        return b""

    def upgradefromstager(self):
        """
        upgrade the connection from staged form to unstaged real connection
        :return: None
        """

        # TODO: upgrade stager instead of reopening connection
        #self.close()
        #self.open(staged=False)
        pass

    def upgradetotls(self):
        """
        upgrade to a tls wrapped connection
        :return: None
        """

        # TODO: implement
        print_error("DNS + TLS is not implemented yet")
        return

        ## TODO: newer TLS version?
        #context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        ## TODO: load the certificate from the correct option path
        #context.load_cert_chain(certfile="./data/syssspy.pem", keyfile="./data/syssspy.pem")
        #self.conn = context.wrap_socket(self.conn, server_side=True)
        #print_message("Upgrade to TLS done")

    def close(self):
        """
        Close the connection
        :return: None
        """

        if not self.server:
            print_error("Connection not open")
            return

        self.server.shutdown()
        self.server.server_close()
        self.server = None


class DnsHandler(socketserver.BaseRequestHandler):
    """
    This class is instanciated once per connection and should handle the DNS requests
    """

    transport = None

    def handle(self):
        data = self.request[0].strip()
        socket = self.request[1]

        zone = self.transport.options["ZONE"]["Value"].rstrip(".")
        #print_debug(DEBUG_MODULE, "zone = " + str(zone))

        msg = dns.message.from_wire(data)

        if msg.opcode() != 0: # not a query
            print_error("invalid DNS request received: "+str(msg))
            return

        for q in msg.question:
            print_debug(DEBUG_MODULE, "query from {}: {}".format(self.client_address[0], str(q)))
            if "IN PTR" in str(q):
                print_debug(DEBUG_MODULE, "ignoring PTR question " + str(q))
                continue

            qtext = dnsdecode(str(q.name).rstrip(".").rstrip(zone).replace(".", ""))
            print_debug(DEBUG_MODULE, "decoded qtext = {}".format(qtext))

            resp = dns.message.make_response(msg)
            resp.flags |= dns.flags.AA
            resp.set_rcode(0)
            if (resp):
                data = dnsencode(qtext) # TODO: for now we just reply
                resp.answer.append(dns.rrset.from_text(q.name, 7600, dns.rdataclass.IN, dns.rdatatype.TXT, str(data, 'utf-8')))
                print_debug(DEBUG_MODULE, "responding with: {}".format(str(data, 'utf-8')))
                socket.sendto(resp.to_wire(), self.client_address)
            else:
                print_error("error creating response for DNS query: " + msg)
                return



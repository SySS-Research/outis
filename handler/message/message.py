
from ..transport.transport import Transport
from helpers.log import *
import struct

MESSAGE_HEADER_LEN = 5
DEBUG_MODULE = "Message"


class Message:
    """
    Message object for the transport communication
    Message format: Type-Byte 4-Byte-Length Content-of-that-Length
    Everything should be network byte order
    """

    def __init__(self):
        self.type = None
        self.length = None
        self.content = None
        self.ready = False

    def parseFromTransport(self, transport):
        """ parse a message object from the agent over the given transport object """
        
        if not isinstance(transport, Transport):
            print_error(str(transport)+" is not a transport")
            return
        
        buf = b''
        while len(buf) < MESSAGE_HEADER_LEN:
            morebuf = transport.receive(leng=MESSAGE_HEADER_LEN-len(buf))
            if not morebuf:
                break
            buf += morebuf
        if not buf:
            print_error("Invalid empty message")
            return
        if len(buf) < MESSAGE_HEADER_LEN:
            print_error("Invalid message (too short): "+str(buf))
            return
        
        print_debug(DEBUG_MODULE+" Parse", "header: "+str(buf[:MESSAGE_HEADER_LEN]))
        self.type, self.length = struct.unpack("!BI", buf[:MESSAGE_HEADER_LEN])
        buf = buf[MESSAGE_HEADER_LEN:]
        
        print_debug(DEBUG_MODULE+" Parse", "type: "+str(self.type))
        print_debug(DEBUG_MODULE+" Parse", "length: "+str(self.length))
        while len(buf) < self.length:
            morebuf = transport.receive(leng=min(1024, self.length))
            if not morebuf:
                print_error("Connection ended before end of message, message so far: "+str(buf))
                return
            buf += morebuf
        
        self.content = buf[:self.length]
        self.ready = True
        print_debug(DEBUG_MODULE+" Parse", "content: "+str(self.content))
        print_debug(DEBUG_MODULE+" Parse", "additionaldata: "+str(buf[self.length:]))
        
    def create(self, typ, content):
        """ create a new message from these fields """

        self.type = typ
        self.length = len(content)
        print_debug(DEBUG_MODULE+" Create", "type: "+str(self.type))
        print_debug(DEBUG_MODULE+" Create", "length: "+str(self.length))
        self.content = content
        print_debug(DEBUG_MODULE+" Create", "content: "+str(self.content))
        self.ready = True
    
    def sendToTransport(self, transport):
        """ send the message over the given transport object to the agent """

        if not isinstance(transport, Transport):
            print_error(str(transport)+" is not a transport")
            return
        
        buf = struct.pack("!BI", self.type, self.length) + self.content
        transport.send(buf)

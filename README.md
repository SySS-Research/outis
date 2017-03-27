
syssspy is a custom Remote Administration Tool (RAT) or something like than. Think Meterpreter or Empire-Agent. However, the focus of this tool is neither an exploit toolkit (there are no exploits) nor persistant management of targets. The focus is to communicate between server and target system and to transfer files, share sockets, spawn shells and so on using varios methods and platforms.


Dependencies for the Handler
============================

 * python3
 * python-progressbar2
 * python-dnspython
 * python-crypto
 * python-pyopenssl (version 16.1.0 or newer is required, check as follows)
 ```
    $ python3 -c 'import OpenSSL; print(OpenSSL.version.__version__)'
 ```
 * and probably more...


Installation
============

Clone this git with recursive flag to also clone its submodules in the thirdpartytools folder:

```
git clone --recursive git@git.syss.intern:finn.steglich/syssspy.git
```

The handler runs on Python 3. Install its dependencies and run it. It will generate stagers, agents and everything else for you.

To bind low ports without needing root privileges, consider using the wrapper binary in my capability-wrappers collection:

```
git clone https://git.syss.intern/finn.steglich/capability-wrappers.git
cd capability-wrappers
vim syssspy.c # to edit the paths
make syssspy
```


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


Currently Supported Extras
==========================

 * When using DNS transport with stager and powershell, you can stage the tool dnscat2 / dnscat2-powershell from the thirdpartytools directory instead of the default syssspy agent. Set the platform option AGENTTYPE to DNSCAT2 (will take a while, but uses only DNS to stage) or DNSCAT2DOWNLOADER (tries to download using HTTPS).


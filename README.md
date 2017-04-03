
syssspy is a custom Remote Administration Tool (RAT) or something like than. Think Meterpreter or Empire-Agent. However, the focus of this tool is neither an exploit toolkit (there are no exploits) nor persistant management of targets. The focus is to communicate between server and target system and to transfer files, share sockets, spawn shells and so on using varios methods and platforms.


Dependencies for the Handler
============================

Archlinux users can install the following packages:

 * python3
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

Marcel succeded with python virtual environments and the following pip packages:

```
$ pip freeze
appdirs==1.4.3
asn1crypto==0.22.0
cffi==1.10.0
crypto==1.4.1
cryptography==1.8.1
dnspython==1.15.0
idna==2.5
Naked==0.1.31
packaging==16.8
progressbar2==3.16.0
pycparser==2.17
pycrypto==2.6.1
pyOpenSSL==16.2.0
pyparsing==2.2.0
python-utils==2.0.1
PyYAML==3.12
requests==2.13.0
shellescape==3.4.1
six==1.10.0
```


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
 * upload and download of files


Currently Supported Extras
==========================

 * When using DNS transport with stager and powershell, you can stage the tool dnscat2 / dnscat2-powershell from the thirdpartytools directory instead of the default syssspy agent. Set the platform option AGENTTYPE to DNSCAT2 (will take a while, but uses only DNS to stage) or DNSCAT2DOWNLOADER (tries to download using HTTPS).


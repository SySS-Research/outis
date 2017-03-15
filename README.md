
syssspy is a custom Remote Administration Tool (RAT) or something liket than. Think Meterpreter or Empire-Agent.
However, the focus of this tool ist not exploit toolkit (there are no exploits) or persistant management of targets.
The focus is to communicate between server and target system and to transfer files, share sockets, spawn shells
and so on using varios methods and platforms


Dependencies
============

 * python3
 * python-progressbar2 (for progressbars, duh!)
 * and probably more...


Installation
============

Clone this git with recursive flag to also clone its submodules in the thirdpartytools folder:

```
git clone --recursive git@git.syss.intern:finn.steglich/syssspy.git
```

The tool runs on Python 3. Install its dependencies and run it. It will generate stagers, agents and everything else
for you.

To bind low ports without needing root privileges, consider using the wrapper binary in my capability-wrappers
collection:

```
git clone https://git.syss.intern/finn.steglich/capability-wrappers.git
```


Terms
=====

 * **agent**: software, that runs on the victim system
 * **handler**: software, that parses your commands and leads the agents (usually it runs on your server)
 * **stager**: short script that downloads the agent (using the transport module) and runs it
 * **transport**: communication channel between handler/stager and agent, e.g. ReverseTCP
 * **platform**: victim architecture to use for stager/agent scripts, e.g. PowerShell


Currently Supported Plattforms
==============================

 * PowerShell (partial)


Currently Supported Transports
==============================

 * Reverse TCP
 * DNS (partial)


Currently Supported Cryptography
================================

 * Agent stages can be encoded (for obfuscation, not for security) using cyclic XOR
 * Agent stages can be authenticated using RSA signatures and pinned certificates
 * Transport connections can be encrypted / authenticated using TLS and pinned certificates

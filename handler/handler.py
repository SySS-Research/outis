#!/usr/bin/python3

from transport.reversetcp import TransportReverseTcp
from transport.message import Message
from helpers.log import print_message, print_error

transport = TransportReverseTcp()
transport.open()

message0 = Message()
message0.create(0x01, b'Test0')
message0.sendToTransport(transport)

message1 = Message()
message1.parseFromTransport(transport)

message2 = Message()
message2.create(0x01, b'TestBack')
message2.sendToTransport(transport)

transport.close()



#$ ./handler.py
#[+] TCP Transport listening on 0.0.0.0:8080
#[+] Connection from 127.0.0.1:46148
#[D] [Message] header: b'\x01\x00\x00\x00\x04'
#[D] [Message] type: 1
#[D] [Message] length: 4
#[D] [Message] content: b'Test'
#[D] [Message] additionaldata: b''
#[D] [Message] type: 1
#[D] [Message] length: 8
#[D] [Message] content: b'TestBack'
#
#$ echo -ne '\x01\x00\x00\x00\x04Test' | ncat -v 127.0.0.1 8080 | xxd
#Ncat: Version 7.31 ( https://nmap.org/ncat )
#Ncat: 9 bytes sent, 13 bytes received in 0.03 seconds.
#00000000: 0100 0000 0854 6573 7442 6163 6b         .....TestBack


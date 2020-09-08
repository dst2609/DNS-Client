#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Created on Wed Feb 19 22:07:57 2020
@authors:  DEVARSH THAKER
"""

#necessary imports
import sys
import socket #used to create connection with DNS server
from random import randint
import codecs
import re

#####----- 1 DNS QUERY -----#####

### Get Host Name from command Line argument
try:
    host_name = str(sys.argv[1])
except IndexError:
    print("Enter hostname in following format-->")
    print("<dns-client> <hostname>")
    print("Exiting...")
    sys.exit(0)

#get each section in hostname for QNAME
host_name_section = host_name.split(".")

print("Preparing DNS query..")
### Starting with HEADER
### ----------------------
### Generate a random hexadecimal Header ID 
### Size: 16 bits 
ID = str(hex(randint(1,65534))[2:])

###hex representation of the flags
#in binary: 0  0000   0  0  1  0  000 0000
#           QR OPCODE AA TC RD RA Z   RCODE
# therefore, the hex representation of the above binary string is as follows.
FLAGS = "0100"
### Sending One Hostname Query at a time
### 16 bits
QDCOUNT = hex(1)[2:].zfill(4)
ANCOUNT = hex(0)[2:].zfill(4)
NSCOUNT = hex(0)[2:].zfill(4)
ARCOUNT = hex(0)[2:].zfill(4)

#Finalize header
HEADER = ID + FLAGS + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT

### Starting with QUESTION SECTION
### ----------------------

#QNAME
Qname_list = []
for section in host_name_section:
    ###get length of the section of url
    Qname_list.append(hex(len(section))[2:].zfill(2))
    for char in section:
        ###get ASCII code Octet for each char in section of url
        Qname_list.append(hex((ord(char)))[2:])
###Qname terminates with 00
Qname_list.append("00")
QNAME = ''.join(Qname_list)

#QTYPE
QTYPE = hex(1)[2:].zfill(4)

#QCLASS
### 0x0001 for INTERNET
QCLASS = hex(1)[2:].zfill(4)

QUESTION = QNAME + QTYPE + QCLASS

DNS_QUERY = HEADER + QUESTION

###SEND THE DNS QUERY

print("Contacting DNS server..")

#by default DNS operates on port 53
PORT = 53 

#because this assignment is graded only for Google's public DNS Server
IP_ADDRESS = "8.8.8.8" 

#create a socket object
udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#SOCK_DGRAM tells the socket object that UDP is going to be used instead of TCP

#used to catch timeout errors after giving it 5 seconds to send the query
udp_socket.settimeout(5.0)

print("Sending DNS query..")

#send the query to dns server
try:
    udp_socket.sendto(bytes.fromhex(DNS_QUERY), (IP_ADDRESS, PORT))
#OSError when problem with internet connection
except OSError as e:
    print("No Internet or problem with Internet. Exiting...")
    sys.exit(0)
except ValueError as e:
    print("DNS_QUERY sending error. Try again!")
    sys.exit(0)
    
#create message string
message = ""

#in case packet gets dropped, try 3 times
for i in range(3):
    print("DNS response received (attempt",i+1 , "of 3)")
    try:
        message, address = udp_socket.recvfrom(2048)
        if message:
            break
    #resend the query in case the server doesn't respond
    except OSError as msg:
        udp_socket.sendto(bytes.fromhex(DNS_QUERY), (IP_ADDRESS, PORT))
        print("Trying again.")
    except timeout as msg:
        udp_socket.sendto(bytes.fromhex(DNS_QUERY), (IP_ADDRESS, PORT))
        print("Trying again.")


if not message:
    print("Timeout: No response received after 3 attempts.")

#close socket connection  
udp_socket.close()

if message:
    #index where question starts
    a = 24
    b = 26
    count = 0
    qname = ""
    ###EXTRACT QNAME
    y = int(message.hex()[a:b])
    while 1:
        qname += str(message.hex()[b:b+2])
        b += 2
        count += 1
        if count == y:
            y = int(message.hex()[b:b+2])
            qname += " "
            count = 0
            b += 2
            if y == 0:
                break
    ###QTYPE
    qtype = message.hex()[b:b+4]
    
    ###QCLASS
    qclass = message.hex()[b+4:b+8]
    
    ###QNAME
    qname = re.sub("\s+", "2e", qname.strip())
    bytes_object = bytes.fromhex(qname)
    QNAME = bytes_object.decode("ASCII")

    RCODE = str(message.hex()[7]) ##last four bits of the flag

    ###ID
    id_ = message.hex()[0:4]
    ###FLAGS
    flags = "{0:08b}".format(int(str(message.hex()[4:8]), 16))
    
    qr = flags[0]
    opcode = flags[1:5]
    aa = flags[5]
    tc = flags[6]
    rd = flags[7]
    ra = flags[8]
    z = flags[9:12]
    rcode = flags[12:16]
    qdcnt = int(message.hex()[8:12])
    ancnt = int(message.hex()[12:16])
    nscnt = int(message.hex()[16:20])
    arcnt = int(message.hex()[20:24])
    
    #print DNS response header and question
    print("Processing DNS response..")
    print("----------------------------------------")
    print("header.ID = "+id_)
    print("header.QR = "+qr)
    print("header.Opcode =",int(opcode))
    print("header.AA =",int(aa))
    print("header.TC =",int(tc))
    print("header.RD =",int(rd))
    print("header.RA =",int(ra))
    print("header.Z =",int(z))
    print("header.RCODE =",int(rcode))
    print("header.QDCOUNT =", int(qdcnt))
    print("header.ANCOUNT =", int(ancnt))
    print("header.NSCOUNT =", int(nscnt))
    print("header.ARCOUNT =", int(arcnt))
    print("---><---")
    print("question.QNAME = " + QNAME)
    print("question.QTYPE = ", int(QTYPE))
    print("question.QCLASS = ", int(QCLASS))

    #index where answer query starts in response
    ans_start = b + 8
    #current ancount
    cr_ancnt = 0
    while (cr_ancnt < ancnt):
        
        print("---><---")
        #extract data from Resource Record(s)
        ans_name = message.hex()[ans_start:ans_start+4]
    
        ans_type = int(message.hex()[ans_start+4:ans_start+8])
    
        ans_class = int(message.hex()[ans_start+8:ans_start+12])
        #ttl is in seconds
        ttl_hex = message.hex()[ans_start+12:ans_start+20]
        ttl_byte = codecs.decode(ttl_hex, "hex")
        ttl=int.from_bytes(ttl_byte, byteorder='big')
        
        rdlength = int(message.hex()[ans_start+20:ans_start+24])
        ###EXTRACT IP ADDRESS
        IP = ""
        #check RCODE
        if RCODE == "0":
#            i = -4 - (cr_ancnt*16)
            i = -(rdlength) - (cr_ancnt*16)
            ip_address = []
            #if more than 1 ancount- get ip from all RR's
            while 1:
                ip_address.append(str(message[i]))
                i += 1
                if i == -0 - (cr_ancnt*16):
                    break
            IP = ".".join(ip_address)
            
        elif RCODE == "1":
            print("Format Error: unable to interpret the query.")
        elif RCODE == "2":
            print("Server Failure: unable to process the query. There was a problem with the name server.")
        elif RCODE == "3":
            print("Name Error: domain name referenced in the query does not exist.")
        elif RCODE == "4":
            print("Not Implemented: the server does not support the requested kind of query.")
        elif RCODE == "5":
            print("Refused: server refuses to perform the specified operation for policy reasons. Check RFC for more information.")

        cr_ancnt = cr_ancnt + 1
        ##print answer messages
        print("answer.NAME = " + QNAME)
        print("answer.TYPE = ", int(ans_type))
        print("answer.CLASS = ", int(ans_class))
        print("answer.TTL =", ttl)
        print("answer.RDLENGTH =", int(rdlength))
        print("answer.RDATA = "+IP)
#end

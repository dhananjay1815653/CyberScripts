#from scapy.all import *

import socket
from scapy.all import *
from scapy.layers import dns, inet
from base64 import b64decode
from time import sleep

def sendResponse(query,ip):
    question = dns.DNS(query["Raw"].load).qd
    answer = dns.DNSRR(rrname=question.qname,ttl=1000,rdata=ip)
    response = inet.IP(src=query["IP"].dst, dst=query["IP"].src)/dns.UDP(dport=query["UDP"].sport,sport=query["UDP"].dport)/dns.DNS(id=dns.DNS(query["Raw"].load).id,qr=1,qdcount=1,ancount=1,qd=dns.DNS(query["Raw"].load).qd,an=answer)
    sleep(1)
    print(response)
    send(response)

extracted = ""

def extractData(x):
    #b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0eVGhpcyBpcyBEaA\x07rachhuu\x03com\x00\x00\x01\x00\x01'
    input=dns.DNS(x["Raw"].load)
    #result = input.decode("utf-8").replace('\x00',' ').replace('\x0e',' ').replace('\x01',' ').replace('\x07','.').replace('\x03','.').split()[0]
    #d = bytes(result,"utf-8")
        
    global extracted
    if x.haslayer("Raw") and x["UDP"].dport == 1396:
        domain = input.qd.qname
        ind = domain.index(bytes(".","utf-8"))
        data = domain[:ind]
        padnum = (4-(len(data)%4))%4
        data += bytes("="*padnum,"utf-8")
        try:
            decoded = b64decode(data).decode("utf-8")
            if decoded == "R":
                response = sendResponse(x,"10.0.0.2")
                print("End transmission")
                print(extracted)
                extracted = ""
            else:
                extracted += decoded
                print("2",decoded)
                response = sendResponse(x,"10.0.0.1")
        except Exception as e:
            print(e)
            response = sendResponse(x,"10.0.0.0")

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.bind(("",1396))
#s.listen(10)

sniff(filter="port 1396", prn=extractData)


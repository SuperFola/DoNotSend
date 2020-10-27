#!/usr/bin/env python3

from scapy.sendrecv import sr1
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP

from converter import decode, encode
from utils import DNSHeaders


class Client:
    def __init__(self, dns_server: str, domain: str, verbosity: int=0):
        self.dns_server = dns_server
        self.domain = domain
        self.verb = verbosity

    def send(self, message: str):
        crafted_domain = f"{encode(message)}.{self.domain}"

        pkt = IP(dst=self.dns_server)
        pkt /= UDP(dport=53)
        pkt /= DNS(rd=0, qr=DNSHeaders.QR.Query, qd=DNSQR(qname=crafted_domain))

        answers = sr1(pkt, verbose=self.verb)
        return answers[DNS]

    def recv(self, pkt: DNS):
        print(f"ANCOUNT: {pkt.ancount}")
        for i in range(pkt.ancount):
            print(f"Message {i}: {pkt.an[i].rrname}")


if __name__ == "__main__":
    client = Client("127.0.0.1", "12f.pl", verbosity=2)
    pkt = client.send("hello world")
    client.recv(pkt)
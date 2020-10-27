#!/usr/bin/env python3

import logging

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sr1

from converter import decode, encode
from utils import DNSHeaders, init_logger


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

        answer = sr1(pkt, verbose=self.verb, timeout=1)
        return answer[DNS] if answer is not None else None

    def recv(self, pkt: DNS):
        if pkt is not None:
            logging.debug(f"ANCOUNT: {pkt.ancount}")
            for i in range(pkt.ancount):
                logging.info(f"Message {i}: {pkt.an[i].rrname}")
        else:
            logging.warn("Packet was none, most likely timeout")


if __name__ == "__main__":
    init_logger()
    client = Client("127.0.0.1", "12f.pl", verbosity=2)
    pkt = client.send("hello world")
    client.recv(pkt)

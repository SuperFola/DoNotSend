#!/usr/bin/env python3

import sys
import socket
import logging

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sr1

from converter import Domain, Content
from utils import DNSHeaders, init_logger, get_ip_from_hostname


class Client:
    def __init__(self, domain: str, ip: str, verbosity: int = 0):
        self.dns_server = ip
        self.domain = domain
        self.verb = verbosity

    def send(self, message: str):
        crafted_domain = f"{Domain.encode(message)}.{self.domain}"
        logging.debug("crafted domain: %s", crafted_domain)

        pkt = IP(dst=self.dns_server)
        pkt /= UDP(dport=53)
        pkt /= DNS(
            rd=0,
            qr=DNSHeaders.QR.Query,
            qd=DNSQR(
                qname=crafted_domain,
                qtype=DNSHeaders.Type.HostAddr,
            ),
        )

        answer = sr1(pkt, verbose=self.verb, timeout=1)
        return answer[DNS] if answer is not None else None

    def recv(self, pkt: DNS):
        if pkt is not None:
            logging.debug(f"ANCOUNT: {pkt.ancount}")
            for i in range(pkt.ancount):
                rrname = pkt.an[i].rrname.decode("utf-8")
                logging.info("Message %i: %s", i, rrname[:-1])
                logging.info("Decoded: %s", Content.decode(rrname[:-1]))
            logging.info(pkt[DNS].summary())
        else:
            logging.warn("Packet was none, most likely timeout")


if __name__ == "__main__":
    init_logger()
    if len(sys.argv) < 2:
        logging.error("Usage: %s hostname", sys.argv[0])
        sys.exit(-1)

    ip = get_ip_from_hostname(sys.argv[1])
    if ip is None:
        sys.exit(-1)

    client = Client(sys.argv[1], ip, verbosity=2)
    pkt = client.send("hello world")
    client.recv(pkt)

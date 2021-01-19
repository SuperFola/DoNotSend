#!/usr/bin/env python3

import sys
import socket

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP, ICMP, IPerror
from scapy.sendrecv import sr1

from converter import Domain, Content
from packet import Packet
from utils import DNSHeaders, init_logger, get_ip_from_hostname


logger = None


class Client:
    def __init__(self, domain: str, ip: str, verbosity: int = 0):
        self.dns_server = ip
        self.domain = domain
        self.verb = verbosity

    def send(self, message: str):
        crafted_domain = f"{Domain.encode(message)}.{self.domain}"
        logger.debug("crafted domain: %s", crafted_domain)

        packet = Packet.build_query(
            {"dst": self.dns_server, "dns": {"qname": crafted_domain}}, self.domain,
        )
        answer = sr1(packet.packet, verbose=self.verb, timeout=1)
        if answer.haslayer(ICMP) or answer.haslayer(IPerror):
            logger.debug(answer.show())
            logger.critical("Unreachable host or filtered port")
            return None
        return answer[DNS] if answer is not None else None

    def recv(self, pkt: DNS):
        if pkt is not None:
            packet = Packet(pkt, self.domain)
            for i, (rrname, rdata) in enumerate(packet.answers):
                logger.info("Message %i (%s): %s", i, rrname, rdata)
                try:
                    logger.info("Decoded: %s", Content.decode(rdata))
                except Exception:
                    logger.warning("Couldn't decode message")
            logger.debug(packet.dns.summary())
        else:
            logger.warning("Packet was none, most likely timeout")


if __name__ == "__main__":
    logger = init_logger()
    if len(sys.argv) < 2:
        logger.error("Usage: %s hostname", sys.argv[0])
        sys.exit(-1)

    ip = get_ip_from_hostname(sys.argv[1])
    if ip is None:
        sys.exit(-1)

    client = Client(sys.argv[1], ip)
    pkt = client.send("hello world")
    client.recv(pkt)

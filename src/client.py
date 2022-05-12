#!/usr/bin/env python3

import sys

from scapy.layers.dns import DNS, struct
from scapy.layers.inet import UDP, ICMP, IPerror
from scapy.sendrecv import sr1

from converter import Domain, Content
from packet import Packet
from utils import init_logger, get_ip_from_hostname


logger = None


class Client:
    def __init__(self, domain: str, ip: str, port: int = 53, verbosity: int = 0):
        self.dns_server = ip
        self.dns_server_port = port
        self.domain = domain
        self.verb = verbosity

    def send(self, message: str):
        crafted_domain = f"{Domain.encode(message)}.{self.domain}"

        packet = Packet.build_query(
            {
                "dst": self.dns_server,
                "dport": self.dns_server_port,
                "dns": {"qname": crafted_domain},
            },
            self.domain,
        )
        answer = sr1(packet.packet, verbose=self.verb, timeout=1)
        if answer.haslayer(ICMP) or answer.haslayer(IPerror):
            logger.debug(answer.show())
            logger.critical("Unreachable host or filtered port")
            return None

        # if we are using a port other than 53, then scapy will not
        # parse the DNS layer automatically
        if DNS not in answer:
            try:
                dns_layer = DNS(answer[UDP].payload.load)
            except struct.error:
                logger.error("UDP payload of answer is not a valid DNS packet")
                return None
            answer[UDP].remove_payload()
            answer /= dns_layer

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
        logger.error("Usage: %s hostname[:port] [message]", sys.argv[0])
        sys.exit(-1)

    # seperate hostname and optional port
    hostname_and_port = sys.argv[1].split(":")
    hostname = hostname_and_port[0]
    port = 53
    if len(hostname_and_port) == 2:
        port = int(hostname_and_port[1])

    ip = get_ip_from_hostname(hostname)
    if ip is None:
        sys.exit(-1)

    client = Client(hostname, ip, port)
    pkt = client.send("hello world" if len(sys.argv) == 2 else sys.argv[2])
    client.recv(pkt)

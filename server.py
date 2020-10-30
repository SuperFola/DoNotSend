#!/usr/bin/env python3

import sys
import socket
import logging

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import send, sniff

from converter import Domain, Content
from packet import Packet
from utils import DNSHeaders, DNSAnswer, init_logger, get_ip_from_hostname


class Server:
    def __init__(self, interface: str, domain: str, host_ip: str):
        self.interface = interface
        self.host_ip = host_ip
        self.domain = domain

    def dns_responder(self, pkt: IP):
        packet = Packet(pkt, self.domain)

        if packet.is_valid_dnsquery():
            print(pkt[0].show())
            subdomain = packet.subdomain_from_qname
            logging.debug("subdomain: %s", subdomain)
            data = Domain.decode(subdomain)
            logging.debug("decoded: %s", data)

            # keep destination
            logging.debug("packet from %s:%i", packet.src, packet.sport)
            answer = Packet.build_reply(
                {
                    "src": self.host_ip,
                    "dst": packet.src,
                    "dport": packet.sport,
                    "dns": {
                        "id": packet.id,
                        # TODO ensure that we're under the 500 bytes limit
                        "messages": [
                            DNSRR(
                                rrname=packet.qname,
                                rdata=Content.encode("test"),
                                type=DNSAnswer.Type.Text,
                            ),
                        ],
                    },
                },
                self.domain,
            )

            logging.debug("incomming packet type: %s", hex(packet.question.qtype))

            logging.debug(answer.dns.summary())
            send(answer.packet, verbose=2, iface=self.interface)

    def run(self):
        logging.info(f"DNS responder started on {self.host_ip}:53")
        sniff(
            filter=f"udp port 53 and ip dst {self.host_ip}",
            prn=self.dns_responder,
            iface=self.interface,
        )


if __name__ == "__main__":
    init_logger()
    if len(sys.argv) < 3:
        logging.error("Usage: %s interface hostname", sys.argv[0])
        sys.exit(-1)

    ip = get_ip_from_hostname(sys.argv[2])
    if ip is None:
        sys.exit(-1)

    server = Server(sys.argv[1], sys.argv[2], ip)
    server.run()

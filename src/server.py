#!/usr/bin/env python3

import binascii
import socket
import sys
import threading

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import send, sniff

from converter import Content, Domain
from packet import Packet
from utils import DNSAnswer, DNSHeaders, get_ip_from_hostname, init_logger


def socket_server(ip: str):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((ip, 53))
    while True:
        s.recvfrom(1024)
    s.close()


class Server:
    def __init__(self, interface: str, domain: str, host_ip: str):
        self.interface = interface
        self.host_ip = host_ip
        self.domain = domain
        self.logger = init_logger()

    def on_query(self, message: str, src_ip: str) -> str:
        return "test"

    def dns_responder(self, pkt: IP):
        packet = Packet(pkt, self.domain)

        if packet.is_valid_dnsquery():
            self.logger.info("got a packet from %s:%i", packet.src, packet.sport)

            subdomain = packet.subdomain_from_qname.split('.')[0]
            self.logger.debug("subdomain: %s", subdomain)

            try:
                data = Domain.decode(subdomain)
            except binascii.Error:
                # couldn't decode, drop the packet and do nothing
                return

            # keep destination
            answer = Packet.build_reply(
                {
                    "src": self.host_ip,
                    "dst": packet.src,
                    "dport": packet.sport,
                    "dns": {
                        "id": packet.id,
                        "question": packet.question,
                        # TODO ensure that we're under the 500 bytes limit
                        "messages": [
                            DNSRR(
                                rrname=packet.qname,
                                rdata=Content.encode(self.on_query(data, packet.src)),
                                type=DNSAnswer.Type.Text,
                                ttl=1024,
                            ),
                        ],
                    },
                },
                self.domain,
            )

            self.logger.debug("Answering %s", answer.dns.summary())
            send(answer.packet, verbose=0, iface=self.interface)

    def run(self):
        # bind a UDP socket server on port 53, otherwise we'll have
        # ICMP type 3 error as a client, because the port will be seen
        # as unreachable (nothing being binded on it)
        t = threading.Thread(target=socket_server, args=(self.host_ip, ))
        t.start()

        self.logger.info(f"DNS responder started on {self.host_ip}:53")
        sniff(
            filter=f"udp port 53 and ip dst {self.host_ip}",
            prn=self.dns_responder,
            iface=self.interface,
        )

        t.join()


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: %s interface hostname" % sys.argv[0])
        sys.exit(-1)

    ip = get_ip_from_hostname(sys.argv[2])
    if ip is None:
        sys.exit(-1)

    server = Server(sys.argv[1], sys.argv[2], ip)
    server.run()

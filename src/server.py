#!/usr/bin/env python3

import binascii
import os
import socket
import sys
import threading
from configparser import ConfigParser
from typing import List

from scapy.layers.dns import DNS, DNSQR, DNSRR, dnstypes
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import send, sniff

from converter import Content, Domain
from packet import Packet
from utils import DNSAnswer, DNSHeaders, get_ip_from_hostname, init_logger


def socket_server(ip: str):
    # bind UDP socket to port 53
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((ip, 53))
    # and read until the end of the world
    while True:
        s.recvfrom(1024)
    s.close()


class Server:
    @staticmethod
    def from_file(filename: str):
        if not os.path.exists(filename):
            raise FileNotFoundError(filename)

        config = ConfigParser()
        config.read(filename)

        return Server(
            config['server']['interface'],
            config['server']['domain'],
            config['server']['host_ip'],
            config
        )

    def __init__(self, iface: str, domain: str, ip: str, config: ConfigParser = None):
        self.interface = iface
        self.host_ip = ip
        self.domain = domain
        self.config = config

        # subdomain => function(msg, ip, domains)
        self.subservers = {}

        self.logger = init_logger()

    def register(self, **subservers):
        self.subservers.update(subservers)

    def on_query(self, message: str, src_ip: str, domains: List[str]) -> str:
        if domains and self.subservers.get(domains[0]):
            return self.subservers[domains[0]](message, src_ip, domains)
        return "test"

    def _make_message(self, qname: str, content: str) -> DNSRR:
        return DNSRR(
            rrname=qname,
            rdata=Content.encode(content),
            type=DNSAnswer.Type.Text,
            ttl=self.config["packets"]["ttl"] if self.config else 60,
        )

    def _make_txt(self, packet: Packet) -> Packet:
        try:
            subdomain, *domains = packet.subdomain_from_qname.split('.')
            domains = domains[::-1]
            data = Domain.decode(subdomain)
        except binascii.Error:
            # couldn't decode, drop the packet and do nothing
            return

        return Packet.build_reply(
            {
                "src": self.host_ip,
                "dst": packet.src,
                "dport": packet.sport,
                "dns": {
                    "id": packet.id,
                    "question": packet.question,
                    "messages": [
                        self._make_message(
                            packet.qname,
                            self.on_query(data, packet.src, domains)
                        ),
                    ],
                },
            },
            self.domain,
        )

    def _make_a(self, packet: Packet) -> Packet:
        if self.config is None:
            return

        # if we receive a DNS A query for a subdomain, answer it with an ip from
        # the configuration file
        if packet.qname in self.config.sections():
            return Packet.build_reply(
                {
                    "src": self.host_ip,
                    "dst": packet.src,
                    "dport": packet.sport,
                    "dns": {
                        "id": packet.id,
                        "question": packet.question,
                        "messages": [
                            DNSRR(
                                rrname=packet.qname,
                                rdata=self.config[packet.qname]["ip"],
                                type=DNSAnswer.Type.HostAddr,
                                ttl=self.config[packet.qname]["ttl"],
                            ),
                        ],
                    },
                },
                self.domain,
            )

    def _dns_responder(self, pkt: IP):
        packet = Packet(pkt, self.domain)
        answer = None

        self.logger.info(
            "[DNS %s] Source %s:%i - on %s",
            dnstypes[packet.question.qtype],
            packet.src,
            packet.sport,
            packet.qname
        )

        # reject every packet which isn't a DNS TXT query
        if packet.is_valid_dnsquery("A"):
            answer = self._make_txt(packet)
        elif packet.is_valid_dnsquery("TXT"):
            answer = self._make_a(packet)

        if answer is not None:
            send(answer.packet, verbose=0, iface=self.interface)

    def run(self):
        # bind a UDP socket server on port 53, otherwise we'll have
        # ICMP type 3 error as a client, because the port will be seen
        # as unreachable (nothing being binded on it)
        t = threading.Thread(target=socket_server, args=(self.host_ip, ))
        t.start()

        self.logger.info(f"DNS sniffer started on {self.host_ip}:53")
        sniff(
            filter=f"udp port 53 and ip dst {self.host_ip}",
            prn=self._dns_responder,
            iface=self.interface,
        )

        t.join()


def main(**subservers):
    if len(sys.argv) != 2 and len(sys.argv) != 3:
        print(sys.argv)
        print("Usage: %s interface hostname" % sys.argv[0])
        print("       %s config_file.ini" % sys.argv[0])
        sys.exit(-1)

    server = None

    if len(sys.argv) == 3:
        ip = get_ip_from_hostname(sys.argv[2])
        if ip is None:
            print("Couldn't resolve IP from hostname, consider using a config file")
            sys.exit(-1)

        server = Server(sys.argv[1], sys.argv[2], ip)
    elif len(sys.argv) == 2:
        server = Server.from_file(sys.argv[1])

    if server is not None:
        server.register(**subservers)
        server.run()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3

import operator as op
from functools import reduce
from random import randint

from scapy.layers.dns import DNS, DNSQR, DNSRR, dnstypes
from scapy.layers.inet import IP, UDP

from utils import DNSHeaders


def build_tos(
    precedence: int, lowdelay: bool, throughput: bool, reliability: bool, lowcost: bool
) -> int:
    """Building IP Type of Service value

    Args:
        precedence (int): intended to denote the importance or priority of the datagram
            0b1000   --   minimize delay
            0b0100   --   maximize throughput
            0b0010   --   maximize reliability
            0b0001   --   minimize monetary cost
            0b0000   --   normal service
        lowdelay (bool): low (True), normal (False)
        throughput (bool): high (True) or low (False)
        reliability (bool): high (True) or normal (False)
        lowcost (bool): minimize memory cost (True)

    Returns:
        int: type of service as describe in the RFC 1349 and 791
    """
    return (
        (lowcost << 1)
        + (reliability << 2)
        + (throughput << 3)
        + (lowdelay << 4)
        + (max(min(precedence, 0b111), 0b000) << 5)
    )


class Packet:
    @staticmethod
    def build_query(layer: dict, domain: str) -> object:
        """Build a DNS query packet

        Args:
            layer (dict): dict of the different layer properties and values
            domain (str): the domain the packet is from

        Returns:
            object: a Packet object
        """
        pkt = IP(dst=layer["dst"], tos=build_tos(1, 0, 1, 0, 0))
        pkt /= UDP(sport=randint(0, 2 ** 16 - 1), dport=53)
        pkt /= DNS(
            # random transaction id
            id=randint(0, 2 ** 16 - 1),
            rd=1,  # recursion desired
            qr=DNSHeaders.QR.Query,
            # requests must be of type TXT otherwise our answers (of type TXT)
            # don't get transmitted if recursion occured
            qd=DNSQR(qname=layer["dns"]["qname"], qtype=DNSHeaders.Type.Text),
        )

        return Packet(pkt, domain)

    @staticmethod
    def build_reply(layer: dict, domain: str) -> object:
        """Build a DNS reply packet

        Args:
            layer (dict): dict of the different layer properties and values
            domain (str): the domain the packet is from

        Returns:
            object: a Packet object
        """
        pkt = IP(dst=layer["dst"], src=layer["src"])
        pkt /= UDP(dport=layer["dport"], sport=53)
        pkt /= DNS(
            id=layer["dns"]["id"],
            qr=DNSHeaders.QR.Answer,
            ancount=len(layer["dns"]["messages"]),
            an=reduce(op.truediv, layer["dns"]["messages"]),
            qd=layer["dns"]["question"],
        )

        return Packet(pkt, domain)

    def __init__(self, pkt: IP, domain: str):
        self._pkt = pkt
        self._domain = domain

    def is_valid_dnsquery(self, qtype: str, domain: str = "") -> bool:
        def check_qname(q: str) -> str:
            return q.endswith(f"{domain if domain else self._domain}.")

        return (
            DNS in self._pkt
            and self._pkt[DNS].opcode == DNSHeaders.OpCode.StdQuery
            and self._pkt[DNS].qr == DNSHeaders.QR.Query
            and dnstypes[self._pkt[DNSQR].qtype] == qtype
            and check_qname(self._pkt[DNSQR].qname.decode("utf-8"))
            and self._pkt[DNS].ancount == 0
        )

    @property
    def packet(self) -> IP:
        return self._pkt

    @property
    def dns(self) -> DNS:
        return self._pkt[DNS]

    @property
    def src(self) -> str:
        return self._pkt[IP].src

    @property
    def sport(self) -> int:
        return self._pkt[UDP].sport

    @property
    def question(self) -> DNSQR or None:
        if DNSQR in self._pkt:
            return self._pkt[DNSQR]
        return None

    @property
    def answers(self):
        return (
            [
                (an.rrname.decode("utf-8")[:-1], b"".join(an.rdata).decode("utf-8"))
                for an in self._pkt.an
            ]
            if self._pkt.an is not None
            else []
        )

    @property
    def id(self) -> int:
        return self._pkt[DNS].id

    @property
    def qname(self) -> str or None:
        qd = self.question
        if qd:
            return qd.qname.decode("utf-8")
        return None

    @property
    def subdomain_from_qname(self) -> str or None:
        qname = self.qname
        if qname is not None:
            return qname[: len(qname) - 2 - len(self._domain)]
        return None

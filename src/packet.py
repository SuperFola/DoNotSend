#!/usr/bin/env python3

import operator as op
from functools import reduce

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP

from utils import DNSHeaders


class Packet:
    @staticmethod
    def build_query(layer: dict, domain: str) -> object:
        pkt = IP(dst=layer["dst"], ihl=5, tos=0x28)
        pkt /= UDP(dport=53)
        pkt /= DNS(
            rd=0,  # no recursion desired
            qr=DNSHeaders.QR.Query,
            qd=DNSQR(qname=layer["dns"]["qname"], qtype=DNSHeaders.Type.Text),
        )

        return Packet(pkt, domain)

    @staticmethod
    def build_reply(layer: dict, domain: str) -> object:
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

    def is_valid_dnsquery(self) -> bool:
        def check_qname(q: str) -> str:
            return q[len(q) - len(self._domain) - 2 : len(q) - 2]

        return (
            DNS in self._pkt
            and self._pkt[DNS].opcode == DNSHeaders.OpCode.StdQuery
            and self._pkt[DNS].qr == DNSHeaders.QR.Query
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

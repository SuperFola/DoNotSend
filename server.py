#!/usr/bin/env python3

from scapy.sendrecv import send, sniff
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP

from utils import DNSHeaders


class Server:
    def __init__(self, interface: str, host_ip: str, domain: str):
        self.interface = interface
        self.host_ip = host_ip
        self.domain = domain

    def is_correct_pkt(self, pkt: IP):
        """
            opcode  (4bits)  : type of the message
            ancount (16bits) : the number of ressource records provided
        """
        check_qname = lambda q: q[len(q) - len(self.domain) - 2:len(q) - 2]

        return (
            DNS in pkt
            and pkt[DNS].opcode == DNSHeaders.OpCode.StdQuery
            and pkt[DNS].qr == DNSHeaders.QR.Query
            and check_qname(str(pkt[DNSQR].qname))
            and pkt[DNS].ancount == 0
        )

    def dns_responder(self, pkt: IP):
        if self.is_correct_pkt(pkt):
            question_record = str(pkt[DNSQR].qname)

            # keep destination
            answer = IP(dst=pkt[IP].src, src=self.host_ip)
            # specify protocol, UDP:53
            answer /= UDP(dport=pkt[UDP].sport, sport=53)

            messages = DNSRR(rrname="test", rdata=self.host_ip) / DNSRR(
                rrname="hello", rdata=self.host_ip
            )

            # craft the DNS packet
            answer /= DNS(
                id=pkt[DNS].id,
                aa=1,  # authoritative answer
                qr=DNSHeaders.QR.Answer,
                ancount=2,  # answers count
                an=messages,
            )
            send(answer, verbose=0, iface=self.interface)
            return f"DNS response for {question_record} sent to {pkt[IP].src}"

    def run(self):
        print(f"DNS responder started on {self.host_ip}:53")
        sniff(
            filter=f"udp port 53 and ip dst {self.host_ip}",
            prn=self.dns_responder,
            iface=self.interface,
        )


if __name__ == "__main__":
    server = Server("lo", "127.0.0.1", "12f.pl")
    server.run()

#!/usr/bin/env python3

from utils import IP, UDP, DNS, DNSQR, sr1, DNSHeaders

DEST = "127.0.0.1"
VERBOSE = 2


def send_msg(msg: str, dest: str):
    pkt = IP(dst=dest)
    pkt /= UDP(dport=53)
    pkt /= DNS(
        rd=0, qr=DNSHeaders.QR.Query,
        qd=DNSQR(
            qname=msg
        )
    )

    answer = sr1(pkt, verbose=VERBOSE)
    return answer[DNS]


pkt = send_msg("hello world", DEST)


print(f"ANCOUNT {pkt.ancount}")
for i in range(pkt.ancount):
    print(pkt.an[i].rrname)

#!/usr/bin/env python3

from utils import (
    sniff,
    check_if_correct_dns_request,
    DNS,
    DNSRR,
    UDP,
    IP,
    DNSQR,
    send,
    sr1,
    DNSHeaders,
)


IFACE = "lo"
DNS_SERVER_IP = "127.0.0.1"
BPF_FILTER = f"udp port 53 and ip dst {DNS_SERVER_IP}"


def dns_responder(local_ip: str):
    def get_response(pkt: IP):
        if check_if_correct_dns_request(pkt):
            question_record = str(pkt[DNSQR].qname)

            # keep destination
            spf_resp = IP(dst=pkt[IP].src, src=local_ip)
            # specify protocol, UDP:53
            spf_resp /= UDP(dport=pkt[UDP].sport, sport=53)

            answers = DNSRR(rrname="test", rdata=local_ip) / DNSRR(
                rrname="hello", rdata=local_ip
            )

            # craft the DNS packet
            spf_resp /= DNS(
                id=pkt[DNS].id,
                aa=1,  # authoritative answer
                qr=DNSHeaders.QR.Answer,
                ancount=2,  # answers count
                an=answers,
            )
            send(spf_resp, verbose=0, iface=IFACE)
            return f"DNS response for {question_record} sent to {pkt[IP].src}"

    return get_response


sniff(filter=BPF_FILTER, prn=dns_responder(DNS_SERVER_IP), iface=IFACE)

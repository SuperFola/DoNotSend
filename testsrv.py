#! /usr/bin/env python3

from scapy.all import DNS, DNSQR, DNSRR, IP, send, sniff, sr1, UDP

IFACE = "eth0"   # Or your default interface
DNS_SERVER_IP = "163.172.237.14"  # Your local IP

BPF_FILTER = f"udp port 53 and ip dst {DNS_SERVER_IP}"


def dns_responder(local_ip: str):
    def get_response(pkt: IP):
        if (DNS in pkt and pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0):
            spf_resp = IP(dst=pkt[IP].src)
            spf_resp /= UDP(dport=pkt[UDP].sport, sport=53)
            spf_resp /= DNS(
                    id=pkt[DNS].id,
                    qr=1,
                    aa=1,
                    rd=pkt[DNS].rd,
                    opcode=0,
                    ra=1,
                    z=0,
                    rcode=0,
                    qdcount=pkt[DNS].qdcount,
                    qd=pkt[DNS].qd,
                    ancount=1,
                    an=DNSRR(
                        type='A',
                        ttl=1,
                        rrname=pkt[DNSQR].qname,
                        rdata=local_ip
                    )
                )
            send(spf_resp, verbose=2, iface=IFACE)
            print(spf_resp.summary())
            return f"Spoofed DNS Response Sent: {pkt[IP].src}\n{spf_resp.show()}"

    return get_response

sniff(filter=BPF_FILTER, prn=dns_responder(DNS_SERVER_IP), iface=IFACE)

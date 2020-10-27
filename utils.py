#!/usr/bin/env python3

from scapy.layers.inet import IP
from scapy.layers.dns import DNS

class DNSHeaders:
    class QR:
        Query = 0
        Answer = 1

    class OpCode:
        StdQuery = 0
        InvQuery = 1
        SrvStatusQuery = 2

    class RCode:
        NoErr = 0
        FormatErr = 1
        ServerFailu = 2
        NameErr = 3
        NotImpl = 4
        Refused = 5


class DNSQuestion:
    class QType:
        HostAddr = 0x0001
        NameServer = 0x0002
        MailServer = 0x000F

    class QClass:
        IP = 0x0001


class DNSAnswer:
    class Type:
        HostAddr = 0x0001
        NameServer = 0x0002
        CName = 0x0005
        MailServer = 0x000F

    class Class:
        IP = 0x0001


def check_if_correct_dns_request(pkt):
    """
        opcode  (4bits)  : type of the message
        ancount (16bits) : the number of ressource records provided
    """
    return (
        DNS in pkt
        and pkt[DNS].opcode == DNSHeaders.OpCode.StdQuery
        and pkt[DNS].ancount == 0
        and pkt[DNS].qr == DNSHeaders.QR.Query
    )

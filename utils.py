#!/usr/bin/env python3

import socket
import logging


def get_ip_from_hostname(hostname: str) -> str or None:
    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror as e:
        logging.error(e)
        return None
    else:
        return ip


def init_logger(log_level: int = logging.DEBUG):
    logging.basicConfig(
        # filename="file.log",
        # encoding="utf-8",
        format="[%(asctime)s] %(levelname)s:%(message)s",
        level=log_level,
    )


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
        ServerFailure = 2
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
        Text = 0x0010
        MailServer = 0x000F

    class Class:
        IP = 0x0001

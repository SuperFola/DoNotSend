#!/usr/bin/env python3

import socket
import logging
from colorlog import ColoredFormatter


def get_ip_from_hostname(hostname: str) -> str or None:
    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror as e:
        logging.error(e)
        return None
    else:
        return ip


def init_logger(log_level: int = logging.DEBUG):
    formatter = ColoredFormatter(
        "%(cyan)s[%(asctime)s]%(reset)s in %(filename)s:%(lineno)s %(log_color)s%(levelname)-8s%(reset)s %(message)s", 
        datefmt=None,
        reset=True,
        log_colors={
            "DEBUG":    "cyan",
            "INFO":     "green",
            "WARNING":  "yellow",
            "ERROR":    "red",
            "CRITICAL": "red",
            }
        )
    logger = logging.getLogger('example')
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(log_level)
    return logger


class DNSHeaders:
    class QR:
        Query = 0
        Answer = 1

    class OpCode:
        StdQuery = 0
        InvQuery = 1
        SrvStatusQuery = 2

    class Type:
        HostAddr = 0x0001
        NameServer = 0x0002
        CName = 0x0005
        Text = 0x0010
        MailServer = 0x000F

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

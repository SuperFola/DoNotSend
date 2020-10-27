#!/usr/bin/env python3

import base64


def b32encode(data: str) -> str:
    return base64.b32encode(bytearray(data, "ascii")).decode("utf-8")


def b32decode(data: str) -> str:
    return base64.b32decode(bytearray(data, "ascii")).decode("utf-8")


def b64encode(data: str) -> str:
    return base64.b64encode(bytearray(data, "ascii")).decode("utf-8")


def b64decode(data: str) -> str:
    return base64.b64decode(bytearray(data, "ascii")).decode("utf-8")


# to be able to have multiple encoders / decoders


class Domain:
    encode = b32encode
    decode = b32decode


class Content:
    encode = b64encode
    decode = b64decode

#!/usr/bin/env python3

import base64


def b32encode(data: str) -> str:
    data_bytes = bytearray(data, "ascii")
    out = base64.b32encode(data_bytes).decode("utf-8")
    return out.replace("=", "")  # remove padding


def b32decode(data: str) -> str:
    # add padding
    data += "=" * (8 - (len(data) % 8))
    data_bytes = bytearray(data, "ascii")
    return base64.b32decode(data_bytes).decode("utf-8")


def b64encode(data: str) -> str:
    data_bytes = bytearray(data, "ascii")
    out = base64.urlsafe_b64encode(data_bytes).decode("utf-8")
    # remove padding
    return out.replace("=", "")


def b64decode(data: str) -> str:
    # add padding
    data += "=" * (4 - (len(data) % 4))
    data_bytes = bytearray(data, "ascii")
    return base64.urlsafe_b64decode(data_bytes).decode("utf-8")


# to be able to have multiple encoders / decoders


class Domain:
    encode = b32encode
    decode = b32decode


class Content:
    encode = b64encode
    decode = b64decode

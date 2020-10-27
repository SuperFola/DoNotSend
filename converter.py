#!/usr/bin/env python3

import base64


def encode(data: str) -> str:
    return base64.b32encode(bytearray(data, "ascii")).decode("utf-8")


def decode(data: str) -> str:
    return base64.b32decode(bytearray(data, "ascii")).decode("utf-8")
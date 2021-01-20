#!/usr/bin/env python3

import sys
import time
from typing import List

from server import Server
from utils import get_ip_from_hostname


class Message:
    def __init__(self, author: str, content: str):
        self.author = author
        self.content = content
        self.timestamp = time.time()
        self.seen_by = []


class ChatServer(Server):
    def __init__(self, *args):
        super().__init__(*args)

        self.messages = []
        self.users = {}

    def on_query(self, message: str, src_ip: str, domains: List[str]) -> str:
        message = message.strip()

        if src_ip not in self.users:
            # associate each new ip with its user id
            self.users[src_ip] = str(len(self.users))

        # check for commands
        if len(message) > 1 and message[0] != '/':
            self.messages.append(Message(self.users[src_ip], message))
            self.messages[-1].seen_by.append(self.users[src_ip])
            return "/ok"
        elif message == "/consult":
            # get the user unread messages list
            history = []
            # get the last 5 messages in reverse order
            for msg in self.messages[:-6:-1]:
                if self.users[src_ip] not in msg.seen_by:
                    history.append(msg)
                    # mark the message as seen
                    msg.seen_by.append(self.users[src_ip])

            # create the unread message list
            output = ""
            # append message in ascending order
            for msg in history[::-1]:
                output += f"@{msg.author} [{msg.timestamp}]: {msg.content}\n"
            return output
        return "/error"


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: %s interface hostname" % sys.argv[0])
        sys.exit(-1)

    ip = get_ip_from_hostname(sys.argv[2])
    if ip is None:
        sys.exit(-1)

    server = ChatServer(sys.argv[1], sys.argv[2], ip)
    server.run()

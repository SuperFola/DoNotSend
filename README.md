# [WIP] DoNotSend - hijacking the DNS protocol

The DNS protocol is convetionally used to ask for the IP address of a given website.

Here it's used to send messages and retrieve other messages, instead of asking for a website IP address and retrieving its IP address.

## [WIP] client

Can send a message using a DNS query, message put in qname field.

Retrieve message(s) from the an field, can receive an arbitrary amount of messages, display them in the order they are appearing (stored in the name field of the answer).

### Running the client

```shell
# needs to run as root because it is using port 53
sudo python3 client.py
```

It will send a single message (DNS request), "hello world", on a DNS server running on `127.0.0.1:53`, then it displays all the answers received.

## [WIP] server

Receive messages, read them, send back a DNS answer with two answers:
* the first contains test in the name of the answer
* the second contains hello in the name of the answer

### Running the server

```shell
# needs to run as root because it is binding port 53
sudo python3 server.py
```

Runs on `127.0.0.1:53`, and when it receives a message (DNS request), sends 2 answers in the DNS reply packet: "test" and "hello".

## Documentation

* [DNS packet structure](DNSPacketStructure.md)
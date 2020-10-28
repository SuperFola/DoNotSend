# [WIP] DoNotSend - hijacking the DNS protocol

The DNS protocol is convetionally used to ask for the IP address of a given website.

Here it's used to send messages and retrieve other messages, instead of asking for a website IP address and retrieving its IP address.

## Setup

Environment variables:
* `DNS_HOSTNAME`
* `DNS_PUBLIC_IP`
* `DNS_INTERFACE`

## client

We can include arbitrary data in the hostname which the server then can interpret and execute/relay.
Thus we put our data in the qname section of the query, encoded using base32, without the padding (we can easily recalculate it).

Currently, it's just a WIP, it sends a single message "hello world" and get responses from the server which are displayed.

### Running the client

```shell
# needs to run as root because it is using port 53
python3 client.py
```

## server

It receives queries and read the wanted "fake" hostname, decode the data put in the hostname as base32.

Then it replies through a DNS TXT reply, where the data is encoded as base64 without padding.

### Running the server

```shell
# needs to run as root because it is binding port 53
python3 server.py
```

## Documentation

* [DNS packet structure](DNSPacketStructure.md)

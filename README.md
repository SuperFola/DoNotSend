# [WIP] DoNotSend - hijacking the DNS protocol

For now, it works on **Linux only**.

The DNS protocol is convetionally used to ask for the IP address of a given website.

Here it's used to send messages and retrieve other messages, instead of asking for a website IP address and retrieving its IP address.

## Setup

* Python >= 3.7
* Scapy >= 2.4
    * if it isn't installed alongside scapy:
        * libpcap
* venv
    * Sometimes the wheel module is needed as well

```shell
apt install python3-venv
python3 -m venv venv/
source venv/bin/activate

pip3 install scapy
# if it fails because it couldn't build the wheel:
pip3 uninstall scapy && pip3 install wheel && pip3 install scapy

# run as admin to check everything is fine
python3 server.py "interface" "host name"
# if it complains about libpcap not installed, then:
apt install libpcap0.8-dev
```

## client

We can include arbitrary data in the hostname which the server then can interpret and execute/relay.
Thus we put our data in the qname section of the query, encoded using base32, without the padding (we can easily recalculate it).

Currently, it's just a WIP, it sends a single message "hello world" and get responses from the server which are displayed.

### Running the client

```shell
# needs to run as root because it is using port 53
python3 client.py "hostname"
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

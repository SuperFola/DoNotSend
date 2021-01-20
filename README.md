# DoNotSend - hacking the DNS protocol

*Works on Windows and Linux*

The DNS protocol is conventionally used to ask for the IP address of a given website.

Here it's used to send messages and retrieve other messages, instead of asking for a website IP address and retrieving its IP address.

## Setup

* Python >= 3.7
* Scapy >= 2.4
  * if it isn't installed alongside scapy:
    * libpcap
* venv
  * Sometimes the `wheel` module is needed as well

```shell
apt install python3-venv
python3 -m venv venv/
source venv/bin/activate

pip3 install scapy
# if it fails because it couldn't build the wheel:
pip3 uninstall scapy && pip3 install wheel && pip3 install scapy

cd src
# run as admin to check everything is fine
python3 server.py "interface" "host name"
# if it complains about libpcap not installed, then:
apt install libpcap0.8-dev
```

## client

We can include arbitrary data in the hostname which the server then can interpret and execute/relay.
Thus we put our data in the qname section of the query, encoded using base32, without the padding (we can easily recalculate it).

The queries sent are TXT DNS queries, otherwise (because we answer with TXT DNS replies) the replies will get lost/deleted when transmitted by peers (yes you read correctly, Google can ask the DNS if it knows `crafted-domain.my_dns.domain.example.com`).

```bash
python3 client.py [my_dns.domain.example.com] "message here"
```

If no message is given, `hello world` is sent.

You can also use the `client.sh` version, relying only on `dig`, `base32` and `base64`.

## server

It receives queries and read the wanted "fake" hostname, decode the data put in the hostname as base32.

Then it replies through a DNS TXT reply, where the data is encoded as base64 without padding.

### Running the server

```shell
cd src
# needs to run as root because it is binding port 53
python3 server.py [interface, for example eth0 on linux] [my_dns.domain.example.com]
```

## Having other big DNS relay your queries and answers

In a few steps I was able to configure my NS provider to set myself up as my own DNS, to get to reply to the weird domains I need to communicate.

For this examples, let's say my server is named `example.com`.

1. I added a `A` entry for `dns.example.com`, pointing to `my server ip here`
1. In the DNS servers configuration, I already had things like `ns1.provider.com`, I added myself as a DNS server: `dns.example.com`, pointing to `my server ip here`
1. Then, just wait a bit (can be as long as 48 hours) and you're good to go

Now I just have to tell my client scripts to use the domain `dns.example.com` to send messages to it and it works like a charm, even when asking Google about it!

## Documentation

* [DNS packet structure](doc/DNSPacketStructure.md)
* [Design choices](doc/design.md)

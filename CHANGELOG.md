# Changelog

## v0.0.4

### Added
- different users with the same tag (when registering) are now different in the message log
- possibility to log only a specific kind of DNS requests (on the server, through the configuration file)

### Changed
- answers TTL changed from 1024 (17 minutes ~) to 60 (1 minute)

## v0.0.2
### Added
- converter.py, to encode/decode ascii in base 32 and base 64 flawlessly
- packet.py to encapsulate a lot of dull work
- threaded udp socket server binded on port 53 otherwise we have an ICMP type 3 error (port unreachable, because nothing is binded to it)
- simple chat server, anonymizing the ip addresses, can receive commands to get the messages (/consult), otherwise just add the message to the queue
- error catching on subdomains decoding errors

### Changed
- now using subdomains of a main domain instead of the qname field, in case it's filtered
- the replies come in DNS reply answer field, as TXT
- the answer now includes the original question
- the IP packet is constructed with a TOS of 0x28 (normal priority, high throughput)
- TTL was added to the answer
- transaction id added to DNS layer (random, generated by client)
- random source port for UDP packet
- the client can now get a message as command line parameter
- fixing a bug on the decoders: they were adding padding when it shouldn't (payload size modulo 4 = 0)

## v0.0.1
### Added
- basic client sending message in DNS question qname field
- basic server reading message from DNS question qname field, answer in DNS reply answer field
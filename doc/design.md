# Design choices

Because the project is relying on DNS request/reply, we have limited amount of bit we can send.

I'll try to explain here the different limits and how I'm trying to stay in bound.

## IPv4 datagram

    +----------------+-------------+------------------------------------+
    |  IPv4 headers  | UDP headers |              UDP data              |
    |    20 bytes    |   8 bytes   |        max size 65'507 bytes       |
    +----------------+-------------+------------------------------------+
                     \__________________________________________________/
                                     max size 65'515 bytes

## DNS packet

DNS packets are stored in the UDP data.

    +-------------------+---------+---------+-----------+-----------------+
    | DNS fixed headers | Queries | Answers | Authority | Additional info |
    |      12 bytes     | section | section |  section  |     section     |
    +-------------------+---------+---------+-----------+-----------------+
                        \_________________________________________________/
                                            variable size

According to [this blog post by Cloudfare](https://blog.cloudflare.com/a-deep-dive-into-dns-packet-sizes-why-smaller-packet-sizes-keep-the-internet-safe/),
our DNS answers should fit in a 512 bytes UDP packet, thus we can calculate the variable size:

    512B = UDP headers + DNS fixed headers + variable size
    512B =      8B     +        12B        + x
    x    = 512 - 8 - 12 B
         = 492B

Thus we have *only* 492 bytes for our data.

## [WIP] Compression

To achieve this, we will need to perform some compression. Here I chose to use Huffman coding.

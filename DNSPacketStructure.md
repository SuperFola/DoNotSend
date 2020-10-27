# DNS packet structure

## DNS Headers (for both requests and replies)
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    ID (16 bits) : should match between question and reply
        should be a new one for every request
    QR (1 bit) : specify if it's a query (0) or an answer (1)
    OPCODE (4 bits) : type of the message
        std query = 0
        inverse query = 1
        server status query = 2
    AA (1 bit) : authoritative answer, useful for answer only
    TC (1 bit) : truncation, specifies taht the message was truncated
    RD (1 bit) : recursion desired, if the query should be pursued recursively
    RA (1 bit) : recursion available, answer only
    Z (3 bits) : reserved for future use
    RCODE (4 bits) : response code, answer only
        0. no error
        1. format error (couldn't read query)
        2. server failure (couldn't process query)
        3. name error (only for authoritative name servers)
            domain does not exist
        4. not implemented (unsupported query)
        5. refused (for policy reasons)
    QDCOUNT (16 bits) : number of entries in the question section
        should be set to 1, we have a single question
    ANCOUNT (16 bits) : number of resource records in the answer section
    NSCOUNT (16 bits) : number of name server resource records in the
        authority records section
    ARCOUNT (16 bits) : number of resource records in the additional
        records section

## DNS Question
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    QNAME : domain name, represented as a sequence of labels
        a label starts with a length octet, then the label
        domain name is terminated with the 0 length octet
    QTYPE (2 octets) : specifies the type of the query
        (A) host addresses = 0x0001
        (MX) mail server = 0x000f
        (NS) name servers = 0x0002
    QCLASS (2 octets) : the class of the query
        internet addresses = 0x0001

## DNS Answer
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    NAME : the queried domain name, same format as QNAME
    TYPE (2 octets) : specify the meaning of the data in the RDATA field
        (A record) interpret type = 0x0001
        (CNAME) 0x0005
        (NS) 0x0002
        (MX) 0x000f
        (TXT) 0x0010
    CLASS (2 octets) : class of data in the RDATA field
        internet address = 0x0001
    TTL (4 octets) : number of seconds the results can be cached
    RDLENGTH (2 octets) : length of the RDATA field
    RDATA : data of the response, depends on the TYPE field
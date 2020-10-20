# DoNotSend - hijacking DNS requests

## server

Receive messages, read them, send back a DNS answer with two answers:
* the first contains test in the name of the answer
* the second contains hello in the name of the answer

## client

Can send a message using a DNS query, message put in qname field.

Retrieve message(s) from the an field, can receive an arbitrary amount of messages, display them in the order they are appearing (stored in the name field of the answer).
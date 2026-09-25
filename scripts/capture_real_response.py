"""
Capture a real DNS response from a live server and save it for testing.
Uses our own encoder to build the query — validates the encoder against
a real server's expectations.
"""

import socket
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.dns_resolver.parser import DNSEncoder, DNSHeader, DNSQuestion, RecordType, RecordClass, ResponseCode


def capture(domain: str, record_type: RecordType, nameserver: str = "8.8.8.8"):
    header = DNSHeader(
        id=1234, qr=False, opcode=0, aa=False, tc=False,
        rd=True, ra=False, rcode=ResponseCode.NOERROR,
        qdcount=1, ancount=0, nscount=0, arcount=0
    )
    question = DNSQuestion(qname=domain, qtype=record_type, qclass=RecordClass.IN)

    encoder = DNSEncoder()
    query = encoder.encode_message(header, [question])

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.sendto(query, (nameserver, 53))
    response, _ = sock.recvfrom(512)
    sock.close()

    os.makedirs('docs/responses', exist_ok=True)
    type_name = record_type.name
    filename = f'docs/responses/{domain}-{type_name}.bin'
    with open(filename, 'wb') as f:
        f.write(response)

    print(f"Saved {len(response)} bytes to {filename}")
    return response


if __name__ == '__main__':
    capture('google.com', RecordType.A)
    capture('github.com', RecordType.NS)
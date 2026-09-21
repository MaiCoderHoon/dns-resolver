"""
DNS Wire Format Parser & Encoder
RFC 1035 compliant DNS message parsing and encoding

Implements:
- DNS header format
- Question section parsing
- Answer/Authority/Additional sections
- Name compression pointer handling
- Record types: A, AAAA, NS, CNAME, MX, TXT, SOA
"""

import struct
from dataclasses import dataclass
from typing import List, Tuple, Dict, Optional
from enum import IntEnum


# DNS Record Types
class RecordType(IntEnum):
    A = 1          # IPv4 address
    NS = 2         # Nameserver
    CNAME = 5      # Canonical name
    SOA = 6        # Start of authority
    MX = 15        # Mail exchange
    AAAA = 28      # IPv6 address
    TXT = 16       # Text record


# DNS Classes
class RecordClass(IntEnum):
    IN = 1         # Internet


# DNS Response Codes
class ResponseCode(IntEnum):
    NOERROR = 0    # No error
    FORMERR = 1    # Format error
    SERVFAIL = 2   # Server failure
    NXDOMAIN = 3   # Domain name does not exist
    NOTIMP = 4     # Not implemented
    REFUSED = 5    # Query refused


@dataclass
class DNSHeader:
    """DNS Message Header (12 bytes)"""
    id: int                    # 16-bit identifier
    qr: bool                   # Query (0) or Response (1)
    opcode: int                # Operation code (0 = standard query)
    aa: bool                   # Authoritative answer
    tc: bool                   # Truncated
    rd: bool                   # Recursion desired
    ra: bool                   # Recursion available
    rcode: ResponseCode        # Response code
    qdcount: int               # Number of questions
    ancount: int               # Number of answers
    nscount: int               # Number of nameservers
    arcount: int               # Number of additional records


@dataclass
class DNSQuestion:
    """DNS Question Section"""
    qname: str                 # Question domain name
    qtype: RecordType          # Question type
    qclass: RecordClass        # Question class


@dataclass
class DNSRecord:
    """DNS Resource Record (Answer/Authority/Additional)"""
    name: str                  # Domain name
    type: RecordType           # Record type
    cls: RecordClass           # Record class
    ttl: int                   # Time to live
    rdlen: int                 # Resource data length
    rdata: bytes               # Raw resource data


class DNSParser:
    """Parse and encode DNS messages per RFC 1035"""

    def __init__(self):
        self.packet = b''
        self.offset = 0
        self.name_pointers = {}  # For compression: {offset: domain_name}

    def parse_message(self, packet: bytes) -> Tuple[DNSHeader, List[DNSQuestion], 
                                                     List[DNSRecord], List[DNSRecord], 
                                                     List[DNSRecord]]:
        """
        Parse a complete DNS message
        
        Args:
            packet: Raw DNS message bytes
            
        Returns:
            Tuple of (header, questions, answers, authority, additional)
        """
        self.packet = packet
        self.offset = 0
        self.name_pointers.clear()

        # Parse header (12 bytes)
        header = self._parse_header()

        # Parse questions
        questions = []
        for _ in range(header.qdcount):
            questions.append(self._parse_question())

        # Parse answer records
        answers = []
        for _ in range(header.ancount):
            answers.append(self._parse_record())

        # Parse authority records
        authority = []
        for _ in range(header.nscount):
            authority.append(self._parse_record())

        # Parse additional records
        additional = []
        for _ in range(header.arcount):
            additional.append(self._parse_record())

        return header, questions, answers, authority, additional

    def _parse_header(self) -> DNSHeader:
        """Parse 12-byte DNS header"""
        header_data = self._read_bytes(12)
        
        # Unpack: ID, flags (2 bytes), QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
        id, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', header_data)

        # Decode flags (2 bytes = 16 bits)
        # Bit 0: QR (Query/Response)
        # Bits 1-4: Opcode
        # Bit 5: AA (Authoritative Answer)
        # Bit 6: TC (Truncated)
        # Bit 7: RD (Recursion Desired)
        # Bit 8: RA (Recursion Available)
        # Bits 9-11: Z (reserved, must be 0)
        # Bits 12-15: RCODE (response code)

        qr = bool((flags >> 15) & 1)
        opcode = (flags >> 11) & 0xF
        aa = bool((flags >> 10) & 1)
        tc = bool((flags >> 9) & 1)
        rd = bool((flags >> 8) & 1)
        ra = bool((flags >> 7) & 1)
        rcode = ResponseCode(flags & 0xF)

        return DNSHeader(
            id=id,
            qr=qr,
            opcode=opcode,
            aa=aa,
            tc=tc,
            rd=rd,
            ra=ra,
            rcode=rcode,
            qdcount=qdcount,
            ancount=ancount,
            nscount=nscount,
            arcount=arcount
        )

    def _parse_question(self) -> DNSQuestion:
        """Parse question section"""
        qname = self._parse_name()
        qtype, qclass = struct.unpack('!HH', self._read_bytes(4))
        
        return DNSQuestion(
            qname=qname,
            qtype=RecordType(qtype),
            qclass=RecordClass(qclass)
        )

    def _parse_record(self) -> DNSRecord:
        """Parse resource record (answer/authority/additional)"""
        name = self._parse_name()
        type_val, cls_val, ttl = struct.unpack('!HHI', self._read_bytes(10))
        rdlen = struct.unpack('!H', self._read_bytes(2))[0]
        rdata = self._read_bytes(rdlen)

        return DNSRecord(
            name=name,
            type=RecordType(type_val),
            cls=RecordClass(cls_val),
            ttl=ttl,
            rdlen=rdlen,
            rdata=rdata
        )

    def _parse_name(self) -> str:
        """
        Parse domain name with compression pointer support
        
        Format:
        - If byte < 192: length of label (0-63)
        - If byte >= 192: pointer to another name (12-bit offset)
        - 0 byte: end of name
        """
        labels = []
        
        while True:
            length = self.packet[self.offset]
            self.offset += 1

            if length == 0:
                # End of name
                break
            elif length >= 192:
                # Pointer: 2-byte value where top 2 bits = 11
                # Restore offset for proper parsing of the pointer
                self.offset -= 1
                pointer_bytes = self._read_bytes(2)
                # Mask off the top 2 bits and get 14-bit offset
                pointer_offset = struct.unpack('!H', pointer_bytes)[0] & 0x3FFF
                # Recursively parse the name at that offset
                # Save current offset, jump to pointer, parse, restore offset
                saved_offset = self.offset
                self.offset = pointer_offset
                pointed_name = self._parse_name()
                self.offset = saved_offset
                labels.append(pointed_name)
                break
            else:
                # Regular label
                label = self._read_bytes(length).decode('ascii')
                labels.append(label)

        return '.'.join(labels) if labels else ''

    def _read_bytes(self, n: int) -> bytes:
        """Read n bytes from packet at current offset"""
        data = self.packet[self.offset:self.offset + n]
        self.offset += n
        return data

    # TODO: Implement encoding methods
    # - encode_message()
    # - encode_header()
    # - encode_question()
    # - encode_name() with pointer generation
    # - encode_record()


class DNSEncoder:
    """Encode DNS messages per RFC 1035"""
    
    def __init__(self):
        self.packet = b''
        self.name_offsets = {}  # Track where names have been written for compression

    # TODO: Implement encoder
    # This will be used by Ayush to construct queries


# Utility functions
def format_rdata(record_type: RecordType, rdata: bytes) -> str:
    """
    Format RDATA for display based on record type
    
    TODO: NS/CNAME/MX/SOA need pointer-aware parsing (needs full packet + offset)
    """
    if record_type == RecordType.A:
        return parse_ipv4(rdata)
    elif record_type == RecordType.AAAA:
        return parse_ipv6(rdata)
    elif record_type == RecordType.TXT:
        length = rdata[0]
        return rdata[1:1 + length].decode('ascii')
    else:
        return rdata.hex()  # Fallback for NS/CNAME/MX/SOA — not done yet

def parse_ipv4(rdata: bytes) -> str:
    """Parse A record (4-byte IPv4 address)"""
    if len(rdata) != 4:
        raise ValueError(f"Invalid A record length: {len(rdata)}")
    return '.'.join(str(b) for b in rdata)


def parse_ipv6(rdata: bytes) -> str:
    """Parse AAAA record (16-byte IPv6 address)"""
    if len(rdata) != 16:
        raise ValueError(f"Invalid AAAA record length: {len(rdata)}")
    # TODO: Proper IPv6 formatting with compression
    return ':'.join(f'{int.from_bytes(rdata[i:i+2], "big"):x}' for i in range(0, 16, 2))

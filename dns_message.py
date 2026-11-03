
import struct
import socket


# --------------------------------
# DNS QUERY CONSTRUCTION
# --------------------------------

def build_dns_header():
    transaction_id = 1234
    flags = 0x0000

    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0

    return struct.pack(
        "!HHHHHH",
        transaction_id,
        flags,
        qdcount,
        ancount,
        nscount,
        arcount
    )


def encode_domain(domain):
    encoded = b""

    labels = domain.rstrip(".").split(".")

    for label in labels:
        label_bytes = label.encode("ascii")
        encoded += bytes([len(label_bytes)])
        encoded += label_bytes

    encoded += b"\x00"

    return encoded


def build_dns_question(domain):
    qname = encode_domain(domain)

    qtype = 1
    qclass = 1

    question_fields = struct.pack("!HH", qtype, qclass)

    return qname + question_fields


def build_dns_query(domain):
    header = build_dns_header()
    question = build_dns_question(domain)

    return header + question


# --------------------------------
# DNS RESPONSE HEADER PARSING
# --------------------------------

def parse_dns_header(response):

    if len(response) < 12:
        raise ValueError("DNS response is too short")

    fields = struct.unpack("!HHHHHH", response[:12])

    return {
        "transaction_id": fields[0],
        "flags": fields[1],
        "qdcount": fields[2],
        "ancount": fields[3],
        "nscount": fields[4],
        "arcount": fields[5]
    }


def decode_dns_flags(flags):

    return {
        "QR": (flags >> 15) & 1,
        "OPCODE": (flags >> 11) & 0b1111,
        "AA": (flags >> 10) & 1,
        "TC": (flags >> 9) & 1,
        "RD": (flags >> 8) & 1,
        "RA": (flags >> 7) & 1,
        "RCODE": flags & 0b1111
    }


# --------------------------------
# DNS DOMAIN NAME DECODING
# --------------------------------

def decode_domain_name(message, offset):

    labels = []
    original_offset = None

    while True:

        length = message[offset]

        if (length & 0xC0) == 0xC0:

            second_byte = message[offset + 1]

            pointer = ((length & 0x3F) << 8) | second_byte

            if original_offset is None:
                original_offset = offset + 2

            offset = pointer

        elif length == 0:

            if original_offset is None:
                original_offset = offset + 1

            break

        else:

            offset += 1

            label = message[
                offset:offset + length
            ].decode("ascii")

            labels.append(label)

            offset += length

    domain = ".".join(labels)

    return domain, original_offset


# --------------------------------
# DNS QUESTION PARSING
# --------------------------------

def parse_dns_question(message, offset=12):

    domain, offset = decode_domain_name(message, offset)

    qtype, qclass = struct.unpack(
        "!HH",
        message[offset:offset + 4]
    )

    offset += 4

    return {
        "domain": domain,
        "qtype": qtype,
        "qclass": qclass
    }, offset


# --------------------------------
# RESOURCE RECORD PARSING
# --------------------------------

def parse_dns_resource_record(message, offset):

    name, offset = decode_domain_name(message, offset)

    record_type, record_class, ttl, rdlength = struct.unpack(
        "!HHIH",
        message[offset:offset + 10]
    )

    offset += 10

    # Remember where RDATA begins in the original message
    rdata_offset = offset

    # Extract RDATA
    rdata = message[offset:offset + rdlength]

    # Calculate the next record's position
    next_offset = offset + rdlength

    record = {
        "name": name,
        "type": record_type,
        "class": record_class,
        "ttl": ttl,
        "rdlength": rdlength,
        "rdata": rdata,
        "rdata_offset": rdata_offset
    }

    return record, next_offset


# --------------------------------
# A RECORD DECODING
# --------------------------------

def decode_a_record(rdata):

    if len(rdata) != 4:
        raise ValueError("Invalid A record data length")

    return socket.inet_ntoa(rdata)


def interpret_dns_record(record):

    if record["type"] == 1 and record["class"] == 1:

        ip_address = decode_a_record(record["rdata"])

        return {
            "name": record["name"],
            "type": "A",
            "ttl": record["ttl"],
            "value": ip_address
        }

    return None


# --------------------------------
# ANSWER SECTION PARSING
# --------------------------------

def parse_answer_section(message, offset, ancount):

    answers = []

    for _ in range(ancount):

        record, offset = parse_dns_resource_record(
            message,
            offset
        )

        if record["type"] == 1 and record["class"] == 1:

            result = interpret_dns_record(record)

            answers.append(result)

    return answers, offset

def decode_ns_record(message, record):

    if record["type"] != 2:
        return None

    nameserver, next_offset = decode_domain_name(
        message,
        record["rdata_offset"]
    )

    if next_offset > record["rdata_offset"] + record["rdlength"]:
        raise ValueError("NS record exceeds RDATA boundary")

    return nameserver

def parse_authority_section(message, offset, nscount):

    authority_records = []

    for _ in range(nscount):

        record, offset = parse_dns_resource_record(
            message,
            offset
        )

        if record["type"] == 2 and record["class"] == 1:

            nameserver = decode_ns_record(message, record)

            record["nameserver"] = nameserver

        authority_records.append(record)

    return authority_records, offset

def parse_additional_section(message, offset, arcount):

    additional_records = []

    for _ in range(arcount):

        # Parse one resource record
        record, offset = parse_dns_resource_record(
            message,
            offset
        )

        # Extract only A records
        if record["type"] == 1 and record["class"] == 1:

            result = interpret_dns_record(record)

            additional_records.append(result)

    return additional_records, offset

import struct
import socket


# --------------------------------
# DNS QUERY CONSTRUCTION
# --------------------------------

def build_dns_header(transaction_id = 1234):
    flags = 0x0000  # RD = 0

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


def build_dns_query(domain,transaction_id=1234):
    header = build_dns_header(transaction_id)
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
    jumped = False
    original_offset = offset

    # Track offsets to detect compression pointer loops
    visited_offsets = set()

    while True:
        if offset >= len(message):
            raise ValueError(
                "DNS message is truncated while decoding domain name."
            )

        length = message[offset]

        # Check for compression pointer
        if length & 0xC0 == 0xC0:

            if offset + 2 > len(message):
                raise ValueError(
                    "DNS message is truncated: incomplete compression pointer."
                )

            pointer = struct.unpack(
                "!H",
                message[offset:offset + 2]
            )[0] & 0x3FFF

            if pointer >= len(message):
                raise ValueError(
                    "Invalid DNS compression pointer: offset out of bounds."
                )

            # Detect compression pointer loops
            if pointer in visited_offsets:
                raise ValueError(
                    "Invalid DNS compression pointer: circular reference detected."
                )

            visited_offsets.add(offset)

            if not jumped:
                original_offset = offset + 2

            offset = pointer
            jumped = True
            continue

        # End of domain name
        if length == 0:
            if not jumped:
                original_offset = offset + 1
            break

        # Validate label length
        if length & 0xC0:
            raise ValueError("Invalid DNS label encoding.")

        offset += 1

        if offset + length > len(message):
            raise ValueError(
                "DNS message is truncated: incomplete domain name label."
            )

        label = message[offset:offset + length].decode("ascii")
        labels.append(label)

        offset += length

    domain_name = ".".join(labels)

    return domain_name, original_offset


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

    if offset < 0 or offset >= len(message):
        raise ValueError("Invalid resource record offset.")

    name, offset = decode_domain_name(message, offset)

    # Validate the fixed 10-byte resource record header
    if offset + 10 > len(message):
        raise ValueError(
            "DNS message is truncated: incomplete resource record header."
        )

    record_type, record_class, ttl, rdlength = struct.unpack(
        "!HHIH",
        message[offset:offset + 10]
    )

    # Calculate where RDATA begins
    rdata_offset = offset + 10

    # Validate the RDATA length
    if rdata_offset + rdlength > len(message):
        raise ValueError(
            "DNS message is truncated: incomplete resource record data."
        )

    # Calculate the next record's position
    next_offset = rdata_offset + rdlength

    # Extract RDATA
    rdata = message[rdata_offset:next_offset]

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

def validate_dns_response(
    response,
    expected_transaction_id,
    expected_domain
):
    # A DNS header must contain at least 12 bytes.
    if len(response) < 12:
        raise ValueError("DNS response is shorter than the header.")

    header = parse_dns_header(response)
    flags = decode_dns_flags(header["flags"])

    # Validate Transaction ID.
    if header["transaction_id"] != expected_transaction_id:
        raise ValueError("DNS Transaction ID mismatch.")

    # Ensure this packet is a response.
    if flags["QR"] != 1:
        raise ValueError("Received packet is not a DNS response.")

    # We currently support exactly one question.
    if header["qdcount"] != 1:
        raise ValueError("Unexpected DNS question count.")

    # Parse and validate the question.
    question, _ = parse_dns_question(response)

    received_domain = question["domain"].rstrip(".").lower()
    expected_domain = expected_domain.rstrip(".").lower()

    if received_domain != expected_domain:
        raise ValueError("DNS question name mismatch.")

    if question["qtype"] != 1:
        raise ValueError("Unexpected DNS query type.")

    if question["qclass"] != 1:
        raise ValueError("Unexpected DNS query class.")

    return header, flags, question
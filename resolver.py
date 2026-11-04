import struct
import argparse
import secrets
import time

from dns_message import (
    build_dns_query,
    parse_dns_header,
    decode_dns_flags,
    parse_dns_question,
    parse_answer_section,
    parse_authority_section,
    parse_additional_section,
    validate_dns_response
)

from network import send_dns_query, send_dns_query_tcp

dns_cache = {}

def store_in_cache(domain, records):
    domain_key = domain.rstrip(".").lower()

    for record in records:
        ttl = record["ttl"]

        if ttl <= 0:
            continue

        expires_at = time.time() + ttl

        cached_record = {
            "type": "A",
            "value": record["value"],
            "ttl": ttl,
            "expires_at": expires_at
        }

        dns_cache.setdefault(domain_key, []).append(cached_record)

def get_from_cache(domain):
    domain_key = domain.rstrip(".").lower()

    if domain_key not in dns_cache:
        return None

    current_time = time.time()

    valid_records = [
        record
        for record in dns_cache[domain_key]
        if record["expires_at"] > current_time
    ]

    if not valid_records:
        del dns_cache[domain_key]
        return None

    dns_cache[domain_key] = valid_records

    return [
        {
            "name": domain_key,
            "type": "A",
            "value": record["value"],
            "ttl": max(0, int(record["expires_at"] - current_time))
        }
        for record in valid_records
    ]

# --------------------------------------------------
# 1. Process DNS referrals
# --------------------------------------------------

def process_referral(authority_records, additional_records):
    referrals = []

    for record in authority_records:
        if record["type"] != 2:
            continue

        nameserver = record["nameserver"]
        nameserver_ip = None

        # Find the matching glue A record.
        for additional in additional_records:
            if (
                additional["type"] == "A"
                and additional["name"].rstrip(".").lower()
                == nameserver.rstrip(".").lower()
            ):
                nameserver_ip = additional["value"]
                break

        referrals.append({
            "nameserver": nameserver,
            "ip": nameserver_ip
        })

    return referrals


# --------------------------------------------------
# 2. Parse and validate DNS responses
# --------------------------------------------------

def parse_dns_response(
    response,
    expected_transaction_id,
    expected_domain
):
    # Validate header, transaction ID, QR and question.
    validation_result = validate_dns_response(
        response,
        expected_transaction_id,
        expected_domain
    )

    # Support either a three-value or four-value
    # validation function return.
    header, flags, question = validation_result[:3]

    # Get the offset immediately after the question.
    _, offset = parse_dns_question(response)

    # Parse Answer section.
    answers, offset = parse_answer_section(
        response,
        offset,
        header["ancount"]
    )

    # Parse Authority section.
    authority, offset = parse_authority_section(
        response,
        offset,
        header["nscount"]
    )

    # Parse Additional section.
    additional, offset = parse_additional_section(
        response,
        offset,
        header["arcount"]
    )

    return {
        "header": header,
        "flags": flags,
        "question": question,
        "answers": answers,
        "authority": authority,
        "additional": additional
    }


# --------------------------------------------------
# 3. Handle DNS response codes
# --------------------------------------------------

def handle_dns_error(result):

    rcode = result["flags"]["RCODE"]

    error_messages = {
        1: "FORMERR - Format error",
        2: "SERVFAIL - Server failure",
        3: "NXDOMAIN - Domain does not exist",
        4: "NOTIMP - Not implemented",
        5: "REFUSED - Query refused"
    }

    if rcode == 0:
        return "SUCCESS"

    message = error_messages.get(
        rcode,
        f"Unknown DNS error: {rcode}"
    )

    print(message)

    if rcode == 3:
        return "NXDOMAIN"

    return "RETRY"


# --------------------------------------------------
# 4. Query a nameserver
# --------------------------------------------------

def query_nameserver(domain, server_ip):

    # Generate a random 16-bit transaction ID.
    transaction_id = secrets.randbelow(65536)

    print(f"\nQuerying {server_ip} for {domain}")
    print("Transaction ID:", transaction_id)

    # Build query using this transaction ID.
    query = build_dns_query(domain, transaction_id)

    # Send query.
    response = send_dns_query(query, server_ip)

    if response is None:
        return None

    # Check whether the UDP response is truncated.
    header = parse_dns_header(response)
    flags = decode_dns_flags(header["flags"])

    if flags["TC"] == 1:
        print("Truncated DNS response received.")
        print("Retrying query using TCP...")

        response = send_dns_query_tcp(query, server_ip)

        if response is None:
            print("TCP fallback failed.")
            return None

    # Validate and parse response.
    result = parse_dns_response(
        response,
        transaction_id,
        domain
    )

    return result


# --------------------------------------------------
# 5. Resolve nameserver hostname when glue is missing
# --------------------------------------------------

def resolve_nameserver_ip(
    nameserver,
    resolving_nameservers,
    depth
):

    print(f"\nResolving nameserver hostname: {nameserver}")

    answers = resolve_test(
        nameserver.rstrip("."),
        resolving_nameservers,
        depth + 1
    )

    if not answers:
        print("Could not resolve nameserver:", nameserver)
        return None

    return answers[0]["value"]


# --------------------------------------------------
# 6. Main iterative resolution function
# --------------------------------------------------

def resolve_test(domain, resolving_nameservers=None, depth=0, cname_chain=None):

    if resolving_nameservers is None:
        resolving_nameservers = set()

    if cname_chain is None:
        cname_chain = set()

    domain_key = domain.rstrip(".").lower()

    cached_records = get_from_cache(domain_key)

    if cached_records is not None:
        print(f"\nCache hit for {domain}")
        return cached_records

    print(f"\nCache miss for {domain}")

    # Prevent circular nameserver lookups.
    if domain_key in resolving_nameservers:
        print("Circular nameserver lookup detected:", domain)
        return None

    # Prevent CNAME loops.
    if domain_key in cname_chain:
        print("CNAME loop detected:", domain)
        return None

    # Limit recursive nameserver lookups.
    if depth >= 10:
        print("Maximum lookup depth reached.")
        return None

    # Track nameserver lookups independently.
    resolving_nameservers = set(resolving_nameservers)
    resolving_nameservers.add(domain_key)

    # Track CNAME lookups independently.
    cname_chain = set(cname_chain)
    cname_chain.add(domain_key)

    # Start with the root server.
    current_referrals = [
        {
            "nameserver": "root server",
            "ip": "198.41.0.4"
        }
    ]

    visited_servers = set()
    max_steps = 20

    for step in range(1, max_steps + 1):

        print(f"\nResolution step {step}")

        next_referrals = None

        # Try nameservers from the current referral.
        for referral in current_referrals:

            nameserver = referral["nameserver"]
            nameserver_ip = referral["ip"]

            # Resolve missing glue only when needed.
            if nameserver_ip is None:

                nameserver_ip = resolve_nameserver_ip(
                    nameserver,
                    resolving_nameservers,
                    depth
                )

                if nameserver_ip is None:
                    continue

            # Avoid querying the same IP repeatedly.
            if nameserver_ip in visited_servers:
                print("Already queried:", nameserver_ip)
                continue

            visited_servers.add(nameserver_ip)

            print("\nQuerying nameserver:", nameserver)
            print("Server IP:", nameserver_ip)
            print("Domain:", domain)

            try:
                result = query_nameserver(
                    domain,
                    nameserver_ip
                )

            except (ValueError, struct.error) as error:
                print("DNS response error:", error)
                continue

            # Try another nameserver if this one failed.
            if result is None:
                print("Nameserver failed. Trying next one.")
                continue

            # Handle DNS response codes.
            status = handle_dns_error(result)

            if status == "NXDOMAIN":
                print("Domain does not exist.")
                return None

            if status == "RETRY":
                print("Nameserver returned an error.")
                print("Trying next nameserver.")
                continue

            # Check for A records first.
            a_records = [
                answer
                for answer in result["answers"]
                if answer["type"] == "A"
            ]

            if a_records:

                print("\nFinal A records:")

                for answer in a_records:
                    print(
                        answer["name"],
                        "->",
                        answer["value"]
                    )

                 # Store successful A records in the DNS cache.
                store_in_cache(domain_key, a_records)

                return a_records

            # Check for CNAME records.
            cname_records = [
                answer
                for answer in result["answers"]
                if answer["type"] == "CNAME"
            ]

            if cname_records:

                cname_record = next(
                    (
                        answer for answer in cname_records
                        if answer["name"].rstrip(".").lower()
                        == domain_key
                    ),
                    None
                )

                if cname_record is not None:

                    cname_target = cname_record["value"]

                    print("\nCNAME record found!")
                    print("Alias:", domain)
                    print("Canonical name:", cname_target)

                    print("\nResolving CNAME target...")

                    return resolve_test(
                        cname_target,
                        resolving_nameservers=set(),
                        depth=0,
                        cname_chain=cname_chain
                    )

            # Extract the next referral.
            referrals = process_referral(
                result["authority"],
                result["additional"]
            )

            if referrals:

                print("\nNew referral received.")

                # Discard old referral candidates.
                next_referrals = referrals
                break

            print("No answer or referral from this nameserver.")
            print("Trying another nameserver...")

        # No usable nameserver or referral remains.
        if not next_referrals:

            print("\nNo more usable nameservers.")
            print("Unable to resolve:", domain)

            return None

        # Continue with the new delegation.
        current_referrals = next_referrals

    print("\nMaximum resolution steps reached.")
    return None


# --------------------------------------------------
# 7. Command-line interface
# --------------------------------------------------

if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="DNS Resolver Test CLI"
    )

    parser.add_argument(
        "domain",
        type=str,
        help="Domain name to resolve (required)"
    )

    args = parser.parse_args()

    resolve_test(args.domain)

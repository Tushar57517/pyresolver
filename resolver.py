import struct
import argparse
from dns_message import (
    build_dns_query,
    parse_dns_header,
    decode_dns_flags,
    parse_dns_question,
    parse_answer_section,
    parse_authority_section,
    parse_additional_section
)

from network import send_dns_query


def process_referral(authority_records, additional_records):
    referrals = []

    for record in authority_records:
        if record["type"] != 2:
            continue

        nameserver = record["nameserver"]

        # Look for a matching A record in Additional.
        nameserver_ip = None

        for additional in additional_records:
            if (
                additional["type"] == "A"
                and additional["name"].rstrip(".").lower()
                == nameserver.rstrip(".").lower()
            ):
                nameserver_ip = additional["value"]
                break

        # Keep the referral even if its IP is missing.
        referrals.append({
            "nameserver": nameserver,
            "ip": nameserver_ip
        })

    return referrals

def parse_dns_response(response):

    # Parse header
    header = parse_dns_header(response)

    # Decode flags
    flags = decode_dns_flags(header["flags"])

    if flags["QR"] != 1:
        raise ValueError("Received a DNS query, not a response")

    if flags["RCODE"] != 0:
        raise ValueError(f"DNS error: {flags['RCODE']}")

    # Parse question
    question, offset = parse_dns_question(response)

    # Parse answer section
    answers, offset = parse_answer_section(
        response,
        offset,
        header["ancount"]
    )

    # Parse authority section
    authority, offset = parse_authority_section(
        response,
        offset,
        header["nscount"]
    )

    # Parse additional section
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

def query_nameserver(domain, server_ip):

    print(f"\nQuerying {server_ip} for {domain}")

    # Build the original A-record query
    query = build_dns_query(domain)

    # Send it to the selected nameserver
    response = send_dns_query(query, server_ip)

    if response is None:
        return None

    # Parse the DNS response
    result = parse_dns_response(response)

    return result


def query_authoritative_server(domain, referrals):

    for referral in referrals:

        nameserver = referral["nameserver"]
        server_ip = referral["ip"]

        print(
            f"\nTrying authoritative server: "
            f"{nameserver} ({server_ip})"
        )

        try:
            result = query_nameserver(domain, server_ip)

        except (ValueError, struct.error) as error:
            print("Invalid DNS response:", error)
            continue

        if result is None:
            continue

        # Check whether we received an A record
        if result["answers"]:

            print("\nAUTHORITATIVE ANSWERS")

            for answer in result["answers"]:
                print(answer)

            return result

        # The server may have returned another referral
        print("No A answer from this nameserver.")

    print("\nNo usable authoritative answer found.")

    return None


def resolve_test(domain, resolving_nameservers=None, depth=0):

    if resolving_nameservers is None:
        resolving_nameservers = set()

    domain_key = domain.rstrip(".").lower()

    # Prevent circular nameserver lookups.
    if domain_key in resolving_nameservers:
        print("Circular nameserver lookup detected:", domain)
        return None

    # Prevent excessive recursive lookups.
    if depth >= 10:
        print("Maximum nameserver lookup depth reached.")
        return None

    # Track the domain currently being resolved.
    resolving_nameservers = set(resolving_nameservers)
    resolving_nameservers.add(domain_key)

    current_server = "198.41.0.4"

    max_steps = 20
    steps = 0

    while steps < max_steps:
        steps += 1

        print(f"\nStep {steps}")
        print("Querying server:", current_server)
        print("Domain:", domain)

        try:
            result = query_nameserver(domain, current_server)

        except (ValueError, struct.error) as error:
            print("DNS response error:", error)
            return None

        if result is None:
            print("No response from nameserver.")
            return None

        # Check for the final A record.
        if result["answers"]:
            print("\nFinal A records:")

            for answer in result["answers"]:
                print(answer["name"], "->", answer["value"])

            return result["answers"]

        # Extract the next referral.
        referrals = process_referral(
            result["authority"],
            result["additional"]
        )

        if not referrals:
            print("No usable referral found.")
            return None

        # For now, use the first referral.
        next_referral = referrals[0]

        nameserver = next_referral["nameserver"]
        nameserver_ip = next_referral["ip"]

        # If glue is missing, resolve the nameserver hostname.
        if nameserver_ip is None:

            print("\nGlue record missing for:", nameserver)
            print("Resolving nameserver hostname...")

            nameserver_answers = resolve_test(
                nameserver.rstrip("."),
                resolving_nameservers,
                depth + 1
            )

            if not nameserver_answers:
                print("Could not resolve nameserver hostname.")
                return None

            nameserver_ip = nameserver_answers[0]["value"]

        # Use the nameserver IP for the next iteration.
        current_server = nameserver_ip

        print("\nFollowing referral:")
        print("Nameserver:", nameserver)
        print("IP address:", current_server)

    print("Maximum resolution steps reached.")
    return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="DNS Resolver Test CLI"
    )

    parser.add_argument(
        "domain",
        type=str,
        help="Domain name to resolve (required)",
    )

    args = parser.parse_args()

    resolve_test(args.domain)

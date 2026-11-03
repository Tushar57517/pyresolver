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


def resolve_nameserver_ip(nameserver, resolving_nameservers, depth):
    """
    Resolve a nameserver hostname when its glue A record is missing.
    """

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


def resolve_test(domain, resolving_nameservers=None, depth=0):

    if resolving_nameservers is None:
        resolving_nameservers = set()

    domain_key = domain.rstrip(".").lower()

    # Prevent circular nameserver lookups.
    if domain_key in resolving_nameservers:
        print("Circular nameserver lookup detected:", domain)
        return None

    # Limit recursive nameserver lookups.
    if depth >= 10:
        print("Maximum lookup depth reached.")
        return None

    # Track domains currently being resolved.
    resolving_nameservers = set(resolving_nameservers)
    resolving_nameservers.add(domain_key)

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
                result = query_nameserver(domain, nameserver_ip)

            except (ValueError, struct.error) as error:
                print("DNS response error:", error)
                continue

            # Try another nameserver if this one failed.
            if result is None:
                print("Nameserver failed. Trying next one.")
                continue

            # Final A record found.
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

            if referrals:

                print("\nNew referral received.")

                # Move to the new delegation.
                # Old referral candidates will be discarded.
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

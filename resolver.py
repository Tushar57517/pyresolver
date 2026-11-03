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

    # Examine every NS record
    for record in authority_records:

        if record["type"] != 2:
            continue

        nameserver = record.get("nameserver")

        if not nameserver:
            continue

        # Find the corresponding A record
        for additional in additional_records:

            if additional["name"].rstrip(".").lower() == nameserver.rstrip(".").lower():

                referral = {
                    "nameserver": nameserver,
                    "ip": additional["value"]
                }

                referrals.append(referral)

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


def resolve_test(domain):

    root_server = "198.41.0.4"

    # =================================
    # STEP 1: QUERY ROOT SERVER
    # =================================

    print("\n========== ROOT SERVER ==========")

    root_result = query_nameserver(domain, root_server)

    if root_result is None:
        print("Root query failed.")
        return

    # =================================
    # STEP 2: FIND TLD NAMESERVERS
    # =================================

    tld_referrals = process_referral(
        root_result["authority"],
        root_result["additional"]
    )

    if not tld_referrals:
        print("No usable TLD referrals found.")
        return

    print("\nDiscovered TLD nameservers:")

    for referral in tld_referrals:
        print(referral)

    # =================================
    # STEP 3: QUERY TLD SERVER
    # =================================

    print("\n========== TLD SERVER ==========")

    tld_result = None

    for referral in tld_referrals:

        print(
            f"\nTrying TLD server: "
            f"{referral['nameserver']}"
        )

        try:
            tld_result = query_nameserver(
                domain,
                referral["ip"]
            )
        except (ValueError, struct.error) as error:
            print("Invalid DNS response:", error)
            continue

        if tld_result is not None:
            break

    if tld_result is None:
        print("All TLD nameservers failed.")
        return

    # =================================
    # STEP 4: CHECK FOR AN ANSWER
    # =================================

    if tld_result["answers"]:

        print("\nDNS ANSWER FOUND AT TLD LEVEL")

        for answer in tld_result["answers"]:
            print(answer)

        return

    # =================================
    # STEP 5: FIND AUTHORITATIVE SERVERS
    # =================================

    authoritative_referrals = process_referral(
        tld_result["authority"],
        tld_result["additional"]
    )

    if not authoritative_referrals:
        print("No usable authoritative referrals found.")
        return

    print("\nDiscovered authoritative nameservers:")

    for referral in authoritative_referrals:
        print(referral)

    # =================================
    # STEP 6: QUERY AUTHORITATIVE SERVER
    # =================================

    print("\n========== AUTHORITATIVE SERVER ==========")

    authoritative_result = query_authoritative_server(
        domain,
        authoritative_referrals
    )

    if authoritative_result is None:
        return

    # =================================
    # STEP 7: DISPLAY FINAL A RECORDS
    # =================================

    print("\n========== FINAL DNS RESULT ==========")

    for answer in authoritative_result["answers"]:
        print(
            f"{answer['name']} -> {answer['value']} "
            f"(TTL: {answer['ttl']})"
        )


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

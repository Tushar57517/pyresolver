import socket

def send_dns_query(query, server_ip, port=53, max_attempts=3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)

    try:
        for attempt in range(1, max_attempts + 1):
            try:
                print(
                    f"Attempt {attempt}/{max_attempts} "
                    f"to {server_ip}:{port}"
                )

                bytes_sent = sock.sendto(query, (server_ip, port))
                print(f"Sent {bytes_sent} bytes to {server_ip}:{port}")

                response, sender = sock.recvfrom(4096)

                print(f"Received {len(response)} bytes from {sender}")

                return response

            except socket.timeout:
                print(f"Timeout from {server_ip}")

        print(f"All attempts failed for {server_ip}")
        return None

    except OSError as error:
        print("Network error:", error)
        return None

    finally:
        sock.close()
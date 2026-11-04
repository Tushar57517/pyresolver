import socket
import struct
import time

def send_dns_query(query, server_ip, port=53, max_attempts=3, timeout=5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

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

                # Validate response source.
                if sender[0] != server_ip or sender[1] != port:
                    print("Response received from unexpected sender.")
                    continue

                return response

            except socket.timeout:
                print(f"Timeout from {server_ip}")

            except OSError as error:
                print(f"Network error with {server_ip}: {error}")

            if attempt < max_attempts:
                delay = 2 ** (attempt - 1)

                print(f"Retrying in {delay} seconds...")
                time.sleep(delay)

        print(f"All attempts failed for {server_ip}")
        return None

    except OSError as error:
        print("Network error:", error)
        return None

    finally:
        sock.close()

def send_dns_query_tcp(query, server_ip, port=53, timeout=5):

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        # TCP DNS messages require a 2-byte length prefix.
        tcp_query = struct.pack("!H", len(query)) + query

        sock.connect((server_ip, port))

        sock.sendall(tcp_query)

        # Read the 2-byte response length.
        length_data = b""

        while len(length_data) < 2:
            chunk = sock.recv(2 - len(length_data))

            if not chunk:
                return None

            length_data += chunk

        response_length = struct.unpack("!H", length_data)[0]

        # Read the complete DNS response.
        response = b""

        while len(response) < response_length:
            chunk = sock.recv(response_length - len(response))

            if not chunk:
                return None

            response += chunk

        return response

    except (socket.timeout, OSError) as error:
        print("TCP DNS network error:", error)
        return None

    finally:
        sock.close()
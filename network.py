
import socket


def send_dns_query(query, server_ip, port=53):

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    sock.settimeout(5)

    try:

        bytes_sent = sock.sendto(
            query,
            (server_ip, port)
        )

        print(
            f"Sent {bytes_sent} bytes to "
            f"{server_ip}:{port}"
        )

        print("Local socket:", sock.getsockname())

        response, sender = sock.recvfrom(4096)

        print(
            f"Received {len(response)} bytes "
            f"from {sender}"
        )

        return response

    except socket.timeout:

        print("DNS request timed out")
        return None

    except OSError as error:

        print("Network error:", error)
        return None

    finally:

        sock.close()

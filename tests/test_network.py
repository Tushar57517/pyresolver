import unittest
from unittest.mock import patch, MagicMock

from network import send_dns_query


class TestDNSNetwork(unittest.TestCase):

    @patch("network.socket.socket")
    @patch("network.time.sleep")
    def test_retry_after_timeout(self, mock_sleep, mock_socket):

        sock = MagicMock()
        mock_socket.return_value = sock

        # First two attempts timeout; third succeeds.
        sock.recvfrom.side_effect = [
            TimeoutError,
            TimeoutError,
            (b"dns_response", ("198.41.0.4", 53))
        ]

        result = send_dns_query(
            b"dns_query",
            "198.41.0.4",
            max_attempts=3,
            timeout=2
        )

        self.assertEqual(result, b"dns_response")
        self.assertEqual(sock.sendto.call_count, 3)

        # Verify exponential backoff delays.
        self.assertEqual(
            [call.args[0] for call in mock_sleep.call_args_list],
            [1, 2]
        )

        sock.close.assert_called_once()

    @patch("network.socket.socket")
    @patch("network.time.sleep")
    def test_all_attempts_timeout(self, mock_sleep, mock_socket):

        sock = MagicMock()
        mock_socket.return_value = sock

        sock.recvfrom.side_effect = TimeoutError

        result = send_dns_query(
            b"dns_query",
            "198.41.0.4",
            max_attempts=3
        )

        self.assertIsNone(result)
        self.assertEqual(sock.sendto.call_count, 3)

        self.assertEqual(
            [call.args[0] for call in mock_sleep.call_args_list],
            [1, 2]
        )

        sock.close.assert_called_once()

    @patch("network.socket.socket")
    def test_configurable_timeout(self, mock_socket):

        sock = MagicMock()
        mock_socket.return_value = sock

        sock.recvfrom.return_value = (
            b"dns_response",
            ("198.41.0.4", 53)
        )

        send_dns_query(
            b"dns_query",
            "198.41.0.4",
            timeout=3
        )

        sock.settimeout.assert_called_once_with(3)


if __name__ == "__main__":
    unittest.main()

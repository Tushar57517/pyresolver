import sys
import os
import unittest
from unittest.mock import patch

sys.path.insert(
    0,
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

from resolver import query_nameserver


class TestTCPFallback(unittest.TestCase):

    @patch("resolver.send_dns_query_tcp")
    @patch("resolver.send_dns_query")
    @patch("resolver.parse_dns_response")
    def test_normal_udp_response(
        self,
        mock_parse,
        mock_udp,
        mock_tcp
    ):
        # TC = 0: normal UDP response.
        mock_udp.return_value = b"udp_response"

        mock_parse.return_value = {
            "flags": {"TC": 0},
            "answers": []
        }

        result = query_nameserver(
            "example.com",
            "198.41.0.4"
        )

        self.assertIsNotNone(result)
        mock_udp.assert_called_once()
        mock_tcp.assert_not_called()

    @patch("resolver.send_dns_query_tcp")
    @patch("resolver.send_dns_query")
    @patch("resolver.parse_dns_response")
    @patch("resolver.parse_dns_header")
    @patch("resolver.decode_dns_flags")
    def test_truncated_udp_uses_tcp(
        self,
        mock_flags,
        mock_header,
        mock_parse,
        mock_udp,
        mock_tcp
    ):
        mock_udp.return_value = b"truncated_response"
        mock_tcp.return_value = b"tcp_response"

        # First flag check detects truncation.
        # parse_dns_response performs its own validation.
        mock_header.return_value = {"flags": 512}
        mock_flags.return_value = {"TC": 1}

        mock_parse.return_value = {
            "flags": {"TC": 0},
            "answers": []
        }

        result = query_nameserver(
            "example.com",
            "198.41.0.4"
        )

        self.assertIsNotNone(result)
        mock_udp.assert_called_once()
        mock_tcp.assert_called_once()

        # Both transports must receive the same query.
        udp_query = mock_udp.call_args.args[0]
        tcp_query = mock_tcp.call_args.args[0]

        self.assertEqual(udp_query, tcp_query)

    @patch("resolver.send_dns_query_tcp")
    @patch("resolver.send_dns_query")
    @patch("resolver.parse_dns_header")
    @patch("resolver.decode_dns_flags")
    def test_tcp_fallback_failure(
        self,
        mock_flags,
        mock_header,
        mock_udp,
        mock_tcp
    ):
        mock_udp.return_value = b"truncated_response"
        mock_tcp.return_value = None

        mock_header.return_value = {"flags": 512}
        mock_flags.return_value = {"TC": 1}

        result = query_nameserver(
            "example.com",
            "198.41.0.4"
        )

        self.assertIsNone(result)
        mock_tcp.assert_called_once()


if __name__ == "__main__":
    unittest.main()

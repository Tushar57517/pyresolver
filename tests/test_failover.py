import sys
import os
import unittest
from unittest.mock import patch

sys.path.insert(
    0,
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

from resolver import resolve_test, dns_cache


class TestNameserverFailover(unittest.TestCase):

    def setUp(self):
        dns_cache.clear()

    @patch("resolver.query_nameserver")
    def test_failover_to_next_nameserver(self, mock_query):

        # First query: root server returns two nameservers.
        root_response = {
            "flags": {"RCODE": 0},
            "answers": [],
            "authority": [
                {
                    "type": 2,
                    "nameserver": "ns1.example.com"
                },
                {
                    "type": 2,
                    "nameserver": "ns2.example.com"
                }
            ],
            "additional": [
                {
                    "type": "A",
                    "name": "ns1.example.com",
                    "value": "192.0.2.1"
                },
                {
                    "type": "A",
                    "name": "ns2.example.com",
                    "value": "192.0.2.2"
                }
            ]
        }

        successful_response = {
            "flags": {"RCODE": 0},
            "answers": [
                {
                    "name": "example.com",
                    "type": "A",
                    "value": "93.184.216.34",
                    "ttl": 300
                }
            ],
            "authority": [],
            "additional": []
        }

        mock_query.side_effect = [
            root_response,
            None,
            successful_response
        ]

        result = resolve_test("example.com")

        self.assertIsNotNone(result)
        self.assertEqual(
            result[0]["value"],
            "93.184.216.34"
        )

        self.assertEqual(mock_query.call_count, 3)

        # Verify the failed nameserver was followed by the second.
        self.assertEqual(
            mock_query.call_args_list[1].args[1],
            "192.0.2.1"
        )

        self.assertEqual(
            mock_query.call_args_list[2].args[1],
            "192.0.2.2"
        )

    def create_root_referral(self):
        return {
            "flags": {"RCODE": 0},
            "answers": [],
            "authority": [
                {
                    "type": 2,
                    "nameserver": "ns1.example.com"
                },
                {
                    "type": 2,
                    "nameserver": "ns2.example.com"
                }
            ],
            "additional": [
                {
                    "type": "A",
                    "name": "ns1.example.com",
                    "value": "192.0.2.1"
                },
                {
                    "type": "A",
                    "name": "ns2.example.com",
                    "value": "192.0.2.2"
                }
            ]
        }

    @patch("resolver.query_nameserver")
    def test_all_nameservers_fail(self, mock_query):

        mock_query.side_effect = [
            self.create_root_referral(),
            None,
            None
        ]

        result = resolve_test("example.com")

        self.assertIsNone(result)
        self.assertEqual(mock_query.call_count, 3)

    @patch("resolver.query_nameserver")
    def test_servfail_tries_next_nameserver(self, mock_query):

        servfail_response = {
            "flags": {"RCODE": 2},
            "answers": [],
            "authority": [],
            "additional": []
        }

        successful_response = {
            "flags": {"RCODE": 0},
            "answers": [
                {
                    "name": "example.com",
                    "type": "A",
                    "value": "93.184.216.34",
                    "ttl": 300
                }
            ],
            "authority": [],
            "additional": []
        }

        mock_query.side_effect = [
            self.create_root_referral(),
            servfail_response,
            successful_response
        ]

        result = resolve_test("example.com")

        self.assertIsNotNone(result)
        self.assertEqual(
            result[0]["value"],
            "93.184.216.34"
        )

        self.assertEqual(mock_query.call_count, 3)

    @patch("resolver.query_nameserver")
    def test_malformed_response_tries_next_nameserver(self, mock_query):

        successful_response = {
            "flags": {"RCODE": 0},
            "answers": [
                {
                    "name": "example.com",
                    "type": "A",
                    "value": "93.184.216.34",
                    "ttl": 300
                }
            ],
            "authority": [],
            "additional": []
        }

        mock_query.side_effect = [
            self.create_root_referral(),
            ValueError("Malformed DNS response"),
            successful_response
        ]

        result = resolve_test("example.com")

        self.assertIsNotNone(result)
        self.assertEqual(
            result[0]["value"],
            "93.184.216.34"
        )

        self.assertEqual(mock_query.call_count, 3)
    
if __name__ == "__main__":
    unittest.main()

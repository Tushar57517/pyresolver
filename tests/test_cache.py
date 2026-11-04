
import sys
import os
import time
import unittest
from unittest.mock import patch

sys.path.insert(
    0,
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

from resolver import (
    dns_cache,
    store_in_cache,
    get_from_cache,
    resolve_test
)


class TestDNSCache(unittest.TestCase):

    def setUp(self):
        dns_cache.clear()

    def test_cache_storage_and_retrieval(self):
        records = [
            {
                "name": "google.com",
                "type": "A",
                "value": "142.250.190.14",
                "ttl": 300
            }
        ]

        store_in_cache("google.com", records)

        result = get_from_cache("google.com")

        self.assertIsNotNone(result)
        self.assertEqual(result[0]["value"], "142.250.190.14")
        self.assertEqual(result[0]["type"], "A")
        self.assertEqual(result[0]["name"], "google.com")

    def test_cache_miss(self):
        result = get_from_cache("example.com")

        self.assertIsNone(result)

    def test_expired_cache(self):
        dns_cache["example.com"] = [
            {
                "type": "A",
                "value": "93.184.216.34",
                "ttl": 1,
                "expires_at": time.time() - 1
            }
        ]

        result = get_from_cache("example.com")

        self.assertIsNone(result)
        self.assertNotIn("example.com", dns_cache)

    @patch("resolver.query_nameserver")
    def test_resolve_uses_cache(self, mock_query):
        # Simulate a successful DNS response.
        mock_query.return_value = {
            "flags": {
                "RCODE": 0
            },
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

        # First lookup: should query the DNS server.
        first_result = resolve_test("example.com")

        self.assertIsNotNone(first_result)
        self.assertEqual(
            first_result[0]["value"],
            "93.184.216.34"
        )

        self.assertEqual(mock_query.call_count, 1)

        # Second lookup: should use the cache.
        second_result = resolve_test("example.com")

        self.assertEqual(
            second_result[0]["value"],
            "93.184.216.34"
        )

        # The DNS server should not be queried again.
        self.assertEqual(mock_query.call_count, 1)

    def test_cache_multiple_a_records(self):
        records = [
            {
                "name": "example.com",
                "type": "A",
                "value": "93.184.216.34",
                "ttl": 300
            },
            {
                "name": "example.com",
                "type": "A",
                "value": "93.184.216.35",
                "ttl": 600
            }
        ]

        store_in_cache("example.com", records)

        result = get_from_cache("example.com")

        self.assertEqual(len(result), 2)

        values = [record["value"] for record in result]

        self.assertIn("93.184.216.34", values)
        self.assertIn("93.184.216.35", values)

    def test_cache_partial_expiration(self):
        dns_cache["example.com"] = [
            {
                "type": "A",
                "value": "93.184.216.34",
                "ttl": 300,
                "expires_at": time.time() - 1
            },
            {
                "type": "A",
                "value": "93.184.216.35",
                "ttl": 300,
                "expires_at": time.time() + 300
            }
        ]

        result = get_from_cache("example.com")

        self.assertEqual(len(result), 1)
        self.assertEqual(
            result[0]["value"],
            "93.184.216.35"
        )


if __name__ == "__main__":
    unittest.main()

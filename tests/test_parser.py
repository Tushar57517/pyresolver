import unittest
import struct

from dns_message import (
    parse_dns_resource_record,
    decode_domain_name,
    interpret_dns_record
)
from resolver import resolve_test


class TestDNSParserSafety(unittest.TestCase):

    def test_incomplete_resource_record_header(self):
        message = b"\x00" * 15

        with self.assertRaises(ValueError):
            parse_dns_resource_record(message, 6)

    def test_incomplete_rdata(self):
        # Root domain name followed by a record header.
        message = (
            b"\x00"
            + struct.pack("!HHIH", 1, 1, 300, 10)
            + b"\x01\x02"
        )

        with self.assertRaises(ValueError):
            parse_dns_resource_record(message, 0)

    def test_incomplete_compression_pointer(self):
        message = b"\xC0"

        with self.assertRaises(ValueError):
            decode_domain_name(message, 0)

    def test_compression_pointer_out_of_bounds(self):
        message = b"\xC0\xFF"

        with self.assertRaises(ValueError):
            decode_domain_name(message, 0)

    def test_circular_compression_pointer(self):
        message = b"\xC0\x00"

        with self.assertRaises(ValueError):
            decode_domain_name(message, 0)

    def test_incomplete_domain_label(self):
        message = b"\x05abc"

        with self.assertRaises(ValueError):
            decode_domain_name(message, 0)

    def test_cname_record_decoding(self):
        # Original DNS message containing "example.com"
        message = (
            b"\x07example\x03com\x00"
        )

        record = {
            "name": "www.example.com",
            "type": 5,
            "class": 1,
            "ttl": 300,
            "rdlength": len(message),
            "rdata": message,
            "rdata_offset": 0
        }

        result = interpret_dns_record(record, message)

        self.assertEqual(result["type"], "CNAME")
        self.assertEqual(result["value"], "example.com")
        self.assertEqual(result["ttl"], 300)

    def test_cname_loop_detection(self):
        cname_chain = {
            "a.example.com",
            "b.example.com"
        }

        result = resolve_test(
            "a.example.com",
            cname_chain=cname_chain
        )

        self.assertIsNone(result)

if __name__ == "__main__":
    unittest.main()

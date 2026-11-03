import unittest
import struct

from dns_message import (
    parse_dns_resource_record,
    decode_domain_name
)


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


if __name__ == "__main__":
    unittest.main()

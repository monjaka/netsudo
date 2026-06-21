import unittest

from netsudo.source import validate_source_ip


class SourceTests(unittest.TestCase):
    def test_validates_ipv4_source(self):
        self.assertEqual(validate_source_ip(" 192.168.6.60 "), "192.168.6.60")

    def test_rejects_ipv6_and_names(self):
        for source in ("table.local", "2001:db8::1", "999.1.1.1"):
            with self.subTest(source=source):
                with self.assertRaises(ValueError):
                    validate_source_ip(source)


if __name__ == "__main__":
    unittest.main()

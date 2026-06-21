import unittest

from netsudo.duration import format_duration, parse_duration


class DurationTests(unittest.TestCase):
    def test_parse_compound_duration(self):
        self.assertEqual(parse_duration("1h30m"), 5400)
        self.assertEqual(parse_duration("2d3h4m5s"), 183845)

    def test_parse_seconds_int(self):
        self.assertEqual(parse_duration(90), 90)
        self.assertEqual(parse_duration("90"), 90)

    def test_parse_rejects_invalid_values(self):
        for value in ("", "0", "10x", "1h 30m", "-5m"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    parse_duration(value)

    def test_format_duration(self):
        self.assertEqual(format_duration(0), "0s")
        self.assertEqual(format_duration(90), "1m30s")
        self.assertEqual(format_duration(90061), "1d1h1m1s")


if __name__ == "__main__":
    unittest.main()

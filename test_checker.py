import unittest
from header_checker import format_url, calculate_grade

class TestHeaderChecker(unittest.TestCase):

    def test_format_url_adds_https(self):
        self.assertEqual(format_url("example.com"), "https://example.com")
        self.assertEqual(format_url("http://example.com"), "http://example.com")
        self.assertEqual(format_url("https://example.com"), "https://example.com")

    def test_calculate_grade(self):
        self.assertEqual(calculate_grade(95), "A+")
        self.assertEqual(calculate_grade(85), "A")
        self.assertEqual(calculate_grade(75), "B")
        self.assertEqual(calculate_grade(65), "C")
        self.assertEqual(calculate_grade(55), "D")
        self.assertEqual(calculate_grade(30), "F")

if __name__ == "__main__":
    unittest.main()

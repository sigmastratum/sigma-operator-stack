import unittest

from src.example import answer


class SmokeTests(unittest.TestCase):
    def test_answer(self) -> None:
        self.assertEqual(answer(), 42)


if __name__ == "__main__":
    unittest.main()

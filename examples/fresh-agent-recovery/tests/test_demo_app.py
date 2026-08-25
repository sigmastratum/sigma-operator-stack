import unittest

from src.demo_app import answer


class DemoAppTests(unittest.TestCase):
    def test_answer(self) -> None:
        self.assertEqual(answer(), 42)


if __name__ == "__main__":
    unittest.main()

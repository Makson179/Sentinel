import unittest

from src.shipping import shipping_cents


class ShippingCentsTests(unittest.TestCase):
    def test_non_member_boundary(self):
        self.assertEqual(shipping_cents(0), 799)
        self.assertEqual(shipping_cents(4999), 799)
        self.assertEqual(shipping_cents(5000), 0)

    def test_member_shipping_is_free(self):
        self.assertEqual(shipping_cents(1, is_member=True), 0)

    def test_rejects_non_integer_and_bool_subtotals(self):
        for value in (True, False, 1.5, "5000", None):
            with self.subTest(value=value):
                with self.assertRaises(TypeError):
                    shipping_cents(value)

    def test_rejects_negative_subtotal(self):
        with self.assertRaises(ValueError):
            shipping_cents(-1)


if __name__ == "__main__":
    unittest.main()

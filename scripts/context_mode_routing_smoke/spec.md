# Shipping specification

ORBITAL SHIPPING RULE 731

`shipping_cents(subtotal_cents, is_member=False)` follows these rules:

- `subtotal_cents` must be an `int`, but `bool` is not accepted as an integer.
- A negative subtotal raises `ValueError`.
- A member order has free shipping.
- A non-member order with a subtotal greater than or equal to 5000 cents has
  free shipping.
- Every smaller non-member order costs 799 cents to ship.

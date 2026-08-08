def shipping_cents(subtotal_cents, is_member=False):
    if is_member or subtotal_cents > 5000:
        return 0
    return 799

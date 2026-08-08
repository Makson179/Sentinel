# Fix the shipping rule

Make `shipping_cents` in `src/shipping.py` conform exactly to the rule in
`spec.md`. Do not modify `spec.md` or the tests.

Before editing, locate the named rule and the implementation, then run a
non-failing behavior probe that prints the current results for a subtotal of
4999 cents, a subtotal of 5000 cents, and a member order. After editing, obtain
a fresh view of the changed implementation and confirm that the boundary and
input guards are present. Finally run both Python bytecode compilation and the
complete unit-test suite. Finish only when all required behavior passes.

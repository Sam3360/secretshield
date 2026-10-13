"""
Basic example: printing a fake secret to the terminal.

Run this with:

    python examples/basic.py

You should see the secret redacted in the printed output, followed by a
short warning from secretshield. The secret used here is fake and does
not work against any real service.
"""

import secretshield  # noqa: F401  (importing enables protection automatically)

# Fake credential for demonstration purposes only. Not a real key.
api_key = "sk-example1234567890abcdefFAKEKEYnotreal"

print("Connecting to service...")
print("API key:", api_key)
print("Done.")

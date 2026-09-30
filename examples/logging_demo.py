"""
Logging example: secretshield also protects Python's `logging` module,
including both `%s`-style lazy arguments and pre-formatted f-strings.

Run this with:

    python examples/logging_demo.py

The secret used here is fake and does not work against any real service.
"""

import logging

import secretshield  # noqa: F401  (importing enables protection automatically)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("logging_demo")

# Fake credential for demonstration purposes only. Not a real token.
github_token = "ghp_FAKEexampleTokenNotRealDoNotUse1234"

logger.info("Starting deployment process")

# %-style lazy formatting: secretshield inspects record.args.
logger.warning("Found token in environment: %s", github_token)

# Pre-formatted f-string: secretshield inspects record.msg.
logger.warning(f"Token again (f-string form): {github_token}")

logger.info("Deployment process complete")

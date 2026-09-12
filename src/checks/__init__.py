"""Explicit passive checks over already-collected HTTP evidence."""

from .content import check_content
from .cookies import check_cookies
from .cors import check_cors
from .headers import check_headers
from .registry import Check, CheckContext

PASSIVE_CHECKS: tuple[Check, ...] = (check_headers, check_cookies, check_cors, check_content)

__all__ = ["PASSIVE_CHECKS", "Check", "CheckContext"]

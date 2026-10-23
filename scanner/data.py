"""Reference data that goes stale. Update it from time to time.

WordPress: only the newest release series is officially supported. If this
reference is older than WP_REFERENCE_MAX_AGE_DAYS, the "outdated version"
finding is skipped instead of risking a wrong answer.
"""

from datetime import date

WP_CURRENT_SERIES = (7, 0)          # WordPress 7.0 (released 2026-05-20)
WP_REFERENCE_DATE = date(2026, 10, 21)
WP_REFERENCE_MAX_AGE_DAYS = 180
